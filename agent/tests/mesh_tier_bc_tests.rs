//! M-PLAN M-3/M-4 — bất biến Tier B/C tại tầng engine:
//! - Tier B/C flag TẮT MẶC ĐỊNH (plan §10) — bật không flag = lỗi rõ ràng;
//! - BLE presence KHÔNG BAO GIỜ nâng NodeState / tạo node / vào log quorum
//!   (zero trust — M-PLAN §5, plan §10 Tier C);
//! - WFD connect yêu cầu pinning device_id + neo vk đầy đủ.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::time::sleep;

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::graph::NodeState;
use cyberv_agent::mesh::node::MeshNode;
use cyberv_agent::mesh::transport::ble::BleBeacon26;
use cyberv_agent::mesh::MeshError;

fn key() -> DeviceIdentityKey {
    DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
}

fn node_of(k: &DeviceIdentityKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn pinned(keys: &[&DeviceIdentityKey]) -> std::collections::HashMap<[u8; 32], VerifyingKey> {
    keys.iter().map(|k| (node_of(k), *k.verifying_key())).collect()
}

async fn wait_until<F, Fut>(mut cond: F, what: &str)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..600 {
        if cond().await {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("điều kiện không đạt sau 6s: {what}");
}

#[tokio::test]
async fn tier_flags_default_off_and_honest_errors() {
    let ka = key();
    let node = MeshNode::new(ka.clone(), pinned(&[]), Default::default());

    // Flag mặc định tắt — bật phải lỗi RÕ RÀNG (không im lặng bật radio).
    let err = node.enable_wifi_direct().await.unwrap_err();
    assert!(err.to_string().contains("wifi_direct_enabled"), "{err}");
    let err = node.enable_ble_watch().await.unwrap_err();
    assert!(err.to_string().contains("ble_discovery_enabled"), "{err}");
    let err = node.enable_ble_advertise(&BleBeacon26::from_identity(&node_of(&ka), &node_of(&ka))).await.unwrap_err();
    assert!(err.to_string().contains("ble_discovery_enabled"), "{err}");
}

#[tokio::test]
async fn ble_presence_never_creates_or_raises_nodes() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));
    let node = MeshNode::new(ka.clone(), pinned(&[&kb]), Default::default());
    // Self-node Attested từ lúc dựng (identity nội bộ).
    assert_eq!(node.state_of(&ida).await, Some(NodeState::Attested));
    let log_before = node.log_len().await;

    // 1. BLE sample của node LẠ (chưa từng thấy) — KHÔNG tạo node trong graph.
    let stranger = BleBeacon26::from_identity(&[0xEE; 32], &[0xFF; 32]);
    let mut batch = vec![(stranger, [1u8; 6])];
    let absorbed = node.absorb_ble_presence(&mut batch).await;
    assert_eq!(absorbed, 1);
    assert_eq!(node.state_of(&[0xEE; 32]).await, None, "BLE không được tạo node");
    assert_eq!(node.log_len().await, log_before, "BLE không được vào log/quorum");

    // 2. BLE sample của node đã ATTESTED — state phải GIỮ NGUYÊN (không nâng,
    //    không hạ): presence ≠ trust (INV-012).
    let peer_beacon = BleBeacon26::from_identity(&idb, &idb);
    let mut batch2 = vec![(peer_beacon, [2u8; 6])];
    node.absorb_ble_presence(&mut batch2).await;
    // B chưa từng attest với A → graph KHÔNG có B dù BLE thấy prefix.
    assert_eq!(node.state_of(&idb).await, None, "BLE presence không tạo node B");

    // 3. Sổ presence ghi đúng — đây là TẤT CẢ những gì BLE được phép làm.
    //    (mono của SystemClock đếm từ lúc dựng node — chưa tới 1s.)
    let now = 1_000u64;
    assert!(
        node.ble_seen_recently(&idb[..8].try_into().unwrap(), now, 10_000).await,
        "presence phải được ghi sổ"
    );
    assert!(
        !node.ble_seen_recently(&[0x99; 8], now, 10_000).await,
        "prefix chưa thấy phải vắng mặt"
    );
    // Self-node vẫn nguyên trạng thái.
    assert_eq!(node.state_of(&ida).await, Some(NodeState::Attested));
}

#[tokio::test]
async fn wfd_connect_requires_full_pinning_chain() {
    let (ka, kb, kc) = (key(), key(), key());
    let idb = node_of(&kb);
    let node = MeshNode::new(ka.clone(), pinned(&[&kb]), Default::default());

    // 1. device_id chưa pin → từ chối (không TOFU qua WFD).
    let err = node.connect_wifi_direct("SWD#WiFiDirect#unpinned", idb).await.unwrap_err();
    assert!(matches!(err, MeshError::InvalidEndpoint(_)), "{err}");

    // 2. Pin cho peer KHÔNG có neo vk → UnknownPeer (pin yêu cầu neo đủ).
    let idc = node_of(&kc);
    let err = node.pin_wfd_device("SWD#WiFiDirect#dev-c", idc).await.unwrap_err();
    assert!(matches!(err, MeshError::UnknownPeer(_)), "{err}");

    // 3. Pin chuẩn dev-b → idb; nhưng connect hỏi device_id đó cho KC →
    //    từ chối (mismatch device_id ↔ peer).
    node.pin_wfd_device("SWD#WiFiDirect#dev-b", idb).await.unwrap();
    let err = node.connect_wifi_direct("SWD#WiFiDirect#dev-b", idc).await.unwrap_err();
    assert!(matches!(err, MeshError::InvalidEndpoint(_)), "{err}");

    // 4. Connect đúng cặp (dev-b, idb): đi tới bước shim/radio — kết quả
    //    tuỳ shim (thật → NotFound/Timeout/OsError; stub → Unsupported);
    //    QUAN TRỌNG: không bao giờ OK vì peer không có thật.
    let res = node.connect_wifi_direct("SWD#WiFiDirect#dev-b", idb).await;
    match res {
        Ok(()) => panic!("connect peer không có thật không được OK"),
        Err(e) => {
            let honest = e.to_string().contains("NOT_FOUND")
                || e.to_string().contains("TIMEOUT")
                || e.to_string().contains("OS_ERROR")
                || e.to_string().contains("UNSUPPORTED")
                || e.to_string().contains("RADIO_OFF");
            assert!(honest, "lỗi phải trung thực: {e}");
        }
    }
    // Chờ task sạch (không bắt buộc — chống flake khi CI tắt).
    wait_until(|| async { true }, "no-op").await;
}
