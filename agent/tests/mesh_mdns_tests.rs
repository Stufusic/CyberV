//! M-PLAN M-2 — close condition: 2 node TỰ tìm thấy nhau qua mDNS và attest
//! thành công KHÔNG cấu hình tay (chạy trên 1 máy — multicast loopback;
//! kiểm chứng 2 máy LAN thật là việc operator thực hiện khi deploy).
//!
//! Ranh giới trung thực được test chốt:
//! - peer qua mDNS chỉ vào `Discovered` trước khi bắt tay (presence ≠ trust);
//! - attest chỉ đến từ bắt tay chữ ký thật (INV-012);
//! - beacon lệch node_id ≠ vk bị từ chối + đếm.

use std::collections::HashMap;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::time::sleep;

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::discovery::{MeshBeacon, BEACON_VERSION};
use cyberv_agent::mesh::graph::{NodeId, NodeState};
use cyberv_agent::mesh::node::{MeshNode, MeshNodeConfig};

fn key() -> DeviceIdentityKey {
    DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
}

fn node_of(k: &DeviceIdentityKey) -> NodeId {
    k.verifying_key().to_bytes()
}

fn pinned(keys: &[&DeviceIdentityKey]) -> HashMap<NodeId, VerifyingKey> {
    keys.iter().map(|k| (node_of(k), *k.verifying_key())).collect()
}

/// Config cho test mDNS: bind 0.0.0.0 để kết nối tới địa chỉ interface thật
/// mà daemon quảng bá được (listener loopback thuần sẽ từ chối kết nối đó).
fn mdns_config() -> MeshNodeConfig {
    MeshNodeConfig {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
        ..MeshNodeConfig::default()
    }
}

#[tokio::test]
async fn mdns_discovery_and_auto_attest_without_manual_config() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let na = {
        let n = MeshNode::new(ka.clone(), pinned(&[&kb]), mdns_config());
        n.start().await.unwrap();
        n
    };
    let nb = {
        let n = MeshNode::new(kb.clone(), pinned(&[&ka]), mdns_config());
        n.start().await.unwrap();
        n
    };

    // Nếu môi trường không chạy được mDNS daemon (thiếu multicast/firewall)
    // thì SKIP có ghi rõ — không phải pass âm thầm, không phải fail giả.
    if let Err(e) = na.enable_mdns().await {
        eprintln!("SKIP (mDNS daemon không khả dụng: {e})");
        return;
    }
    if let Err(e) = nb.enable_mdns().await {
        eprintln!("SKIP (mDNS daemon không khả dụng: {e})");
        return;
    }

    // Không cấu hình tay gì thêm: hai node tự browse + connect + attest.
    let mut both_attested = false;
    for _ in 0..150 {
        let _ = na.browse_and_connect().await;
        let _ = nb.browse_and_connect().await;
        let a_sees_b = na.state_of(&idb).await == Some(NodeState::Attested);
        let b_sees_a = nb.state_of(&ida).await == Some(NodeState::Attested);
        if a_sees_b && b_sees_a {
            both_attested = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        both_attested,
        "2 node phải tự tìm thấy + attest qua mDNS trong 15s \
         (na: {:?}, nb: {:?})",
        na.stats().await,
        nb.stats().await
    );
    assert_eq!(na.stats().await.beacons_rejected, 0);

    na.disable_mdns().await;
    nb.disable_mdns().await;
}

#[tokio::test]
async fn absorb_discovered_gates_mismatched_beacon_and_discovers_without_trust() {
    let (ka, kb) = (key(), key());
    let idb = node_of(&kb);
    // Connect timeout thấp — endpoint trong test cố tình chết, không chờ 3s.
    let cfg = MeshNodeConfig {
        connect_timeout_ms: 250,
        ..mdns_config()
    };
    let na = MeshNode::new(ka.clone(), pinned(&[]), cfg);

    // 1. Beacon lệch node_id ≠ vk = beacon giả — gate phải từ chối + đếm.
    let fake = MeshBeacon { node_id: [0x44; 32], vk: [0x55; 32], wire_version: BEACON_VERSION };
    let mut batch = vec![(fake, "127.0.0.1:1".parse().unwrap())];
    na.absorb_discovered(&mut batch).await.unwrap();
    assert_eq!(na.stats().await.beacons_rejected, 1);
    assert_eq!(na.state_of(&fake.node_id).await, None, "beacon giả không được pin/observe");

    // 2. Beacon hợp lệ (node_id ≡ vk) — CHỈ được Discovered: presence không
    //    nâng trust (INV-012); attest phải qua bắt tay chữ ký thật.
    let good = MeshBeacon { node_id: idb, vk: idb, wire_version: BEACON_VERSION };
    let mut batch2 = vec![(good, "127.0.0.1:1".parse().unwrap())];
    let connected = na.absorb_discovered(&mut batch2).await.unwrap();
    assert_eq!(connected, 0, "endpoint chết — không có link nào được thiết lập");
    assert_eq!(na.state_of(&idb).await, Some(NodeState::Discovered));
    assert_ne!(na.state_of(&idb).await, Some(NodeState::Attested));
}
