// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! M-PLAN I-1 — Self-isolation close condition:
//! tamper signal → self-isolate → peer alert qua gossip → peer hạ Isolated;
//! kẻ mượn alert đòi isolate người khác bị bỏ qua; hết TTL mở lại inbound
//! (INV-014 — reversibility outranks persistence).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::events::{EventKind, NsgEvent, SignalClass};
use cyberv_agent::mesh::graph::{NodeId, NodeState};
use cyberv_agent::mesh::node::{ManualClock, MeshNode, MeshNodeConfig};

fn key() -> DeviceIdentityKey {
    DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
}

fn node_of(k: &DeviceIdentityKey) -> NodeId {
    k.verifying_key().to_bytes()
}

fn pinned(keys: &[&DeviceIdentityKey]) -> HashMap<NodeId, VerifyingKey> {
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("điều kiện không đạt sau 6s: {what}");
}

async fn started_node(
    key: DeviceIdentityKey,
    pinned_peers: HashMap<NodeId, VerifyingKey>,
    config: MeshNodeConfig,
) -> MeshNode {
    let node = MeshNode::new(key, pinned_peers, config);
    node.start().await.unwrap();
    node
}

#[tokio::test]
async fn self_isolate_cuts_links_alerts_peers_and_refuses_inbound() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let na = started_node(ka.clone(), pinned(&[&kb]), MeshNodeConfig::default()).await;
    let nb = started_node(kb.clone(), pinned(&[&ka]), MeshNodeConfig::default()).await;
    let addr_b = nb.local_addr().await.unwrap();
    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A",
    )
    .await;

    // Node A phát hiện tamper → tự cách ly.
    na.self_isolate("driver signature check failed").await.unwrap();

    // A: self-node Isolated, không còn link nào.
    assert_eq!(na.state_of(&ida).await, Some(NodeState::Isolated));
    assert!(na.self_isolated_until().await.is_some());
    wait_until(
        || async { na.active_link_count().await == 0 },
        "A cắt hết link",
    )
    .await;

    // B: nhận alert → hạ A về Isolated + cắt link với A.
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Isolated) },
        "B hạ A Isolated theo alert",
    )
    .await;
    wait_until(
        || async { nb.active_link_count().await == 0 },
        "B cắt link với A",
    )
    .await;
    assert_eq!(nb.stats().await.links_closed, 1);

    // A đang isolated → chặn CẢ outbound (A chủ động) LẪN inbound (B chủ
    // động tới A) — fail-closed, hai chiều, có đếm.
    let err = na.connect_peer(idb, addr_b).await;
    assert!(err.is_err(), "A isolated không được chủ động connect outbound");
    let err = nb.connect_peer(ida, na.local_addr().await.unwrap()).await;
    assert!(err.is_err(), "A isolated phải từ chối bắt tay inbound của B");
    wait_until(
        || async { na.stats().await.inbound_rejected_isolated >= 1 },
        "A đếm inbound bị chặn khi isolated",
    )
    .await;
}

#[tokio::test]
async fn spoofed_isolation_alert_claiming_another_node_is_ignored() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let na = started_node(ka.clone(), pinned(&[&kb]), MeshNodeConfig::default()).await;
    let nb = started_node(kb.clone(), pinned(&[&ka]), MeshNodeConfig::default()).await;
    let addr_b = nb.local_addr().await.unwrap();
    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A",
    )
    .await;

    // A gửi IsolationAlert đòi isolate NGƯỜI KHÁC (subject ≠ origin) —
    // chữ ký hợp lệ, nhưng đây là dữ liệu quorum, không phải lệnh.
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut spoofed = NsgEvent {
        event_id: [0; 32],
        origin_id: ida,
        origin_seq: 0,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: Some([0xBB; 32]),
        created_wall_ms: wall,
        expiry_wall_ms: wall + 3_600_000,
        kind: EventKind::IsolationAlert,
        signal_class: Some(SignalClass::Verified),
        subject: Some([0xCC; 32]), // ≠ ida — đòi isolate node thứ ba
        obs_channel: None,
        signature: [0; 64],
    };
    spoofed.sign(&ka);
    na.gossip_signed(spoofed).await.unwrap();
    wait_until(
        || async { nb.stats().await.gossip_in_accepted >= 1 },
        "B nhận event giả mạo subject",
    )
    .await;

    // B KHÔNG isolate ai cả: node thứ ba không xuất hiện, A vẫn Attested.
    assert_eq!(nb.state_of(&[0xCC; 32]).await, None);
    assert_eq!(nb.state_of(&ida).await, Some(NodeState::Attested));
    assert_eq!(nb.active_link_count().await, 1, "link A-B phải còn nguyên");
}

#[tokio::test]
async fn ttl_expiry_lifts_self_isolation_and_allows_re_attest() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let clock_a = Arc::new(ManualClock::new(10_000, wall_ms()));
    let clock_b = Arc::new(ManualClock::new(10_000, wall_ms()));
    let cfg = MeshNodeConfig::default();
    let ttl = cfg.isolation_ttl_ms;
    let na = {
        let n = MeshNode::with_clock(ka.clone(), pinned(&[&kb]), cfg.clone(), clock_a.clone());
        n.start().await.unwrap();
        n
    };
    let nb = {
        let n = MeshNode::with_clock(kb.clone(), pinned(&[&ka]), cfg.clone(), clock_b.clone());
        n.start().await.unwrap();
        n
    };
    let addr_b = nb.local_addr().await.unwrap();
    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A",
    )
    .await;

    na.self_isolate("runtime tamper").await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Isolated) },
        "B hạ A Isolated",
    )
    .await;

    // Đẩy thời gian qua TTL trên CẢ HAI node rồi tick: A mở lại inbound,
    // B auto-lift A về Unknown (INV-014 — không isolation vĩnh viễn).
    clock_a.advance_mono(ttl + 1);
    clock_b.advance_mono(ttl + 1);
    let report = na.tick().await;
    assert_eq!(report.lifted_isolations, 1, "self-node A được lift");
    assert_eq!(na.self_isolated_until().await, None);
    assert_eq!(na.state_of(&ida).await, Some(NodeState::Unknown));
    let report_b = nb.tick().await;
    assert_eq!(report_b.lifted_isolations, 1, "A trên graph của B được lift");
    assert_eq!(nb.state_of(&ida).await, Some(NodeState::Unknown));

    // Kết nối lại — M-PLAN §6.3 grace de-escalation: KHÔNG nhảy thẳng
    // Attested; phải ở Suspect (probation) qua K tick sạch mới lên Attested.
    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Suspect) },
        "A re-attest sau TTL phải ở Suspect (probation)",
    )
    .await;
    for _ in 0..cfg.probation_ticks - 1 {
        nb.tick().await;
        assert_eq!(nb.state_of(&ida).await, Some(NodeState::Suspect));
    }
    nb.tick().await;
    assert_eq!(
        nb.state_of(&ida).await,
        Some(NodeState::Attested),
        "probation sạch → Attested"
    );
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
