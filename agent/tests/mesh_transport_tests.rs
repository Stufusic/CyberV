// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
//! M-PLAN M-1 — close conditions cho `MeshTransport` + TCP-LAN + path_class.
//!
//! Node engine chạy THẬT trên TCP loopback: socket thật, bắt tay 3 bước thật,
//! AEAD thật. Kịch bản kẻ xấu dùng raw socket nói đúng wire format rồi gian
//! lận (frame hỏng tag, peer chưa pin) — nhánh bị tấn công phải bị từ chối,
//! không chỉ happy path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::events::{EventKind, NsgEvent, ObsChannel, SignalClass};
use cyberv_agent::mesh::graph::{EdgeState, NodeId, NodeState, EDGE_STALE_MS};
use cyberv_agent::mesh::node::{ManualClock, MeshNode, MeshNodeConfig};
use cyberv_agent::mesh::quorum::{NotReachedReason, QuorumVerdict};
use cyberv_agent::mesh::session::{
    HandshakeConfig, HandshakeMessage, Initiator, MeshSession, MESH_WIRE_VERSION,
};
use cyberv_agent::mesh::transport::{tcp_path_class, FRAME_GOSSIP_EVENT};
use cyberv_agent::mesh::MeshError;

fn key() -> DeviceIdentityKey {
    DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
}

fn node_of(k: &DeviceIdentityKey) -> NodeId {
    k.verifying_key().to_bytes()
}

fn pinned(keys: &[&DeviceIdentityKey]) -> HashMap<NodeId, VerifyingKey> {
    keys.iter().map(|k| (node_of(k), *k.verifying_key())).collect()
}

fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Chờ điều kiện (future-based — mọi accessor của node là async) đạt trong
/// 6s, không thì panic với mô tả rõ ràng.
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

/// Dựng event đã ký — caller là engine (`gossip_signed` sẽ tự cấp seq) hoặc
/// raw client (đặt seq tay). Root/channel tùy biến để cô lập điều kiện
/// independence cần test.
fn vote_event(
    key: &DeviceIdentityKey,
    seq: u64,
    subject: NodeId,
    root: [u8; 32],
    channel: ObsChannel,
) -> NsgEvent {
    let wall = wall_now();
    let mut ev = NsgEvent {
        event_id: [0; 32],
        origin_id: key.verifying_key().to_bytes(),
        origin_seq: seq,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: Some(root),
        created_wall_ms: wall,
        expiry_wall_ms: wall + 3_600_000,
        kind: EventKind::Vote,
        signal_class: Some(SignalClass::Verified),
        subject: Some(subject),
        obs_channel: Some(channel),
        signature: [0; 64],
    };
    ev.sign(key);
    ev
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

/// Raw handshake initiator qua socket thô — đúng wire format, dùng cho kịch
/// bản kẻ xấu/khung hỏng mà engine API không cho phép tạo.
async fn raw_handshake(
    stream: &mut TcpStream,
    identity: &DeviceIdentityKey,
    peer_vk: VerifyingKey,
    peer_node_id: NodeId,
) -> MeshSession {
    let initiator = Initiator::new(
        HandshakeConfig { identity, peer_vk, peer_node_id, version: MESH_WIRE_VERSION },
        &mut OsCryptoRng,
    )
    .unwrap();
    stream.write_all(&initiator.hello().encode()).await.unwrap();
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await.unwrap();
    let ack = HandshakeMessage::decode(&buf[..n]).unwrap();
    let (session, confirm) = initiator.handle_ack(&ack).unwrap();
    stream.write_all(&confirm.encode()).await.unwrap();
    session
}

// ---------------------------------------------------------------------------
// Close condition M-1: 2 node trao đổi gossip qua TCP thật
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_nodes_exchange_gossip_over_loopback() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let na = started_node(ka.clone(), pinned(&[&kb]), MeshNodeConfig::default()).await;
    let nb = started_node(kb.clone(), pinned(&[&ka]), MeshNodeConfig::default()).await;
    let addr_b = nb.local_addr().await.unwrap();

    na.connect_peer(idb, addr_b).await.unwrap();
    assert_eq!(na.state_of(&idb).await, Some(NodeState::Attested));
    // Phía responder đăng ký bất đồng bộ — đợi B xong bắt tay + register.
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A",
    ).await;
    assert_eq!(na.edge_state(&idb).await, Some(EdgeState::Attested));
    wait_until(
        || async { nb.edge_state(&ida).await == Some(EdgeState::Attested) },
        "cạnh B-A attested",
    ).await;

    // A phát vote → B nhận vào log; đường nhận = path_class của link.
    let subject = [0xEE; 32];
    let ev = vote_event(&ka, 0, subject, [0xA1; 32], ObsChannel::Kernel);
    let (sent, signed) = na.gossip_signed(ev).await.unwrap();
    assert_eq!(sent, 1, "một peer một link — đúng một bản ra");
    // Engine tự cấp origin_seq rồi ký lại → id PHẢI đổi; dùng id của bản đã ký.
    assert_ne!(signed.event_id, [0u8; 32]);
    let event_id = signed.event_id;

    wait_until(|| nb.log_contains(&event_id), "B nhận event qua TCP").await;
    assert_eq!(nb.stats().await.gossip_in_accepted, 1);

    let link_path = na.paths_of(&idb).await[0];
    assert_eq!(link_path, tcp_path_class("127.0.0.1".parse().unwrap()));
    assert_eq!(nb.arrival_path_of(&event_id).await, Some(link_path));

    na.disconnect_peer(&idb).await;
}

// ---------------------------------------------------------------------------
// Close condition M-1: 2 vote cùng path_class đếm 1 (tầng engine)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_votes_over_same_path_count_as_one() {
    let (ka, kb, kc) = (key(), key(), key());
    let idc = node_of(&kc);

    let na = started_node(ka.clone(), pinned(&[&kc]), MeshNodeConfig::default()).await;
    let nb = started_node(kb.clone(), pinned(&[&kc]), MeshNodeConfig::default()).await;
    let nc = started_node(kc.clone(), pinned(&[&ka, &kb]), MeshNodeConfig::default()).await;

    let addr_c = nc.local_addr().await.unwrap();
    na.connect_peer(idc, addr_c).await.unwrap();
    nb.connect_peer(idc, addr_c).await.unwrap();

    // Hai vote KHÁC origin/channel/evidence — mọi điều kiện independence thoả
    // TRỪ đường: cả hai đến C qua cùng TCP loopback (cùng path_class).
    let subject = [0xEE; 32];
    let ev_a = vote_event(&ka, 0, subject, [0xA1; 32], ObsChannel::Kernel);
    let ev_b = vote_event(&kb, 0, subject, [0xA2; 32], ObsChannel::FilesystemAcl);
    let (_qa, signed_a) = na.gossip_signed(ev_a).await.unwrap();
    let (_qb, signed_b) = nb.gossip_signed(ev_b).await.unwrap();
    let id_a = signed_a.event_id;
    let id_b = signed_b.event_id;
    wait_until(
        || async { nc.log_contains(&id_a).await && nc.log_contains(&id_b).await },
        "C nhận 2 vote",
    ).await;

    // Đường khác nhau trên GIẤY nhưng cùng path_class THẬT → đếm 1 nguồn.
    let outcome = nc.evaluate_subject(subject).await;
    assert_eq!(
        outcome.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 }),
        "2 vote cùng path_class qua TCP cùng segment phải đếm 1 — close condition M-1"
    );
    // Shadow mode: không đạt quorum → KHÔNG có đề nghị isolate.
    assert_eq!(nc.shadow_len().await, 0);
}

// ---------------------------------------------------------------------------
// Kẻ xấu: frame hỏng tag AEAD — bị đếm, link sống dưới trần, frame tốt vẫn qua
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_frame_counted_and_link_survives_below_cap() {
    let (ka, kb) = (key(), key());
    let ida = node_of(&ka);
    let na = started_node(ka.clone(), pinned(&[&kb]), MeshNodeConfig::default()).await;
    let addr_a = na.local_addr().await.unwrap();

    let mut stream = TcpStream::connect(addr_a).await.unwrap();
    let mut session_b = raw_handshake(&mut stream, &kb, *ka.verifying_key(), ida).await;

    // 1. Frame hỏng tag (lật byte cuối ciphertext) — phải bị đếm là fault.
    let ev1 = vote_event(&kb, 1, [0xEE; 32], [0xA1; 32], ObsChannel::Kernel);
    let mut bad = session_b.seal(FRAME_GOSSIP_EVENT, &ev1.to_wire()).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    stream.write_all(&bad).await.unwrap();

    // 2. Frame tốt ngay sau đó — cửa sổ replay KHÔNG bị frame giả đẩy (tag
    //    verify trước khi commit) → event thật vẫn vào log.
    let ev2 = vote_event(&kb, 2, [0xEE; 32], [0xA2; 32], ObsChannel::FilesystemAcl);
    let good = session_b.seal(FRAME_GOSSIP_EVENT, &ev2.to_wire()).unwrap();
    stream.write_all(&good).await.unwrap();

    wait_until(|| na.log_contains(&ev2.event_id), "frame tốt sau frame hỏng vẫn nhận").await;
    wait_until(
        || async { na.stats().await.crypto_faults >= 1 },
        "fault AEAD được đếm",
    ).await;
    assert!(!na.log_contains(&ev1.event_id).await, "frame hỏng không được nhận");
}

// ---------------------------------------------------------------------------
// Kẻ xấu: peer chưa pin neo — bị từ chối fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_peer_dropped_fail_closed() {
    let (ka, kc) = (key(), key());
    let ida = node_of(&ka);
    let na = started_node(ka.clone(), pinned(&[]), MeshNodeConfig::default()).await;
    let addr_a = na.local_addr().await.unwrap();

    // C tự kết nối, tự khai node_id — A không có neo pinning → drop, không
    // trả HelloAck, không tạo node ngầm trong graph.
    let initiator = Initiator::new(
        HandshakeConfig {
            identity: &kc,
            peer_vk: *ka.verifying_key(),
            peer_node_id: ida,
            version: MESH_WIRE_VERSION,
        },
        &mut OsCryptoRng,
    )
    .unwrap();
    let mut stream = TcpStream::connect(addr_a).await.unwrap();
    stream.write_all(&initiator.hello().encode()).await.unwrap();

    wait_until(
        || async { na.stats().await.links_dropped_unknown_peer >= 1 },
        "unknown peer bị đếm",
    ).await;
    // Socket bị đóng — C đọc được EOF chứ không phải phản hồi giả.
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    assert_eq!(read.unwrap().unwrap(), 0, "phải là EOF (socket đóng)");
}

// ---------------------------------------------------------------------------
// Disconnect giữa chừng → edge Stale, node KHÔNG rớt khỏi graph
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disconnect_stales_edge_without_dropping_graph() {
    let (ka, kb) = (key(), key());
    let (ida, idb) = (node_of(&ka), node_of(&kb));

    let clock_a = Arc::new(ManualClock::new(1_000, 1_000));
    let clock_b = Arc::new(ManualClock::new(1_000, 1_000));
    let na = {
        let n = MeshNode::with_clock(
            ka.clone(),
            pinned(&[&kb]),
            MeshNodeConfig::default(),
            clock_a.clone(),
        );
        n.start().await.unwrap();
        n
    };
    let nb = {
        let n = MeshNode::with_clock(
            kb.clone(),
            pinned(&[&ka]),
            MeshNodeConfig::default(),
            clock_b.clone(),
        );
        n.start().await.unwrap();
        n
    };
    let addr_b = nb.local_addr().await.unwrap();
    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A",
    ).await;

    // A chủ động ngắt — B phải thấy link đóng (đếm, không âm thầm).
    na.disconnect_peer(&idb).await;
    wait_until(
        || async { nb.stats().await.links_closed >= 1 },
        "B ghi nhận link đóng",
    ).await;

    // Đẩy thời gian qua TTL stale rồi GC: edge → Stale, node → Unknown,
    // NHƯNG vẫn nằm trong graph (không rớt, không panic).
    clock_b.advance_mono(EDGE_STALE_MS + 1);
    let report = nb.tick().await;
    assert_eq!(report.staled_edges, 1);
    assert_eq!(report.staled_nodes, 1, "chỉ node A stale — self-node được heartbeat");
    assert_eq!(nb.state_of(&ida).await, Some(NodeState::Unknown));
    assert_eq!(nb.edge_state(&ida).await, Some(EdgeState::Stale));
}

// ---------------------------------------------------------------------------
// Cap link/peer — link thứ hai bị từ chối RÕ RÀNG, link đầu vẫn sống
// ---------------------------------------------------------------------------

#[tokio::test]
async fn link_cap_per_peer_enforced_with_accounting() {
    let (ka, kb) = (key(), key());
    let ida = node_of(&ka);
    let idb = node_of(&kb);

    let cfg_b = MeshNodeConfig { max_links_per_peer: 1, ..MeshNodeConfig::default() };
    let na = started_node(ka.clone(), pinned(&[&kb]), MeshNodeConfig::default()).await;
    let nb = started_node(kb.clone(), pinned(&[&ka]), cfg_b).await;
    let addr_b = nb.local_addr().await.unwrap();

    na.connect_peer(idb, addr_b).await.unwrap();
    wait_until(
        || async { nb.state_of(&ida).await == Some(NodeState::Attested) },
        "B attest A (link 1)",
    ).await;
    // Link thứ hai cùng peer — B pre-check cap rồi CẮT SỚM (không trả
    // HelloAck, không tiết lộ lý do — fail-closed): A thấy link đứt giữa tay.
    let err = na.connect_peer(idb, addr_b).await.unwrap_err();
    assert!(
        matches!(err, MeshError::LinkClosed(_) | MeshError::LimitExceeded { .. }),
        "link thừa phải bị cắt: {err}"
    );
    wait_until(
        || async { nb.stats().await.links_dropped_over_cap >= 1 },
        "cap drop được đếm",
    ).await;

    // Link ĐẦU TIÊN vẫn hoạt động bình thường.
    let ev = vote_event(&ka, 0, [0xEE; 32], [0xA1; 32], ObsChannel::Kernel);
    let (_q, signed) = na.gossip_signed(ev).await.unwrap();
    let event_id = signed.event_id;
    wait_until(|| nb.log_contains(&event_id), "link đầu vẫn trao đổi được").await;
}
