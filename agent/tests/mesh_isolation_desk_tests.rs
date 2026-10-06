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
//! M-PLAN I-2 — Isolation Desk close conditions:
//! - quorum (đa dạng path thật) → đề nghị → operator duyệt → thực thi
//!   (logic-only trên loopback — plan §9 cấm rule WFP cho loopback);
//! - approve không có đề nghị → từ chối rõ ràng;
//! - grace de-escalation: sau isolation, re-attest phải qua Suspect +
//!   K tick sạch mới Attested (không nhảy thẳng);
//! - benign: không có quorum → không có đề nghị (đã chốt ở test M-1).

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::events::{EventKind, NsgEvent, ObsChannel, SignalClass};
use cyberv_agent::mesh::graph::{NodeId, NodeState};
use cyberv_agent::mesh::isolation::{DecisionAction, EnforcementMode};
use cyberv_agent::mesh::node::{ManualClock, MeshNode, MeshNodeConfig};
use cyberv_agent::mesh::quorum::{QuorumPolicy, QuorumVerdict};

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

fn vote_event(key: &DeviceIdentityKey, subject: NodeId, root: [u8; 32], channel: ObsChannel) -> NsgEvent {
    let wall = wall_now();
    let mut ev = NsgEvent {
        event_id: [0; 32],
        origin_id: key.verifying_key().to_bytes(),
        origin_seq: 0,
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

/// Địa chỉ LAN cục bộ (không gửi packet — trick UDP connect).
fn local_lan_ip() -> Option<std::net::IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("10.254.254.254:1").ok()?;
    Some(sock.local_addr().ok()?.ip())
}

#[tokio::test]
async fn approve_without_pending_proposal_is_rejected() {
    let ka = key();
    let na = {
        let n = MeshNode::new(ka.clone(), pinned(&[]), MeshNodeConfig::default());
        n.start().await.unwrap();
        n
    };
    // Không có đề nghị nào — approve phải từ chối RÕ RÀNG.
    let err = na.approve_isolation([0xEE; 32], "không có căn cứ").await;
    assert!(err.is_err(), "isolate tay không căn cứ phải bị từ chối");
    assert_eq!(na.pending_isolation_proposals().await.len(), 0);
}

#[tokio::test]
async fn quorum_proposal_then_operator_approve_then_grace_deescalation() {
    let (ka, kb, kc, kd) = (key(), key(), key(), key());
    let (ida, idb, idc, idd) = (node_of(&ka), node_of(&kb), node_of(&kc), node_of(&kd));
    let victim = idd;

    // C cần hai đường KHÁC nhau thật để quorum đạt (M-PLAN §1.2): A đi
    // loopback, B đi LAN IP. Thiếu LAN IP (máy không có mạng) → SKIP rõ ràng.
    let Some(lan_ip) = local_lan_ip() else {
        eprintln!("SKIP (máy không có địa chỉ LAN để tạo path diversity)");
        return;
    };
    if lan_ip.is_loopback() {
        eprintln!("SKIP (LAN IP resolve về loopback — không tạo được đa dạng path)");
        return;
    }

    // Policy quorum hạ ngưỡng: 2 node cold-start (150 mỗi node) = 300 ≥ 300.
    let cfg_c = MeshNodeConfig {
        listen_addr: "0.0.0.0:0".parse().unwrap(),
        quorum: QuorumPolicy {
            threshold_weight: 300,
            min_votes: 2,
            require_verified: true,
            max_ballots: 64,
        },
        ..MeshNodeConfig::default()
    };

    let clock_c = Arc::new(ManualClock::new(1_000, wall_now()));
    let na = {
        let n = MeshNode::new(ka.clone(), pinned(&[&kc]), MeshNodeConfig::default());
        n.start().await.unwrap();
        n
    };
    let nb = {
        let n = MeshNode::new(kb.clone(), pinned(&[&kc]), MeshNodeConfig::default());
        n.start().await.unwrap();
        n
    };
    let clock_d = Arc::new(ManualClock::new(1_000, wall_now()));
    let nd = {
        let n = MeshNode::with_clock(
            kd.clone(),
            pinned(&[&kc]),
            MeshNodeConfig::default(),
            clock_d.clone(),
        );
        n.start().await.unwrap();
        n
    };
    let nc = {
        let n = MeshNode::with_clock(kc.clone(), pinned(&[&ka, &kb, &kd]), cfg_c, clock_c.clone());
        n.start().await.unwrap();
        n
    };

    let addr_c = nc.local_addr().await.unwrap();
    let addr_c_loopback: SocketAddr = format!("127.0.0.1:{}", addr_c.port()).parse().unwrap();
    let addr_c_lan: SocketAddr = SocketAddr::new(lan_ip, addr_c.port());

    // D (victim) attest với C; A đi loopback; B đi LAN — path_class khác nhau.
    nd.connect_peer(idc, addr_c_loopback).await.unwrap();
    na.connect_peer(idc, addr_c_loopback).await.unwrap();
    nb.connect_peer(idc, addr_c_lan).await.unwrap();
    wait_until(|| async {
        nc.state_of(&ida).await == Some(NodeState::Attested)
            && nc.state_of(&idb).await == Some(NodeState::Attested)
            && nc.state_of(&idd).await == Some(NodeState::Attested)
    }, "C attest cả 3 peer")
    .await;

    // Hai vote về D từ HAI ĐƯỜNG khác nhau — quorum phải ĐẠT.
    let ev_a = vote_event(&ka, victim, [0xA1; 32], ObsChannel::Kernel);
    let ev_b = vote_event(&kb, victim, [0xA2; 32], ObsChannel::FilesystemAcl);
    let (_q, signed_a) = na.gossip_signed(ev_a).await.unwrap();
    let (_q, signed_b) = nb.gossip_signed(ev_b).await.unwrap();
    wait_until(|| async {
        nc.log_contains(&signed_a.event_id).await && nc.log_contains(&signed_b.event_id).await
    }, "C nhận 2 vote từ 2 đường")
    .await;

    let outcome = nc.evaluate_subject(victim).await;
    match &outcome.verdict {
        QuorumVerdict::Reached { total_weight, .. } => {
            assert_eq!(*total_weight, 300, "2×150 cold-start = 300 ≥ ngưỡng 300");
        }
        other => panic!("quorum phải đạt với 2 path_class khác nhau: {other:?}"),
    }

    // Đề nghị xuất hiện trong Inbox — CHỜ NGƯỜI, không tự thực thi.
    let proposals = nc.pending_isolation_proposals().await;
    assert_eq!(proposals.len(), 1, "đúng một đề nghị cho victim");
    assert_eq!(proposals[0].subject, victim);
    assert_eq!(proposals[0].accepted_event_ids.len(), 2);
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Attested), "chưa duyệt thì không isolate");

    // Operator DUYỆT — loopback peer → LogicOnly (plan §9 cấm rule WFP
    // loopback; trung thực thay vì giả vờ chặn).
    let enforcement = nc.approve_isolation(victim, "quorum + operator duyệt").await.unwrap();
    assert_eq!(enforcement, EnforcementMode::LogicOnly);
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Isolated));
    wait_until(
        || async {
            nc.paths_of(&idd).await.is_empty() && nd.stats().await.links_closed >= 1
        },
        "link với victim bị cắt (C không còn record nào cho D)",
    )
    .await;
    // Sổ quyết định ghi rõ — audit hai chiều.
    let proposals_after = nc.pending_isolation_proposals().await;
    assert_eq!(proposals_after.len(), 0, "đề nghị đã được quyết");

    // ---- Grace de-escalation: hết TTL → re-attest → Suspect → K tick sạch
    // ---- → Attested (KHÔNG nhảy thẳng).
    clock_c.advance_mono(MeshNodeConfig::default().isolation_ttl_ms + 1);
    nc.tick().await;
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Unknown), "TTL lift về Unknown");

    nd.connect_peer(idc, addr_c_loopback).await.unwrap();
    wait_until(
        || async { nc.state_of(&idd).await == Some(NodeState::Suspect) },
        "re-attest sau isolation phải ở Suspect (probation)",
    )
    .await;

    // 2 tick đầu chưa đủ (probation_ticks = 3).
    nc.tick().await;
    nc.tick().await;
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Suspect));
    // Tick thứ 3 sạch → Attested.
    nc.tick().await;
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Attested));

    // ---- Admin lift: isolate lại (qua alert) rồi lift → Suspect, không Attested.
    nd.self_isolate("test lift").await.unwrap();
    wait_until(
        || async { nc.state_of(&idd).await == Some(NodeState::Isolated) },
        "alert tự tố đưa D về Isolated",
    )
    .await;
    // D hết TTL tự cách ly của CHÍNH NÓ (đồng hồ D) rồi mới connect lại được.
    clock_d.advance_mono(MeshNodeConfig::default().isolation_ttl_ms + 1);
    nd.tick().await;
    // C hết deadline isolation cho D (đồng hồ C) → D về Unknown (INV-014).
    clock_c.advance_mono(MeshNodeConfig::default().isolation_ttl_ms + 1);
    nc.tick().await;
    assert_eq!(nc.state_of(&idd).await, Some(NodeState::Unknown));
    nd.connect_peer(idc, addr_c_loopback).await.unwrap();
    wait_until(|| async { nc.state_of(&idd).await == Some(NodeState::Suspect) }, "D probation lần 2")
        .await;
    // Admin lift ngay từ Suspect → phải lỗi rõ ràng (lift chỉ áp cho Isolated).
    let lift_err = nc.lift_isolation(idd, "chưa isolated").await;
    assert!(lift_err.is_err());

    // Unused-guard: các import dùng cho assert typed ở trên.
    let _ = DecisionAction::Approve;
}
