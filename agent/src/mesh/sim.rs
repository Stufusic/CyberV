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
//! mesh-sim — harness benchmark NSG-3.5 (pure, đo trên chính tầng mesh)
//!
//! Ref: plan v2 §11 — benchmark framework với các metric bắt buộc; số liệu
//! này là gate cho NSG-4 (wrong-action rate + hiệu năng phải xanh trước khi
//! mở hành động thật). Khác với §11 gốc (đo LAN thật ở NSG-2b), bản pure này
//! đo **tầng logic**: quorum decision, handshake crypto, seal/open, ingest,
//! graph fill — chính là những đường nóng CPU khi mesh vận hành.
//!
//! Trung thực: đây là số liệu máy dev đơn process — KHÔNG thay thế đo
//! distributed (NSG-2b/NSG-7); mọi số công bố phải ghi rõ nguồn đo.

use std::time::{Duration, Instant};

use crate::identity::keypair::DeviceIdentityKey;
use crate::identity::rng::OsCryptoRng;
use crate::mesh::events::{EventKind, NsgEvent, ObsChannel, SignalClass};
use crate::mesh::gossip::{GossipInbox, GossipPolicy};
use crate::mesh::graph::{MeshGraph, NodeId};
use crate::mesh::quorum::{evaluate_quorum, Ballot, QuorumPolicy};
use crate::mesh::session::{HandshakeConfig, Initiator, MeshSession, Responder, MESH_WIRE_VERSION};

/// Kết quả một lượt chạy benchmark đầy đủ.
#[derive(Debug, Clone, Copy)]
pub struct BenchReport {
    pub rounds: usize,
    /// Trung bình 1 lượt `evaluate_quorum` với 256 phiếu.
    pub quorum_decision_256: Duration,
    /// Trung bình 1 bắt tay 3 bước trọn vẹn (gồm RNG + ký).
    pub handshake_avg: Duration,
    /// Trung bình 1 cặp seal + open.
    pub seal_open_avg: Duration,
    /// Tổng thời gian ingest 1000 event đã ký sẵn (không tính ký).
    pub gossip_ingest_1000: Duration,
    /// Lấp đầy graph tới bound (256 node / 2048 edge) + 1 lượt GC.
    pub graph_fill_and_gc: Duration,
}

fn nid(seed: u8) -> NodeId {
    let mut n = [0u8; 32];
    n[0] = seed;
    n
}

/// Quorum decision — 256 phiếu, weight đầy đủ, 8 channel (đủ để greedy quét
/// hết 256 phiếu và reach quorum: 8×1000 = 8000 ≥ 1800).
fn bench_quorum(rounds: usize) -> Duration {
    let subject = nid(0xEE);
    let mut ballots = Vec::with_capacity(256);
    for i in 0..256u16 {
        ballots.push(Ballot {
            event_id: {
                let mut e = [0u8; 32];
                e[0] = i as u8;
                e[1] = (i >> 8) as u8;
                e
            },
            origin_id: {
                let mut o = [0u8; 32];
                o[0] = i as u8;
                o[1] = (i >> 8) as u8;
                o
            },
            epoch: 0,
            subject,
            signal_class: SignalClass::Verified,
            obs_channel: crate::mesh::events::ObsChannel::from_u8((i % 8 + 1) as u8)
                .unwrap_or(ObsChannel::Other),
            // Root phân biệt theo phiếu — nếu chung root thì greedy chỉ nhận
            // 1 phiếu (điều kiện 3), mất ý nghĩa đo worst-case.
            evidence_root: {
                let mut r = [0xA0u8; 32];
                r[0] = i as u8;
                r[1] = (i >> 8) as u8;
                r
            },
            causal_parents: vec![],
            path_class: i as u64,
            weight: 1000,
        });
    }
    let policy = QuorumPolicy::default();
    let start = Instant::now();
    for _ in 0..rounds {
        let _ = evaluate_quorum(&ballots, subject, 0, |_| false, &policy);
    }
    start.elapsed() / rounds.max(1) as u32
}

/// Bắt tay trọn vẹn 1 cặp (2 khóa mới mỗi lần — gồm RNG + Ed25519 + X25519).
fn bench_handshake_once() -> Duration {
    let ki = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let kr = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let start = Instant::now();
    let init = Initiator::new(
        HandshakeConfig {
            identity: &ki,
            peer_vk: *kr.verifying_key(),
            peer_node_id: kr.verifying_key().to_bytes(),
            version: MESH_WIRE_VERSION,
        },
        &mut OsCryptoRng,
    )
    .unwrap();
    let mut resp = Responder::new(
        HandshakeConfig {
            identity: &kr,
            peer_vk: *ki.verifying_key(),
            peer_node_id: ki.verifying_key().to_bytes(),
            version: MESH_WIRE_VERSION,
        },
        &mut OsCryptoRng,
    )
    .unwrap();
    let hello = init.hello();
    let ack = resp.handle_hello(&hello).unwrap();
    let (_session_i, confirm) = init.handle_ack(&ack).unwrap();
    let _session_r = resp.handle_confirm(&confirm).unwrap();
    start.elapsed()
}

/// 1 cặp seal + open trên phiên đã thiết lập.
fn bench_seal_open(session_i: &mut MeshSession, session_r: &mut MeshSession) -> Duration {
    let start = Instant::now();
    let frame = session_i.seal(1, &[0u8; 512]).unwrap();
    let _ = session_r.open(&frame).unwrap();
    start.elapsed()
}

/// Ingest 1000 event ĐÃ KÝ SẴN (không tính ký — đo thuần pipeline inbox).
fn bench_gossip_ingest_1000() -> Duration {
    let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let origin = key.verifying_key().to_bytes();
    let mut inbox = GossipInbox::with_log(
        GossipPolicy {
            max_events_per_peer_per_window: u32::MAX / 2,
            window_ms: u64::MAX / 2,
            max_peers: 16,
        },
        crate::mesh::events::EventLog::new(2048),
    );
    let mut events = Vec::with_capacity(1000);
    for seq in 1..=1000u64 {
        let mut ev = NsgEvent {
            event_id: [0; 32],
            origin_id: origin,
            origin_seq: seq,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some([0xA0; 32]),
            created_wall_ms: 0,
            expiry_wall_ms: u64::MAX / 2,
            kind: EventKind::Vote,
            signal_class: Some(SignalClass::Verified),
            subject: Some(nid(0xEE)),
            obs_channel: Some(ObsChannel::Kernel),
            signature: [0; 64],
        };
        ev.sign(&key);
        events.push(ev);
    }
    let start = Instant::now();
    for ev in events {
        let _ = inbox
            .ingest(origin, ev, key.verifying_key(), 0, 1000, 0)
            .unwrap();
    }
    start.elapsed()
}

/// Lấp đầy graph tới bound + 1 lượt GC.
fn bench_graph_fill_bound() -> Duration {
    let start = Instant::now();
    let mut g = MeshGraph::new();
    for i in 0..256u16 {
        let mut id = [0u8; 32];
        id[0] = i as u8;
        id[1] = (i >> 8) as u8;
        let _ = g.observe(id, i as u64);
    }
    'outer: for a in 0..255u16 {
        for b in (a + 1)..=255u16 {
            let mut ia = [0u8; 32];
            ia[0] = a as u8;
            ia[1] = (a >> 8) as u8;
            let mut ib = [0u8; 32];
            ib[0] = b as u8;
            ib[1] = (b >> 8) as u8;
            let _ = g.link(ia, ib, 10_000);
            if g.edge_count() >= crate::mesh::graph::MAX_EDGES {
                break 'outer;
            }
        }
    }
    let _ = g.tick_gc(10_000 + crate::mesh::graph::EDGE_STALE_MS + 1);
    start.elapsed()
}

/// Chạy toàn bộ suite benchmark. `rounds` càng cao càng ổn định (khuyến nghị ≥ 200).
pub fn run_full(rounds: usize) -> BenchReport {
    // Session dùng chung cho seal/open bench.
    let ki = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let kr = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
    let init = Initiator::new(
        HandshakeConfig {
            identity: &ki,
            peer_vk: *kr.verifying_key(),
            peer_node_id: kr.verifying_key().to_bytes(),
            version: MESH_WIRE_VERSION,
        },
        &mut OsCryptoRng,
    )
    .unwrap();
    let mut resp = Responder::new(
        HandshakeConfig {
            identity: &kr,
            peer_vk: *ki.verifying_key(),
            peer_node_id: ki.verifying_key().to_bytes(),
            version: MESH_WIRE_VERSION,
        },
        &mut OsCryptoRng,
    )
    .unwrap();
    let ack = resp.handle_hello(&init.hello()).unwrap();
    let (mut session_i, confirm) = init.handle_ack(&ack).unwrap();
    let mut session_r = resp.handle_confirm(&confirm).unwrap();

    let handshake_total = (0..rounds).map(|_| bench_handshake_once()).sum::<Duration>();
    let seal_open_total = (0..rounds)
        .map(|_| bench_seal_open(&mut session_i, &mut session_r))
        .sum::<Duration>();

    BenchReport {
        rounds,
        quorum_decision_256: bench_quorum(rounds),
        handshake_avg: handshake_total / rounds.max(1) as u32,
        seal_open_avg: seal_open_total / rounds.max(1) as u32,
        gossip_ingest_1000: bench_gossip_ingest_1000(),
        graph_fill_and_gc: bench_graph_fill_bound(),
    }
}

/// Kết quả mô phỏng isolate/recover/reconcile (M-PLAN §6.3).
#[derive(Debug, Clone, Copy)]
pub struct IsolationSimReport {
    pub rounds: usize,
    pub nodes: usize,
    /// Số lệnh isolate đã phát (quorum hoặc alert).
    pub isolations_issued: u64,
    /// Số isolation được GC lift đúng TTL (INV-014 — phải = isolations
    /// trừ số đang còn hạn cuối vòng đo; sim thiết kế để tất cả hết hạn).
    pub ttl_lifts: u64,
    /// Số đề nghị shadow đã ghi (Reached).
    pub proposals_created: u64,
    /// Số quyết định operator đã log (audit hai chiều).
    pub decisions_logged: u64,
    /// Số node bị stale khi partition rồi sống lại khi merge.
    pub partition_staled: u64,
    pub elapsed: Duration,
}

/// Mô phỏng isolate/recover/reconcile trên 256 node + chu kỳ partition/merge
/// (M-PLAN §6.3: đo trước khi đụng WFP thật). Pure logic — dùng đúng
/// MeshGraph + ShadowLedger + DecisionLog + quorum engine của production,
/// KHÔNG mô hình song song riêng. Deterministic qua LCG nội bộ (không RNG
/// hệ thống) để số liệu tái lập được.
///
/// Mô hình thời gian: mỗi round = 20s mono (EDGE_STALE_MS = 3 phút → node
/// không refresh ~9 round sẽ stale — partition tác động thật trên đồ thị).
/// Partition: nửa node không được refresh; merge: refresh lại (Discovered),
/// đúng luật presence ≠ trust.
pub fn run_isolation_sim(rounds: usize) -> IsolationSimReport {
    use crate::mesh::events::{ObsChannel, SignalClass};
    use crate::mesh::graph::{NodeState, ISOLATION_TTL_MS};
    use crate::mesh::isolation::{DecisionAction, DecisionEntry, DecisionLog, EnforcementMode};
    use crate::mesh::quorum::{evaluate_quorum, Ballot, QuorumPolicy};
    use crate::mesh::shadow::ShadowLedger;

    const N: usize = crate::mesh::graph::MAX_NODES; // 256
    const STEP_MS: u64 = 20_000;
    const PARTITION_EVERY: u64 = 16; // partition 11 round mỗi 16 round (> EDGE_STALE_MS/STEP)

    let mut rng = 0x2545_F491_4F6C_DD1Du64; // seed cố định — sim tái lập được

    let mut graph = MeshGraph::new();
    let mut shadow = ShadowLedger::new();
    let mut decisions = DecisionLog::new();
    // Probation mô phỏng đúng engine: subject → tick sạch còn lại.
    let mut probation: std::collections::HashMap<NodeId, u32> = std::collections::HashMap::new();
    let mut observed: Vec<NodeId> = Vec::with_capacity(N);

    for i in 0..N {
        let id = nid((i % 256) as u8);
        if !observed.contains(&id) {
            observed.push(id);
            let _ = graph.observe(id, 0);
            let _ = graph.transition(&id, NodeState::Attested);
        }
    }

    let mut isolations = 0u64;
    let mut proposals = 0u64;
    let mut decided = 0u64;
    let mut partition_staled = 0u64;
    let mut ttl_lifts = 0u64;
    let start = Instant::now();

    for round in 0..rounds {
        let now = (round as u64).saturating_mul(STEP_MS);
        let in_partition = round as u64 % PARTITION_EVERY >= 5;

        // ---- 1. Refresh presence: toàn trừ nửa node khi partition (chúng
        //      "mất dấu" → tick_gc sẽ stale đúng luật, không mutation ngoài).
        for (i, id) in observed.iter().enumerate() {
            let is_half = i < observed.len() / 2;
            if !(in_partition && is_half) {
                let _ = graph.observe(*id, now);
            }
        }

        // ---- 2. Quorum đề nghị: hai phiếu "verified" từ HAI ĐƯỜNG khác nhau
        //      (path_class mô phỏng: 2×round và 2×round+1), origin khác nhau.
        let subject = observed[(rng % observed.len() as u64) as usize];
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let mut b1 = Ballot {
            event_id: [round as u8, 1, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            origin_id: observed[(rng as usize) % observed.len()],
            epoch: 0,
            subject,
            signal_class: SignalClass::Verified,
            obs_channel: ObsChannel::Kernel,
            evidence_root: [round as u8 + 1, 0xDE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            causal_parents: vec![],
            path_class: 2 * (round as u64),
            weight: 1000,
        };
        b1.event_id[2] = 0xA1;
        let mut b2 = Ballot {
            event_id: [round as u8, 2, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            origin_id: observed[((rng >> 8) as usize + 1) % observed.len()],
            epoch: 0,
            subject,
            signal_class: SignalClass::Verified,
            obs_channel: ObsChannel::EtwTelemetry,
            evidence_root: [round as u8 + 2, 0xDF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            causal_parents: vec![],
            path_class: 2 * (round as u64) + 1,
            weight: 1000,
        };
        if b1.origin_id == b2.origin_id {
            b2.origin_id = observed[(observed.len() - 1).saturating_sub((rng as usize) % observed.len())];
        }
        let outcome = evaluate_quorum(&[b1, b2], subject, 0, |_| false, &QuorumPolicy::default());
        if matches!(outcome.verdict, crate::mesh::quorum::QuorumVerdict::Reached { .. }) {
            if shadow.record(subject, &outcome, ISOLATION_TTL_MS, now).is_ok() {
                proposals += 1;
            }
            // Operator duyệt (I-2 human-in-the-loop — sim chọn approve luôn)
            // — nhưng CHỈ khi subject còn Attested/Suspect: subject bị partition
            // stale về Unknown thì isolate là transition bất hợp lệ (đúng
            // production approve_isolation trả Err).
            let executable = graph
                .node(&subject)
                .map(|n| matches!(n.state, NodeState::Attested | NodeState::Suspect))
                .unwrap_or(false);
            if executable {
                // Đúng luồng production: Attested → Suspect trước khi isolate.
                if graph.node(&subject).map(|n| n.state == NodeState::Attested).unwrap_or(false) {
                    let _ = graph.transition(&subject, NodeState::Suspect);
                }
                if decisions
                    .record(DecisionEntry {
                        subject,
                        action: DecisionAction::Approve,
                        enforcement: EnforcementMode::LogicOnly,
                        evidence_refs: Vec::new(),
                        decided_mono_ms: now,
                        decided_wall_ms: now,
                        reason: "sim".into(),
                    })
                    .is_ok()
                {
                    decided += 1;
                }
                if graph.isolate_with_ttl(&subject, now, ISOLATION_TTL_MS).is_ok() {
                    isolations += 1;
                }
                probation.insert(subject, 3);
            }
        }

        // ---- 3. GC định kỳ: TTL lift + stale — đúng tick_gc production.
        //      Lifts giữa chừng phải CỘNG DỒN (không chỉ đếm tick cuối).
        let report = graph.tick_gc(now);
        partition_staled += report.staled_nodes as u64;
        ttl_lifts += report.lifted_isolations as u64;

        // ---- 4. Probation mô phỏng: tick sạch → Suspect → Attested.
        let subjects: Vec<NodeId> = probation.keys().copied().collect();
        for subject in subjects {
            let Some(node) = graph.node(&subject) else {
                probation.remove(&subject);
                continue;
            };
            if node.state != NodeState::Suspect {
                continue;
            }
            let left = probation.get_mut(&subject).map(|t| {
                *t = t.saturating_sub(1);
                *t
            });
            if left == Some(0) {
                probation.remove(&subject);
                let _ = graph.transition(&subject, NodeState::Attested);
            }
        }
    }

    // Vòng cuối: đẩy thời gian thật xa để mọi isolation còn lại hết TTL
    // (INV-014 — reversibility; sim chứng minh không isolation vĩnh viễn).
    let final_now = (rounds as u64).saturating_mul(STEP_MS) + ISOLATION_TTL_MS + 1;
    let report = graph.tick_gc(final_now);
    ttl_lifts += report.lifted_isolations as u64;

    IsolationSimReport {
        rounds,
        nodes: graph.node_count(),
        isolations_issued: isolations,
        ttl_lifts,
        proposals_created: proposals,
        decisions_logged: decided,
        partition_staled,
        elapsed: start.elapsed(),
    }
}

#[cfg(test)]
mod sim_tests {
    use super::*;

    #[test]
    fn isolation_sim_lifts_all_ttls_and_logs_decisions() {
        let report = run_isolation_sim(60);
        assert_eq!(report.nodes, crate::mesh::graph::MAX_NODES);
        assert!(report.proposals_created > 0, "sim phải sinh đề nghị quorum");
        assert!(report.decisions_logged > 0);
        assert!(
            report.decisions_logged <= report.proposals_created,
            "chỉ đề nghị trên node còn Attested/Suspect mới được duyệt thực thi"
        );
        assert_eq!(
            report.decisions_logged, report.isolations_issued,
            "mỗi quyết định duyệt phải đúng một isolate"
        );
        assert!(report.isolations_issued > 0);
        assert_eq!(
            report.isolations_issued, report.ttl_lifts,
            "mọi isolation phải được lift đúng TTL — không có isolation vĩnh viễn (INV-014)"
        );
        assert!(report.partition_staled > 0, "partition phải tạo stale node/edge");
        assert!(report.elapsed.as_secs() < 60, "sim phải hoàn thành nhanh");
    }
}
