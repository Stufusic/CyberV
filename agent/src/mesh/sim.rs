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
            arrival_path: i as u64,
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
