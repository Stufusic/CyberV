//! NSG-3 — Gossip + Incident Correlation + Shadow Ledger integration tests
//!
//! Ref: plan v2 §12 điều kiện đóng NSG-3: (1) flood/replay/poison bị từ chối +
//! đếm; (2) shadow ledger không thực thi action nào; (3) suspect ranking xuất
//! đúng format §7.2.
//!
//! Luồng end-to-end: report/vote → GossipInbox → EventLog → ballots → quorum
//! → ShadowLedger + SuspectRank.

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::correlation::{
    rank_suspect, sweep_indicators, FpIndicator, Indicator, IndicatorKind,
};
use cyberv_agent::mesh::events::{
    AcceptOutcome, EventKind, NsgEvent, ObsChannel, SignalClass,
};
use cyberv_agent::mesh::gossip::{GossipInbox, GossipPolicy};
use cyberv_agent::mesh::graph::NodeId;
use cyberv_agent::mesh::quorum::{
    evaluate_quorum, Ballot, NotReachedReason, QuorumPolicy, QuorumVerdict,
};
use cyberv_agent::mesh::reputation::ReputationLedger;
use cyberv_agent::mesh::shadow::{ProposedAction, ShadowLedger, ShadowOutcome};

const SUBJECT: NodeId = [0xEE; 32];
const NOW_WALL: u64 = 1_000_000;

/// Node chín muồi qua ĐÚNG public API (giữ nhất quán với mesh_quorum_tests).
struct Voter {
    key: DeviceIdentityKey,
    id: NodeId,
    next_seq: u64,
}

impl Voter {
    fn new(ledger: &mut ReputationLedger) -> Self {
        let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let id = key.verifying_key().to_bytes();
        ledger.on_attested(id, NOW_WALL);
        Self { key, id, next_seq: 1 }
    }

    fn mature(self, ledger: &mut ReputationLedger) -> Self {
        for _ in 0..50 {
            ledger.on_observation(&self.id, true);
        }
        for _ in 0..60 {
            ledger.on_evidence_verified(&self.id);
        }
        for i in 0..60u64 {
            ledger.record_corroborated(&self.id, NOW_WALL + i);
        }
        for _ in 0..250 {
            ledger.record_consistent(&self.id);
        }
        ledger.refresh_cold_start(&self.id, NOW_WALL + 30 * 86_400_000);
        self
    }

    /// Gửi event qua GossipInbox (đường gossip thật, không nộp trực tiếp log).
    fn send_vote(
        &mut self,
        inbox: &mut GossipInbox,
        subject: NodeId,
        root: [u8; 32],
        class: SignalClass,
        channel: ObsChannel,
        now_mono_ms: u64,
    ) -> NsgEvent {
        let mut ev = NsgEvent {
            event_id: [0u8; 32],
            origin_id: self.id,
            origin_seq: self.next_seq,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some(root),
            created_wall_ms: NOW_WALL,
            expiry_wall_ms: NOW_WALL + 3_600_000,
            kind: EventKind::Vote,
            signal_class: Some(class),
            subject: Some(subject),
            obs_channel: Some(channel),
            signature: [0u8; 64],
        };
        ev.sign(&self.key);
        self.next_seq += 1;
        inbox
            .ingest(self.id, ev.clone(), self.key.verifying_key(), now_mono_ms, NOW_WALL + 500, 0)
            .expect("vote hợp lệ phải qua được inbox");
        ev
    }

    fn weight(&self, ledger: &ReputationLedger) -> u32 {
        ledger.weight_of(&self.id)
    }
}

fn ballots_from(events: &[NsgEvent], ledger: &ReputationLedger, paths: &[u64]) -> Vec<Ballot> {
    events
        .iter()
        .zip(paths.iter())
        .filter_map(|(ev, path)| Ballot::from_event(ev, ledger.weight_of(&ev.origin_id), *path))
        .collect()
}

// ====================================================================
// Nhóm 1: End-to-end report → quorum → shadow (KHÔNG thực thi)
// ====================================================================

#[test]
fn test_01_quorum_reaches_shadow_records_but_never_executes() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.send_vote(&mut inbox, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 10);
    let e2 = b.send_vote(&mut inbox, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 20);
    let e3 = c.send_vote(&mut inbox, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 30);

    let ballots = ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]);
    let outcome = evaluate_quorum(&ballots, SUBJECT, 0, |_| false, &QuorumPolicy::default());
    assert!(matches!(outcome.verdict, QuorumVerdict::Reached { total_weight: 2400, .. }));

    // Shadow ledger GHI đề nghị isolate — nhưng không có đường thực thi nào.
    let mut shadow = ShadowLedger::new();
    shadow.record(SUBJECT, &outcome, 900_000, 1000).unwrap();
    let entry = shadow.entries().next().unwrap();
    assert_eq!(entry.proposed_action, ProposedAction::Isolate { ttl_ms: 900_000 });
    assert_eq!(entry.accepted_event_ids.len(), 3);
    // Bất biến trung tâm: KHÔNG entry nào executed, mãi mãi.
    assert!(shadow.all_unexecuted());

    // Sau khi ghi shadow, reputation của voter KHÔNG đổi — shadow không đụng ai.
    assert_eq!(a.weight(&ledger), 800);
    assert_eq!(b.weight(&ledger), 800);
}

#[test]
fn test_02_wrong_action_replay_feeds_reputation_and_breaks_future_quorum() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.send_vote(&mut inbox, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 10);
    let e2 = b.send_vote(&mut inbox, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 20);
    let e3 = c.send_vote(&mut inbox, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 30);
    let outcome = evaluate_quorum(
        &ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]),
        SUBJECT, 0, |_| false, &QuorumPolicy::default(),
    );
    assert!(matches!(outcome.verdict, QuorumVerdict::Reached { .. }));

    // Shadow + replay hậu kỳ kết luận: ĐỀ NGHỊ SAI (subject lành).
    let mut shadow = ShadowLedger::new();
    shadow.record(SUBJECT, &outcome, 900_000, 1000).unwrap();
    assert!(shadow.mark_outcome(&SUBJECT, ShadowOutcome::WrongAction));
    assert_eq!(shadow.wrong_action_count(), 1);

    // Caller (daemon NSG-4) feed decay cho các voter — B report sai 2 lần
    // (mô phỏng lặp lại) → weight 0 → quorum cho subject MỚI không còn đủ.
    ledger.record_wrong_action(&b.id, NOW_WALL + 10);
    ledger.record_wrong_action(&b.id, NOW_WALL + 20);
    assert_eq!(b.weight(&ledger), 0);

    let e4 = a.send_vote(&mut inbox, [0x77; 32], [0xB1; 32], SignalClass::Verified, ObsChannel::Kernel, 40);
    let e5 = b.send_vote(&mut inbox, [0x77; 32], [0xB2; 32], SignalClass::Verified, ObsChannel::FilesystemAcl, 50);
    let e6 = c.send_vote(&mut inbox, [0x77; 32], [0xB3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 60);
    let outcome2 = evaluate_quorum(
        &ballots_from(&[e4, e5, e6], &ledger, &[4, 5, 6]),
        [0x77; 32], 0, |_| false, &QuorumPolicy::default(),
    );
    // A(800) + B(0, bị lọc) + C(800) = 1600 < 1800 → không đủ.
    assert!(matches!(
        outcome2.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight { total: 1600, .. })
    ));
}

// ====================================================================
// Nhóm 2: Flood/poison bị từ chối + đếm (điều kiện đóng NSG-3)
// ====================================================================

#[test]
fn test_03_flood_limited_per_peer_without_starving_others() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::with_log(
        GossipPolicy {
            max_events_per_peer_per_window: 3,
            window_ms: 60_000,
            max_peers: 16,
        },
        cyberv_agent::mesh::events::EventLog::new(1024),
    );
    let mut spam = Voter::new(&mut ledger);
    let honest = Voter::new(&mut ledger);

    // Spam peer xả 3 phiếu trong cửa sổ + 2 vượt → 2 flood drop được đếm.
    for seq in 0..5u64 {
        let mut ev = NsgEvent {
            event_id: [0; 32],
            origin_id: spam.id,
            origin_seq: spam.next_seq,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some([0xD0; 32]),
            created_wall_ms: NOW_WALL,
            expiry_wall_ms: NOW_WALL + 3_600_000,
            kind: EventKind::Vote,
            signal_class: Some(SignalClass::Heuristic),
            subject: Some(SUBJECT),
            obs_channel: Some(ObsChannel::Other),
            signature: [0; 64],
        };
        ev.sign(&spam.key);
        spam.next_seq += 1;
        let res = inbox.ingest(spam.id, ev, spam.key.verifying_key(), 10 + seq, NOW_WALL + 100, 0);
        if seq < 3 {
            assert!(matches!(res, Ok(AcceptOutcome::Accepted)));
        } else {
            assert!(matches!(res, Err(cyberv_agent::mesh::MeshError::LimitExceeded { .. })));
        }
    }
    assert_eq!(inbox.stats(&spam.id).unwrap().flood_dropped, 2);
    assert_eq!(inbox.stats(&spam.id).unwrap().accepted, 3);

    // Peer khác gửi đúng lúc — không bị starve.
    let mut ev_ok = NsgEvent {
        event_id: [0; 32],
        origin_id: honest.id,
        origin_seq: 1,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: Some([0xD1; 32]),
        created_wall_ms: NOW_WALL,
        expiry_wall_ms: NOW_WALL + 3_600_000,
        kind: EventKind::Heartbeat,
        signal_class: None,
        subject: None,
        obs_channel: None,
        signature: [0; 64],
    };
    ev_ok.sign(&honest.key);
    inbox
        .ingest(honest.id, ev_ok, honest.key.verifying_key(), 100, NOW_WALL + 100, 0)
        .unwrap();
    assert_eq!(inbox.stats(&honest.id).unwrap().accepted, 1);
}

#[test]
fn test_04_poison_and_replay_are_classified_and_counted() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut v = Voter::new(&mut ledger);

    let mut ev = NsgEvent {
        event_id: [0; 32],
        origin_id: v.id,
        origin_seq: v.next_seq,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: Some([0xD0; 32]),
        created_wall_ms: NOW_WALL,
        expiry_wall_ms: NOW_WALL + 3_600_000,
        kind: EventKind::Vote,
        signal_class: Some(SignalClass::Verified),
        subject: Some(SUBJECT),
        obs_channel: Some(ObsChannel::Kernel),
        signature: [0; 64],
    };
    ev.sign(&v.key);
    v.next_seq += 1;
    inbox.ingest(v.id, ev.clone(), v.key.verifying_key(), 10, NOW_WALL + 100, 0).unwrap();

    // Poison: sửa subject sau khi ký — crypto rejection đếm riêng.
    let mut poison = ev.clone();
    poison.subject = Some([0x13; 32]);
    assert!(matches!(
        inbox.ingest(v.id, poison, v.key.verifying_key(), 20, NOW_WALL + 100, 0),
        Err(cyberv_agent::mesh::MeshError::EventRejected(_))
    ));
    // Replay: cùng seq nội dung khác — replay đếm riêng.
    let mut replay = ev;
    replay.subject = Some([0x14; 32]);
    replay.origin_seq = 1; // lùi seq
    replay.sign(&v.key);
    assert!(matches!(
        inbox.ingest(v.id, replay, v.key.verifying_key(), 30, NOW_WALL + 100, 0),
        Err(cyberv_agent::mesh::MeshError::ReplayRejected(_))
    ));
    let stats = inbox.stats(&v.id).unwrap();
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.rejected_crypto, 1);
    assert_eq!(stats.rejected_replay, 1);
}

// ====================================================================
// Nhóm 3: Suspect Ranking — format §7.2
// ====================================================================

#[test]
fn test_05_suspect_rank_has_full_provenance_format() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.send_vote(&mut inbox, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 10);
    let e2 = b.send_vote(&mut inbox, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 20);
    let e3 = c.send_vote(&mut inbox, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 30);
    let events = vec![
        (&e1, 1u64),
        (&e2, 2u64),
        (&e3, 3u64),
    ];

    let rank = rank_suspect(SUBJECT, &events, &ledger, 0, |_| false, &QuorumPolicy::default())
        .expect("có event là phải có rank");
    // Format §7.2 — đầy đủ provenance, không phải "92% attacker":
    assert_eq!(rank.subject, SUBJECT);
    assert_eq!(rank.evidence_count, 3);
    assert_eq!(rank.independent_sources, 3);
    assert_eq!(rank.signal_classes.len(), 3);
    assert!(rank.signal_classes.contains(&SignalClass::Verified));
    // Confidence per-mille từ trọng số (3×800 = 2400 → cap 1000).
    assert_eq!(rank.confidence_per_mille, 1000);
    // Trace = event_id chain để audit qua MMR.
    assert_eq!(rank.trace.len(), 3);
    assert!(rank.trace.contains(&e1.event_id));
    // Nguồn chín muồi — không cờ FP nào cả.
    assert!(rank.false_positive_indicators.is_empty());
}

#[test]
fn test_06_rank_flags_cold_start_sources() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut s1 = Voter::new(&mut ledger);
    let mut s2 = Voter::new(&mut ledger);

    let e1 = s1.send_vote(&mut inbox, SUBJECT, [0xA1; 32], SignalClass::Heuristic, ObsChannel::Kernel, 10);
    let e2 = s2.send_vote(&mut inbox, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 20);
    let rank = rank_suspect(
        SUBJECT,
        &[(&e1, 1u64), (&e2, 2u64)],
        &ledger, 0, |_| false, &QuorumPolicy::default(),
    )
    .unwrap();
    // Node mới chưa probe verified — cờ FP phải khai rõ. Hai node channel/
    // root/path khác nhau → ĐÚNG LÀ 2 nguồn độc lập (không flag SingleSource),
    // nhưng weight 150×2 = 300 << 1800 và không phiếu nào verified.
    assert_eq!(rank.independent_sources, 2);
    assert!(rank.false_positive_indicators.contains(&FpIndicator::NoVerifiedSignal));
    assert!(rank.false_positive_indicators.contains(&FpIndicator::ColdStartSources));
    assert!(!rank.false_positive_indicators.contains(&FpIndicator::SingleSource));
    assert!(rank.confidence_per_mille < 1800);
}

#[test]
fn test_07_rank_excludes_revoked_voter() {
    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.send_vote(&mut inbox, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 10);
    let e2 = b.send_vote(&mut inbox, SUBJECT, [0xA2; 32], SignalClass::Verified, ObsChannel::FilesystemAcl, 20);
    let rank = rank_suspect(
        SUBJECT,
        &[(&e1, 1u64), (&e2, 2u64)],
        &ledger,
        0,
        |id| id == &b.id, // b đã bị revoke qua transparency
        &QuorumPolicy::default(),
    )
    .unwrap();
    assert_eq!(rank.independent_sources, 1);
    assert!(rank.false_positive_indicators.contains(&FpIndicator::SingleSource));
}

// ====================================================================
// Nhóm 4: IOC sweep → vote (kết nối UC-2 bước 2)
// ====================================================================

#[test]
fn test_08_ioc_sweep_matches_then_vote_flows_through_pipeline() {
    // Báo cáo của node X chứa 2 indicator; telemetry cục bộ khớp 1 → gợi ý
    // Vote; vote đi qua inbox + rank như mọi đường khác.
    let report_indicators = vec![
        Indicator { kind: IndicatorKind::ProcessPath, value: "C:\\evil\\svc.exe".into() },
        Indicator { kind: IndicatorKind::Signer, value: "CN=Unknown Vendor".into() },
    ];
    let local_telemetry = vec![
        Indicator { kind: IndicatorKind::ProcessPath, value: "C:\\evil\\svc.exe".into() },
    ];
    let matched = sweep_indicators(&report_indicators, &local_telemetry);
    assert_eq!(matched.len(), 1);

    let mut ledger = ReputationLedger::default();
    let mut inbox = GossipInbox::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    // Caller tạo vote với evidence root băm commit của indicator khớp.
    let root = matched[0].commit();
    let e = a.send_vote(&mut inbox, SUBJECT, root, SignalClass::Verified, ObsChannel::FilesystemAcl, 10);
    let rank = rank_suspect(
        SUBJECT,
        &[(&e, 1u64)],
        &ledger, 0, |_| false, &QuorumPolicy::default(),
    )
    .unwrap();
    assert_eq!(rank.evidence_count, 1);
    assert_eq!(rank.trace, vec![e.event_id]);
}
