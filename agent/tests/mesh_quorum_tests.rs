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
//! NSG-1 + NSG-1.5 — Quorum end-to-end: event ký thật → EventLog →
//! ReputationLedger → evaluate_quorum.
//!
//! Ref: plan v2 §4-§5. Đây là suite chứng minh các P0 của phản biện:
//! (1) farm Sybil không tự tạo quorum; (2) hai vote cùng evidence root /
//! nhân quả / đường nhận chỉ tính MỘT nguồn; (3) report sai làm suy yếu
//! người report; (4) node mềm (identity software) cần 3 phiếu — trung thực
//! về nền tảng cho tới P2-1.

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::events::{
    AcceptOutcome, EventKind, EventLog, NsgEvent, ObsChannel, SignalClass,
};
use cyberv_agent::mesh::graph::NodeId;
use cyberv_agent::mesh::quorum::{
    evaluate_quorum, Ballot, NotReachedReason, QuorumPolicy, QuorumVerdict,
};
use cyberv_agent::mesh::reputation::ReputationLedger;

const SUBJECT: NodeId = [0xEE; 32];
const NOW_WALL: u64 = 1_000_000;

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

    fn new_unenrolled() -> Self {
        let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let id = key.verifying_key().to_bytes();
        Self { key, id, next_seq: 1 }
    }

    /// Node "chín muồi" qua ĐÚNG đường public API (không vá hồ sơ trực tiếp):
    /// observation verified, evidence khớp, report được corroboration, lịch sử
    /// heartbeat đều, đủ tuổi + observation để ra khỏi cold-start.
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

    #[allow(clippy::too_many_arguments)] // helper test — mỗi tham số là một trường provenance riêng
    fn vote(
        &mut self,
        log: &mut EventLog,
        subject: NodeId,
        root: [u8; 32],
        class: SignalClass,
        channel: ObsChannel,
        epoch: u64,
        causal: Vec<[u8; 32]>,
    ) -> NsgEvent {
        let mut ev = NsgEvent {
            event_id: [0u8; 32],
            origin_id: self.id,
            origin_seq: self.next_seq,
            epoch,
            causal_parents: causal,
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
        let outcome = log
            .accept(ev.clone(), self.key.verifying_key(), NOW_WALL + 1000, epoch)
            .expect("vote hợp lệ phải được chấp nhận vào log");
        assert_eq!(outcome, AcceptOutcome::Accepted);
        ev
    }

    fn weight(&self, ledger: &ReputationLedger) -> u32 {
        ledger.weight_of(&self.id)
    }
}

/// Dựng ballots từ events + ledger (weight thật) — đường đi chuẩn của NSG-3.
fn ballots_from(
    events: &[NsgEvent],
    ledger: &ReputationLedger,
    paths: &[u64],
) -> Vec<Ballot> {
    events
        .iter()
        .zip(paths.iter())
        .filter_map(|(ev, path)| Ballot::from_event(ev, ledger.weight_of(&ev.origin_id), *path))
        .collect()
}

fn quorum_of(ballots: &[Ballot]) -> QuorumOutcome {
    evaluate_quorum(ballots, SUBJECT, 0, |_| false, &QuorumPolicy::default())
}

use cyberv_agent::mesh::quorum::QuorumOutcome;

// ====================================================================
// Nhóm 1: Quorum đạt đúng điều kiện (happy paths)
// ====================================================================

#[test]
fn test_01_three_matured_software_nodes_reach_quorum() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![]);
    let e3 = c.vote(&mut log, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 0, vec![]);

    // Node software (identity 800) — 2 phiếu chưa đủ, 3 phiếu đủ. Trung thực.
    let two = quorum_of(&ballots_from(&[e1.clone(), e2.clone()], &ledger, &[1, 2]));
    assert!(matches!(
        two.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight { total: 1600, .. })
    ));
    let three = quorum_of(&ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]));
    assert!(matches!(three.verdict, QuorumVerdict::Reached { total_weight: 2400, .. }));
    assert_eq!(a.weight(&ledger), 800);
}

#[test]
fn test_02_heuristic_only_is_rejected_even_with_weight() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Heuristic, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![]);
    let e3 = c.vote(&mut log, SUBJECT, [0xA3; 32], SignalClass::Heuristic, ObsChannel::NetworkSurface, 0, vec![]);
    let out = quorum_of(&ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]));
    assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoVerifiedSignal));
}

// ====================================================================
// Nhóm 2: Independence — nhiều node ≠ nhiều nguồn (P0.1)
// ====================================================================

#[test]
fn test_03_shared_evidence_root_counts_once() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    // Ba node "độc lập" nhưng cùng trích MỘT evidence root (một nguồn thật).
    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![]);
    let e3 = c.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 0, vec![]);
    let out = quorum_of(&ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]));
    assert_eq!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
    );
}

#[test]
fn test_04_causally_derived_vote_does_not_double_count() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    // B và C đều vote DỰA TRÊN report của A (causal_parent = e1) — một nguồn
    // phái sinh, không phải hai nguồn độc lập.
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![e1.event_id]);
    let e3 = c.vote(&mut log, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 0, vec![e1.event_id]);
    let out = quorum_of(&ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]));
    // e2, e3 cùng phái sinh từ e1 → shared causal parent = một nguồn phái sinh.
    // e1 lại bị phụ thuộc trực tiếp với cả hai → chỉ MỘT nguồn được chấp nhận.
    assert_eq!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
    );
}

#[test]
fn test_05_relayed_votes_via_one_path_count_once() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![]);
    // Cả hai phiếu đến qua CÙNG đường (một relay/MITM đứng giữa).
    let out = quorum_of(&ballots_from(&[e1, e2], &ledger, &[7, 7]));
    assert_eq!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
    );
}

// ====================================================================
// Nhóm 3: Sybil + reputation (P0.2)
// ====================================================================

#[test]
fn test_06_fresh_sybil_farm_cannot_reach() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut farm: Vec<Voter> = (0..6).map(|_| Voter::new(&mut ledger)).collect();

    let mut events = Vec::new();
    for (i, voter) in farm.iter_mut().enumerate() {
        let channel = match i % 4 {
            0 => ObsChannel::Kernel,
            1 => ObsChannel::FilesystemAcl,
            2 => ObsChannel::NetworkSurface,
            _ => ObsChannel::Other,
        };
        events.push(voter.vote(
            &mut log, SUBJECT,
            [0xB0 + i as u8; 32],
            SignalClass::Heuristic, // node mới chưa có probe verified
            channel, 0, vec![],
        ));
    }
    let paths: Vec<u64> = (1..=6).collect();
    let out = quorum_of(&ballots_from(&events, &ledger, &paths));
    // 6×150 = 900 < 1800 VÀ không phiếu nào verified.
    assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoVerifiedSignal));
}

#[test]
fn test_07_sybil_farm_cannot_ride_one_honest_node() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut farm: Vec<Voter> = (0..5).map(|_| Voter::new(&mut ledger)).collect();

    let mut events = vec![a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Privilege, 0, vec![])];
    for (i, voter) in farm.iter_mut().enumerate() {
        let channel = match i % 4 {
            0 => ObsChannel::Kernel,
            1 => ObsChannel::FilesystemAcl,
            2 => ObsChannel::NetworkSurface,
            _ => ObsChannel::Other,
        };
        events.push(voter.vote(
            &mut log, SUBJECT,
            [0xC0 + i as u8; 32],
            SignalClass::Heuristic,
            channel, 0, vec![],
        ));
    }
    // Đường nhận: node lành qua path 99, farm qua 5 path khác nhau — independence
    // cho phép tất cả, nhưng cold-start cap 150 giữ tổng tại 800 + 4×150 = 1400.
    let paths = vec![99u64, 1, 2, 3, 4, 5];
    let out = quorum_of(&ballots_from(&events, &ledger, &paths));
    assert!(matches!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight { total: 1400, .. })
    ));
}

#[test]
fn test_08_false_reports_weaken_and_then_silence_the_reporter() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);
    let mut c = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Heuristic, ObsChannel::FilesystemAcl, 0, vec![]);
    let e3 = c.vote(&mut log, SUBJECT, [0xA3; 32], SignalClass::Verified, ObsChannel::NetworkSurface, 0, vec![]);
    assert!(matches!(
        quorum_of(&ballots_from(&[e1.clone(), e2.clone(), e3.clone()], &ledger, &[1, 2, 3])).verdict,
        QuorumVerdict::Reached { .. }
    ));

    // B report sai 1 lần: B 1000→400 → W=400 → tổng 2000 vẫn ≥ 1800
    // (một sai lầm được tha thứ, corroboration của hai node lành còn đủ).
    ledger.record_wrong_action(&b.id, NOW_WALL + 10);
    assert_eq!(b.weight(&ledger), 400);
    let out = quorum_of(&ballots_from(&[e1.clone(), e2.clone(), e3.clone()], &ledger, &[1, 2, 3]));
    assert!(matches!(out.verdict, QuorumVerdict::Reached { total_weight: 2000, .. }));

    // B report sai lần 2: B → 0 → bị loại → 1600 < 1800 → hết quyền FORCE quorum.
    ledger.record_wrong_action(&b.id, NOW_WALL + 20);
    assert_eq!(b.weight(&ledger), 0);
    let out = quorum_of(&ballots_from(&[e1, e2, e3], &ledger, &[1, 2, 3]));
    assert!(matches!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight { total: 1600, .. })
    ));
}

// ====================================================================
// Nhóm 4: Lọc tại ingress + provenance gate
// ====================================================================

#[test]
fn test_09_unenrolled_peer_has_zero_weight_and_no_voice() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut ghost = Voter::new_unenrolled();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);

    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = ghost.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Verified, ObsChannel::FilesystemAcl, 0, vec![]);
    assert_eq!(ledger.weight_of(&ghost.id), 0);
    // weight 0 → bị lọc → chỉ còn 1 phiếu → từ chối.
    let out = quorum_of(&ballots_from(&[e1, e2], &ledger, &[1, 2]));
    assert_eq!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
    );
}

#[test]
fn test_10_stale_epoch_votes_never_count() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let mut b = Voter::new(&mut ledger).mature(&mut ledger);

    // Vote ở epoch 0, hệ thống đã chuyển epoch 1 (partition vừa xảy ra).
    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);
    let e2 = b.vote(&mut log, SUBJECT, [0xA2; 32], SignalClass::Verified, ObsChannel::FilesystemAcl, 0, vec![]);
    let ballots = ballots_from(&[e1, e2], &ledger, &[1, 2]);
    let out = evaluate_quorum(&ballots, SUBJECT, 1, |_| false, &QuorumPolicy::default());
    assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes));
}

#[test]
fn test_11_tampered_vote_rejected_at_ingress() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let a = Voter::new(&mut ledger);
    let mut ev = NsgEvent {
        event_id: [0u8; 32],
        origin_id: a.id,
        origin_seq: 1,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: Some([0xA1; 32]),
        created_wall_ms: NOW_WALL,
        expiry_wall_ms: NOW_WALL + 3_600_000,
        kind: EventKind::Vote,
        signal_class: Some(SignalClass::Verified),
        subject: Some(SUBJECT),
        obs_channel: Some(ObsChannel::Kernel),
        signature: [0u8; 64],
    };
    ev.sign(&a.key);
    // Kẻ xấu sửa subject sau khi ký — ingress phải từ chối.
    ev.subject = Some([0x12; 32]);
    let err = log
        .accept(ev, a.key.verifying_key(), NOW_WALL + 1000, 0)
        .unwrap_err();
    assert!(matches!(err, cyberv_agent::mesh::MeshError::EventRejected(_)));
}

#[test]
fn test_12_vote_without_evidence_never_enters_quorum() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let a = Voter::new(&mut ledger).mature(&mut ledger);
    // Vote KHÔNG có evidence_root — chỉ là telemetry L0.
    let mut ev = NsgEvent {
        event_id: [0u8; 32],
        origin_id: a.id,
        origin_seq: 1,
        epoch: 0,
        causal_parents: vec![],
        evidence_root: None,
        created_wall_ms: NOW_WALL,
        expiry_wall_ms: NOW_WALL + 3_600_000,
        kind: EventKind::Vote,
        signal_class: Some(SignalClass::Verified),
        subject: Some(SUBJECT),
        obs_channel: Some(ObsChannel::Kernel),
        signature: [0u8; 64],
    };
    ev.sign(&a.key);
    log.accept(ev.clone(), a.key.verifying_key(), NOW_WALL + 1000, 0).unwrap();
    assert!(Ballot::from_event(&ev, a.weight(&ledger), 1).is_none());
}

#[test]
fn test_13_duplicate_vote_is_idempotent_not_double_counted() {
    let mut ledger = ReputationLedger::default();
    let mut log = EventLog::default();
    let mut a = Voter::new(&mut ledger).mature(&mut ledger);
    let e1 = a.vote(&mut log, SUBJECT, [0xA1; 32], SignalClass::Verified, ObsChannel::Kernel, 0, vec![]);

    // Kẻ xấu replay ĐÚNG event — log trả Duplicate, không nhân bản.
    let outcome = log
        .accept(e1.clone(), a.key.verifying_key(), NOW_WALL + 2000, 0)
        .unwrap();
    assert_eq!(outcome, AcceptOutcome::Duplicate);

    // Hai bản sao cùng event_id → cùng một ballot → quorum vẫn tính MỘT phiếu.
    let mut ballots = vec![Ballot::from_event(&e1, ledger.weight_of(&a.id), 1).unwrap()];
    ballots.push(Ballot::from_event(&e1, ledger.weight_of(&a.id), 1).unwrap());
    let out = quorum_of(&ballots);
    assert_eq!(
        out.verdict,
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
    );
}
