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
//! NSG-1.6 — Epoch + Partition/Merge integration tests
//!
//! Ref: plan v2 §6.2. Kịch bản: partition → DegradedEpoch (marker ký thật) →
//! vote stale-epoch bị loại → merge 3 nhánh (giữ/mâu thuẫn/bị chặn) → hồi phục
//! Steady với epoch không lùi. Graph nhận action từ merge qua đường hợp lệ.

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::mesh::consistency::{
    reconcile_merge, vote_epoch_fresh, BlockReason, ConsistencyPolicy, EpochTracker,
    MergeAction, MergeOutcome, MergeSide, MeshMode, QuarantineRecord,
};
use cyberv_agent::mesh::events::{
    EventKind, EventLog, NsgEvent, ObsChannel, SignalClass,
};
use cyberv_agent::mesh::graph::{MeshGraph, NodeId, NodeState, ISOLATION_TTL_MS};
use cyberv_agent::mesh::quorum::{
    evaluate_quorum, Ballot, NotReachedReason, QuorumPolicy, QuorumVerdict,
};

fn nid(seed: u8) -> NodeId {
    let mut n = [0u8; 32];
    n[0] = seed;
    n
}

fn key_of(seed: u8) -> DeviceIdentityKey {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    DeviceIdentityKey::from_secret_bytes(&cyberv_agent::identity::secret::Secret32::new(seed_bytes))
        .unwrap()
}

fn vote_event(key: &DeviceIdentityKey, seq: u64, subject: NodeId, epoch: u64) -> NsgEvent {
    let mut ev = NsgEvent {
        event_id: [0u8; 32],
        origin_id: key.verifying_key().to_bytes(),
        origin_seq: seq,
        epoch,
        causal_parents: vec![],
        evidence_root: Some([0xA1; 32]),
        created_wall_ms: 1000,
        expiry_wall_ms: 3_600_000,
        kind: EventKind::Vote,
        signal_class: Some(SignalClass::Verified),
        subject: Some(subject),
        obs_channel: Some(ObsChannel::Kernel),
        signature: [0u8; 64],
    };
    ev.sign(key);
    ev
}

// ====================================================================
// Nhóm 1: Partition → DegradedEpoch
// ====================================================================

#[test]
fn test_01_partition_produces_degraded_epoch_with_signed_marker() {
    let mut tracker = EpochTracker::new(ConsistencyPolicy::default());
    for s in 1..=3u8 {
        tracker.on_attested_join(nid(s));
    }
    assert_eq!(tracker.evaluate_mode(), MeshMode::Steady);

    // Mất đa số (2/3).
    for _ in 0..3 {
        tracker.on_missed_heartbeat(&nid(2));
        tracker.on_missed_heartbeat(&nid(3));
    }
    assert_eq!(tracker.evaluate_mode(), MeshMode::Degraded);
    assert_eq!(tracker.epoch, 1);

    // Marker được ký thật + ghi vào log được.
    let key = key_of(1);
    let marker = tracker.build_epoch_marker(&key, 1, 1000, 60_000);
    marker.verify(key.verifying_key()).unwrap();
    assert_eq!(marker.epoch, 1);
    let mut log = EventLog::default();
    log.accept(marker, key.verifying_key(), 2000, 1).unwrap();

    // Membership root bám theo tập còn kết nối — peer khác đối chiếu được.
    let root_1 = tracker.membership_root();
    let mut tracker2 = EpochTracker::new(ConsistencyPolicy::default());
    tracker2.on_attested_join(nid(1));
    assert_ne!(tracker2.membership_root(), root_1);
}

// ====================================================================
// Nhóm 2: Vote stale-epoch bị loại sau partition
// ====================================================================

#[test]
fn test_02_quorum_ignores_stale_epoch_votes_after_partition() {
    // Phiếu tạo ở epoch 0, hệ thống đã ở epoch 1 — không được tính dù nội dung hợp lệ.
    let key = key_of(2);
    let ev = vote_event(&key, 1, nid(0xEE), 0);
    let ballot = Ballot {
        event_id: ev.event_id,
        origin_id: ev.origin_id,
        epoch: ev.epoch,
        subject: nid(0xEE),
        signal_class: SignalClass::Verified,
        obs_channel: ObsChannel::Kernel,
        evidence_root: [0xA1; 32],
        causal_parents: vec![],
        path_class: 1,
        weight: 1000,
    };
    let out = evaluate_quorum(
        &[ballot],
        nid(0xEE),
        1,
        |_| false,
        &QuorumPolicy::default(),
    );
    assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes));
    assert!(!vote_epoch_fresh(0, 1));
    assert!(vote_epoch_fresh(1, 1));
}

// ====================================================================
// Nhóm 3: Merge — 3 nhánh của plan §6.2
// ====================================================================

#[test]
fn test_03_merge_shared_isolation_keeps_min_ttl_and_applies_to_graph() {
    let local = MergeSide {
        epoch: 3,
        attested: vec![nid(1), nid(2)],
        quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 8_000 }],
    };
    let remote = MergeSide {
        epoch: 3,
        attested: vec![nid(1), nid(3)],
        quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 6_000 }],
    };
    match reconcile_merge(&local, &remote, 1_000, &ConsistencyPolicy::default()) {
        MergeOutcome::KeptLocal { epoch, actions } => {
            assert_eq!(epoch, 3);
            assert_eq!(
                actions,
                vec![(nid(9), MergeAction::Keep { until_mono_ms: 6_000, provisional: false })]
            );
        }
        other => panic!("nhánh (a) sai: {other:?}"),
    }
}

#[test]
fn test_04_merge_conflict_downgrades_isolated_node_in_graph() {
    // Local đã isolate X sau quorum; remote attest X. Merge → DowngradeToSuspect,
    // và graph phải nhận được action này qua đường hợp lệ (Isolated → Suspect).
    let mut g = MeshGraph::new();
    g.observe(nid(9), 0).unwrap();
    g.transition(&nid(9), NodeState::Attested).unwrap();
    g.transition(&nid(9), NodeState::Suspect).unwrap();
    g.isolate_with_ttl(&nid(9), 1000, ISOLATION_TTL_MS).unwrap();

    let local = MergeSide {
        epoch: 2,
        attested: vec![nid(1)],
        quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 50_000 }],
    };
    let remote = MergeSide {
        epoch: 2,
        attested: vec![nid(1), nid(9)],
        quarantines: vec![],
    };
    let outcome = reconcile_merge(&local, &remote, 1_000, &ConsistencyPolicy::default());
    match outcome {
        MergeOutcome::KeptLocal { epoch: _, actions } => {
            assert_eq!(actions, vec![(nid(9), MergeAction::DowngradeToSuspect)]);
            // Áp action vào graph — đường Isolated→Suspect phải mở.
            g.transition(&nid(9), NodeState::Suspect).unwrap();
            assert_eq!(g.node(&nid(9)).unwrap().state, NodeState::Suspect);
        }
        other => panic!("nhánh (b) sai: {other:?}"),
    }
}

#[test]
fn test_05_merge_blocks_when_remote_membership_unknown() {
    let local = MergeSide {
        epoch: 2,
        attested: vec![nid(1)],
        quarantines: vec![],
    };
    let remote = MergeSide {
        epoch: 9,
        attested: vec![],
        quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 50_000 }],
    };
    assert_eq!(
        reconcile_merge(&local, &remote, 1_000, &ConsistencyPolicy::default()),
        MergeOutcome::Blocked(BlockReason::MembershipUnknown)
    );
}

#[test]
fn test_06_merge_adopts_higher_epoch_and_keeps_unknown_subject_provisional() {
    let local = MergeSide {
        epoch: 2,
        attested: vec![nid(1)],
        quarantines: vec![],
    };
    let remote = MergeSide {
        epoch: 5,
        attested: vec![nid(1), nid(2)],
        quarantines: vec![QuarantineRecord { subject: nid(8), until_mono_ms: 900_000 }],
    };
    match reconcile_merge(&local, &remote, 1_000, &ConsistencyPolicy::default()) {
        MergeOutcome::AdoptedRemote { epoch, actions } => {
            assert_eq!(epoch, 5);
            // TTL ghim min(900_000, 1_000 + 120_000) = 121_000 — provisional.
            assert_eq!(
                actions,
                vec![(nid(8), MergeAction::Keep { until_mono_ms: 121_000, provisional: true })]
            );
        }
        other => panic!("phải adopt remote epoch cao hơn: {other:?}"),
    }
}

// ====================================================================
// Nhóm 4: Hồi phục + blocked overlay
// ====================================================================

#[test]
fn test_07_reconnect_restores_steady_epoch_never_goes_backwards() {
    let mut tracker = EpochTracker::new(ConsistencyPolicy::default());
    for s in 1..=3u8 {
        tracker.on_attested_join(nid(s));
    }
    for _ in 0..3 {
        tracker.on_missed_heartbeat(&nid(2));
        tracker.on_missed_heartbeat(&nid(3));
    }
    assert_eq!(tracker.evaluate_mode(), MeshMode::Degraded);
    assert_eq!(tracker.epoch, 1);

    // Đội phân mạng ngoài quay lại.
    tracker.on_heartbeat(&nid(2));
    tracker.on_heartbeat(&nid(3));
    assert_eq!(tracker.evaluate_mode(), MeshMode::Steady);
    assert_eq!(tracker.epoch, 1, "epoch không lùi khi hồi phục");
}

#[test]
fn test_08_blocked_overlay_is_independent_from_mode() {
    let mut tracker = EpochTracker::new(ConsistencyPolicy::default());
    tracker.on_attested_join(nid(1));
    assert_eq!(tracker.mode, MeshMode::Steady);
    tracker.blocked = Some(BlockReason::ConflictingReports);
    assert_eq!(tracker.blocked, Some(BlockReason::ConflictingReports));
    // Mode vẫn Steady — blocked là overlay riêng, hiển thị ở GetStatus.
    assert_eq!(tracker.evaluate_mode(), MeshMode::Steady);
    assert_eq!(tracker.blocked, Some(BlockReason::ConflictingReports));
    tracker.blocked = None;
    assert_eq!(tracker.blocked, None);
}
