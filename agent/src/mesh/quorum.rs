//! Quorum Engine — weighted, pairwise-independent, epoch-bounded (NSG-1 + NSG-1.5)
//!
//! Ref: plan v2 §5 — thay "quorum ≥ 2 node" bằng quorum kiểm tra độc lập
//! **theo cặp** (5 điều kiện) rồi **cộng trọng số** TrustScore. Hai vote từ hai
//! node khác nhau chỉ là một nguồn nếu cùng evidence root / cùng kênh quan sát
//! / cùng đường nhận / quan hệ nhân quả. Report đơn lẻ không bao giờ thành
//! hành động; vote stale-epoch và vote từ node bị revoke = 0.

use super::events::{EventKind, NsgEvent, ObsChannel, SignalClass};
use super::graph::NodeId;

/// Ngưỡng mặc định (per-mille tổng trọng số): 2 node "mạnh" (1000 mỗi node)
/// đạt 2000; 1 mạnh + 1 cold-start (250) chỉ đạt 1250 — bị từ chối. Node
/// software-identity (800) cần 3 phiếu (2400) — trung thực về nền tảng P2-1.
pub const DEFAULT_THRESHOLD_WEIGHT: u32 = 1800;
pub const DEFAULT_MIN_VOTES: usize = 2;
/// Bound chống flood (INV-015): chỉ xét N phiếu nặng nhất mỗi lượt đánh giá.
pub const DEFAULT_MAX_BALLOTS: usize = 64;

/// Policy quorum. Giá trị mặc định là placeholder sở khởi — NSG-3 chuyển
/// sang signed policy (kênh INV-011) thì ngưỡng do authority ký.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumPolicy {
    pub threshold_weight: u32,
    pub min_votes: usize,
    pub require_verified: bool,
    pub max_ballots: usize,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            threshold_weight: DEFAULT_THRESHOLD_WEIGHT,
            min_votes: DEFAULT_MIN_VOTES,
            require_verified: true,
            max_ballots: DEFAULT_MAX_BALLOTS,
        }
    }
}

/// Một phiếu bầu đã qua xác thực (chữ ký + event log) và đã gắn trọng số
/// từ ReputationLedger. `arrival_path` do tầng vận chuyển gắn — định danh
/// đường/nhánh network mà phiếu đến (điều kiện 5 chống relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ballot {
    pub event_id: [u8; 32],
    pub origin_id: NodeId,
    pub epoch: u64,
    pub subject: NodeId,
    pub signal_class: SignalClass,
    pub obs_channel: ObsChannel,
    pub evidence_root: [u8; 32],
    pub causal_parents: Vec<[u8; 32]>,
    pub arrival_path: u64,
    pub weight: u32,
}

impl Ballot {
    /// Dựng Ballot từ event. Trả `None` khi provenance không đủ — event không
    /// phải Vote, thiếu subject/evidence_root/obs_channel/signal_class chỉ là
    /// telemetry L0, KHÔNG được feeding quorum (plan §3, INV-009 planned).
    pub fn from_event(event: &NsgEvent, weight: u32, arrival_path: u64) -> Option<Self> {
        if event.kind != EventKind::Vote {
            return None;
        }
        let subject = event.subject?;
        let evidence_root = event.evidence_root?;
        let obs_channel = event.obs_channel?;
        let signal_class = event.signal_class?;
        Some(Self {
            event_id: event.event_id,
            origin_id: event.origin_id,
            epoch: event.epoch,
            subject,
            signal_class,
            obs_channel,
            evidence_root,
            causal_parents: event.causal_parents.clone(),
            arrival_path,
            weight,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReachedReason {
    /// Không phiếu hợp lệ (đều stale/revoke/weight 0/sai subject).
    NoEligibleVotes,
    /// Đề nghị bị từ chối: report đơn lẻ không bao giờ thành hành động.
    InsufficientSources { count: usize, required: usize },
    /// Chỉ có tín hiệu heuristic — không phiếu nào verified.
    NoVerifiedSignal,
    /// Tổng trọng số chưa đạt ngưỡng (sybil/cold-start/decay).
    InsufficientWeight { total: u32, threshold: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumVerdict {
    Reached {
        total_weight: u32,
        /// event_id của các phiếu được tính — audit theo MMR.
        accepted: Vec<[u8; 32]>,
        verified_count: usize,
    },
    NotReached(NotReachedReason),
}

/// Kết quả đánh giá + số phiếu bị cắt vì flood (đếm được, không âm thầm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumOutcome {
    pub verdict: QuorumVerdict,
    pub flood_dropped: usize,
}

/// Độc lập theo cặp — cả 5 điều kiện của plan §5 phải giữ đồng thời:
/// 1. distinct identity (hiển nhiên, KHÔNG đủ);
/// 2. distinct observation channel;
/// 3. distinct evidence root (cùng trích một root = một nguồn);
/// 4. causal separation (vote dẫn xuất từ vote kia, hoặc HAI vote cùng phái
///    sinh từ một report, chỉ là MỘT nguồn);
/// 5. distinct arrival path (một relay không được mang hai phiếu).
pub fn pairwise_independent(a: &Ballot, b: &Ballot) -> bool {
    a.origin_id != b.origin_id
        && a.obs_channel != b.obs_channel
        && a.evidence_root != b.evidence_root
        && !a.causal_parents.contains(&b.event_id)
        && !b.causal_parents.contains(&a.event_id)
        && !a
            .causal_parents
            .iter()
            .any(|p| b.causal_parents.contains(p))
        && a.arrival_path != b.arrival_path
}

/// Tập phiếu ĐỘC LẬP (greedy theo trọng số) cho một subject — dùng chung cho
/// `evaluate_quorum` và correlation ranking (`correlation::rank_suspect`).
/// Lọc: đúng subject, cùng epoch, weight > 0, không revoked; sort deterministic;
/// truncate theo bound chống flood; greedy chấp nhận phiếu nặng nhất trước
/// nếu độc lập với mọi phiếu đã chọn.
pub fn independent_accepted(
    ballots: &[Ballot],
    subject: NodeId,
    current_epoch: u64,
    is_revoked: impl Fn(&NodeId) -> bool,
    max_ballots: usize,
) -> Vec<&Ballot> {
    let mut eligible: Vec<&Ballot> = ballots
        .iter()
        .filter(|b| {
            b.subject == subject
                && b.epoch == current_epoch
                && b.weight > 0
                && !is_revoked(&b.origin_id)
        })
        .collect();

    eligible.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.origin_id.cmp(&b.origin_id))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    eligible.truncate(max_ballots);

    let mut accepted: Vec<&Ballot> = Vec::new();
    for candidate in &eligible {
        if accepted.iter().all(|acc| pairwise_independent(acc, candidate)) {
            accepted.push(candidate);
        }
    }
    accepted
}

/// Đánh giá quorum cho một subject. Chỉ phiếu cùng epoch hiện hành được tính
/// (quá khứ = stale, tương lai = bất hợp lệ — `consistency::vote_epoch_fresh`).
pub fn evaluate_quorum(
    ballots: &[Ballot],
    subject: NodeId,
    current_epoch: u64,
    is_revoked: impl Fn(&NodeId) -> bool,
    policy: &QuorumPolicy,
) -> QuorumOutcome {
    let eligible_count = ballots
        .iter()
        .filter(|b| {
            b.subject == subject
                && b.epoch == current_epoch
                && b.weight > 0
                && !is_revoked(&b.origin_id)
        })
        .count();
    if eligible_count == 0 {
        return QuorumOutcome {
            verdict: QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes),
            flood_dropped: 0,
        };
    }

    // Greedy independence + bound flood — dùng chung với ranking. flood_dropped
    // chỉ đếm phần cắt bởi bound max_ballots; phiếu bị loại vì KHÔNG độc lập
    // là hành vi đúng của engine, không phải flood.
    let accepted =
        independent_accepted(ballots, subject, current_epoch, is_revoked, policy.max_ballots);
    let flood_dropped = eligible_count.saturating_sub(policy.max_ballots);

    let total: u32 = accepted
        .iter()
        .fold(0u32, |acc, b| acc.saturating_add(b.weight));

    // Verdict — kiểm theo thứ tự cố định: đủ nguồn → có verified → đủ weight.
    let verified_count = accepted
        .iter()
        .filter(|b| b.signal_class == SignalClass::Verified)
        .count();
    let verdict = if accepted.len() < policy.min_votes {
        QuorumVerdict::NotReached(NotReachedReason::InsufficientSources {
            count: accepted.len(),
            required: policy.min_votes,
        })
    } else if policy.require_verified && verified_count == 0 {
        QuorumVerdict::NotReached(NotReachedReason::NoVerifiedSignal)
    } else if total < policy.threshold_weight {
        QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight {
            total,
            threshold: policy.threshold_weight,
        })
    } else {
        QuorumVerdict::Reached {
            total_weight: total,
            accepted: accepted.iter().map(|b| b.event_id).collect(),
            verified_count,
        }
    };

    QuorumOutcome { verdict, flood_dropped }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    fn ballot(seed: u8, root: [u8; 32], channel: ObsChannel, path: u64, weight: u32) -> Ballot {
        Ballot {
            event_id: [seed; 32],
            origin_id: nid(seed),
            epoch: 0,
            subject: nid(0xEE),
            signal_class: SignalClass::Verified,
            obs_channel: channel,
            evidence_root: root,
            causal_parents: Vec::new(),
            arrival_path: path,
            weight,
        }
    }

    #[test]
    fn two_independent_verified_votes_reach() {
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let b2 = ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 2, 1000);
        let out = evaluate_quorum(
            &[b1, b2],
            nid(0xEE),
            0,
            |_| false,
            &QuorumPolicy::default(),
        );
        match out.verdict {
            QuorumVerdict::Reached { total_weight, verified_count, .. } => {
                assert_eq!(total_weight, 2000);
                assert_eq!(verified_count, 2);
            }
            other => panic!("phải đạt quorum, got {other:?}"),
        }
        assert_eq!(out.flood_dropped, 0);
    }

    #[test]
    fn shared_evidence_root_counts_once() {
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let b2 = ballot(2, [0xA1; 32], ObsChannel::FilesystemAcl, 2, 1000);
        let out = evaluate_quorum(&[b1, b2], nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(
            out.verdict,
            QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
        );
    }

    #[test]
    fn causal_child_does_not_double_count() {
        let mut b2 = ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 2, 1000);
        b2.causal_parents.push([1u8; 32]); // vote 2 dẫn xuất từ vote 1
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let out = evaluate_quorum(&[b1, b2], nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(
            out.verdict,
            QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
        );
    }

    #[test]
    fn relayed_pair_via_same_path_counts_once() {
        // Hai phiếu đến cùng một đường (một MITM/relay đứng giữa) — chỉ tính một.
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 7, 1000);
        let b2 = ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 7, 1000);
        let out = evaluate_quorum(&[b1, b2], nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(
            out.verdict,
            QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
        );
    }

    #[test]
    fn heuristic_only_never_reaches() {
        let mut b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let mut b2 = ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 2, 1000);
        b1.signal_class = SignalClass::Heuristic;
        b2.signal_class = SignalClass::Heuristic;
        let out = evaluate_quorum(&[b1, b2], nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoVerifiedSignal));
    }

    #[test]
    fn single_report_is_never_an_action() {
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let out = evaluate_quorum(&[b1], nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(
            out.verdict,
            QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
        );
    }

    #[test]
    fn revoked_voter_is_filtered() {
        let b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        let b2 = ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 2, 1000);
        // Revoke MỘT origin: phiếu đó bị lọc, còn lại 1 phiếu — vẫn không đủ.
        let out = evaluate_quorum(
            &[b1.clone(), b2],
            nid(0xEE),
            0,
            |id| *id == nid(2),
            &QuorumPolicy::default(),
        );
        assert_eq!(
            out.verdict,
            QuorumVerdict::NotReached(NotReachedReason::InsufficientSources { count: 1, required: 2 })
        );
        // Revoke CẢ HAI → không còn phiếu hợp lệ nào.
        let out = evaluate_quorum(
            &[b1, ballot(2, [0xA2; 32], ObsChannel::FilesystemAcl, 2, 1000)],
            nid(0xEE),
            0,
            |_| true,
            &QuorumPolicy::default(),
        );
        assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes));
    }

    #[test]
    fn stale_epoch_ballot_is_filtered() {
        let mut b1 = ballot(1, [0xA1; 32], ObsChannel::Kernel, 1, 1000);
        b1.epoch = 5; // quá khứ so với epoch hiện hành 7
        let out = evaluate_quorum(&[b1], nid(0xEE), 7, |_| false, &QuorumPolicy::default());
        assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes));
    }

    #[test]
    fn sybil_farm_alone_cannot_reach() {
        // Farm node mới: weight thật từ ledger là 160 (identity 800 + 4 chiều
        // Unknown → cap 250, S = 160 — xem reputation tests). Tất cả heuristic,
        // channel/path/root đều khác nhau thật → không bị independence chặn,
        // nhưng thiếu verified signal → từ chối.
        let mut ballots = Vec::new();
        for i in 0..6u8 {
            let mut b = ballot(
                10 + i,
                [0xB0 + i; 32],
                match i % 4 {
                    0 => ObsChannel::Kernel,
                    1 => ObsChannel::FilesystemAcl,
                    2 => ObsChannel::NetworkSurface,
                    _ => ObsChannel::Other,
                },
                (i + 1) as u64,
                160,
            );
            b.signal_class = SignalClass::Heuristic;
            ballots.push(b);
        }
        let out = evaluate_quorum(&ballots, nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        assert_eq!(out.verdict, QuorumVerdict::NotReached(NotReachedReason::NoVerifiedSignal));
    }

    #[test]
    fn sybil_farm_corroborating_one_honest_node_still_fails() {
        // Kịch bản sát thực tế nhất: 1 node lành + cả farm phủ Seymour —
        // tổng weight = 1000 + 4×160 (phiếu thứ 5 bị trùng channel) = 1640
        // < 1800 → InsufficientWeight. Cold-start cap là hàng rào định lượng.
        let mut ballots = Vec::new();
        for i in 0..5u8 {
            let mut b = ballot(
                10 + i,
                [0xB0 + i; 32],
                match i % 4 {
                    0 => ObsChannel::Kernel,
                    1 => ObsChannel::FilesystemAcl,
                    2 => ObsChannel::NetworkSurface,
                    _ => ObsChannel::Other,
                },
                (i + 1) as u64,
                160,
            );
            b.signal_class = SignalClass::Heuristic;
            ballots.push(b);
        }
        ballots.push(ballot(1, [0xA1; 32], ObsChannel::Privilege, 99, 1000));
        let out = evaluate_quorum(&ballots, nid(0xEE), 0, |_| false, &QuorumPolicy::default());
        match out.verdict {
            QuorumVerdict::NotReached(NotReachedReason::InsufficientWeight { total, .. }) => {
                assert_eq!(total, 1640, "1000 lành + 4×160 sybil");
            }
            other => panic!("farm + 1 node lành vẫn phải không đủ: {other:?}"),
        }
    }

    #[test]
    fn flood_bound_counts_dropped() {
        let mut ballots = Vec::new();
        for i in 0..20u8 {
            ballots.push(ballot(
                i,
                [0xC0 + i; 32],
                ObsChannel::Other,
                (i + 1) as u64,
                1000,
            ));
        }
        let policy = QuorumPolicy { max_ballots: 8, ..QuorumPolicy::default() };
        let out = evaluate_quorum(&ballots, nid(0xEE), 0, |_| false, &policy);
        assert_eq!(out.flood_dropped, 12);
    }

    #[test]
    fn ballot_from_event_requires_provenance() {
        use crate::identity::keypair::DeviceIdentityKey;
        use crate::identity::rng::OsCryptoRng;
        use crate::mesh::events::NsgEvent;

        let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let origin = key.verifying_key().to_bytes();
        // Heartbeat không phải Vote → None.
        let mut hb = NsgEvent {
            event_id: [0; 32],
            origin_id: origin,
            origin_seq: 1,
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some([0x11; 32]),
            created_wall_ms: 0,
            expiry_wall_ms: 1000,
            kind: EventKind::Heartbeat,
            signal_class: None,
            subject: None,
            obs_channel: None,
            signature: [0; 64],
        };
        hb.sign(&key);
        assert!(Ballot::from_event(&hb, 500, 1).is_none());

        // Vote thiếu evidence_root → None (provenance không đủ).
        let mut vote = NsgEvent {
            kind: EventKind::Vote,
            evidence_root: None,
            subject: Some(nid(0xEE)),
            signal_class: Some(SignalClass::Verified),
            obs_channel: Some(ObsChannel::Kernel),
            ..hb.clone()
        };
        vote.sign(&key);
        assert!(Ballot::from_event(&vote, 500, 1).is_none());

        // Vote đầy đủ → Some.
        vote.evidence_root = Some([0x33; 32]);
        vote.sign(&key);
        assert!(Ballot::from_event(&vote, 500, 1).is_some());
    }
}
