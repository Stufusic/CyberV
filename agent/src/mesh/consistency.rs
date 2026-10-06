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
//! Epoch + Partition/Merge Consistency (NSG-1.6)
//!
//! Ref: plan v2 §6.2 — phát hiện partition qua mất đa số neighbor đã attest,
//! vào `DegradedEpoch` (epoch +1, phát EpochMarker có chữ ký kèm membership
//! root), peer-quarantine lúc đó chỉ được **provisional** (TTL ghim ngắn).
//! Khi hội tụ: epoch cao thắng; quarantine mâu thuẫn → Suspect (safety over
//! liveness — không auto-trust, không auto-isolate); vote stale-epoch bị loại.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha512};

use crate::identity::keypair::DeviceIdentityKey;

use super::events::{EventKind, NsgEvent, SignalClass};
use super::graph::NodeId;

/// Miền băm membership root — chống va chạm với các domain khác.
pub const DOMAIN_MESH_MEMBERSHIP: &[u8] = b"CYBERV/MESH/MEMBERSHIP/v1";

/// Số lần miss liên tiếp trước khi một attested-neighbor bị coi là mất.
pub const DEFAULT_LOST_HEARTBEAT_THRESHOLD: u32 = 3;
/// TTL ghim cho quarantine provisional trong DegradedEpoch (ngắn hơn TTL
/// thường — mọi quyết định thiếu thông tin phải có đường thoát nhanh).
pub const DEFAULT_PROVISIONAL_TTL_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyPolicy {
    pub lost_heartbeat_threshold: u32,
    pub provisional_ttl_ms: u64,
}

impl Default for ConsistencyPolicy {
    fn default() -> Self {
        Self {
            lost_heartbeat_threshold: DEFAULT_LOST_HEARTBEAT_THRESHOLD,
            provisional_ttl_ms: DEFAULT_PROVISIONAL_TTL_MS,
        }
    }
}

/// Chế độ vận hành mesh cục bộ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshMode {
    Steady,
    Degraded,
}

/// Lý do mesh tạm bị chặn hành động peer-action (overlay hiển thị ở GetStatus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Hai report mâu thuẫn không phân giải được (plan §6.1).
    ConflictingReports,
    /// Merge chưa hoàn tất đối chiếu.
    MergeIncomplete,
    /// Membership view của bên kia không xác minh được.
    MembershipUnknown,
}

/// Theo dõi epoch + membership view cục bộ. Thuần dữ liệu + hash — không I/O.
#[derive(Debug)]
pub struct EpochTracker {
    pub epoch: u64,
    pub mode: MeshMode,
    pub blocked: Option<BlockReason>,
    policy: ConsistencyPolicy,
    attested: HashSet<NodeId>,
    missed: HashMap<NodeId, u32>,
}

impl EpochTracker {
    pub fn new(policy: ConsistencyPolicy) -> Self {
        Self {
            epoch: 0,
            mode: MeshMode::Steady,
            blocked: None,
            policy,
            attested: HashSet::new(),
            missed: HashMap::new(),
        }
    }

    pub fn policy(&self) -> &ConsistencyPolicy {
        &self.policy
    }

    /// Node attest xong — vào membership view.
    pub fn on_attested_join(&mut self, id: NodeId) {
        self.attested.insert(id);
        self.missed.remove(&id);
    }

    /// Node rời view (stale GC / recovery remove) — không còn tính vào majority.
    pub fn on_departure(&mut self, id: &NodeId) {
        self.attested.remove(id);
        self.missed.remove(id);
    }

    pub fn on_heartbeat(&mut self, id: &NodeId) {
        self.missed.remove(id);
    }

    pub fn on_missed_heartbeat(&mut self, id: &NodeId) {
        let count = self.missed.entry(*id).or_insert(0);
        *count = count.saturating_add(1);
        // Quá ngưỡng thì giữ nguyên count — node "mất" vẫn mất, không lật kèo
        // theo nhiễu (một heartbeat đơn lẻ khôi phục, như on_heartbeat).
    }

    /// Số neighbor đã attest hiện còn kết nối (không vượt ngưỡng miss).
    pub fn connected_attested(&self) -> usize {
        self.attested
            .iter()
            .filter(|id| {
                self.missed
                    .get(*id)
                    .is_none_or(|c| *c < self.policy.lost_heartbeat_threshold)
            })
            .count()
    }

    /// Đánh giá lại mode. Vào Degraded lần đầu → **epoch +1** (mỗi lần vào
    /// degraded là một epoch mới); hồi phục → Steady, epoch giữ nguyên (việc
    /// tăng epoch khi hội tụ thuộc merge protocol, không thuộc local view).
    pub fn evaluate_mode(&mut self) -> MeshMode {
        let total = self.attested.len();
        let connected = self.connected_attested();
        let majority_lost = total >= 2 && connected * 2 < total;
        match (majority_lost, self.mode) {
            (true, MeshMode::Steady) => {
                self.mode = MeshMode::Degraded;
                self.epoch = self.epoch.saturating_add(1);
            }
            (false, _) => self.mode = MeshMode::Steady,
            (true, MeshMode::Degraded) => {}
        }
        self.mode
    }

    /// Membership root = hash domain-separate của tập node đã attest (sorted).
    pub fn membership_root(&self) -> [u8; 32] {
        let mut ids: Vec<&NodeId> = self.attested.iter().collect();
        ids.sort();
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_MESH_MEMBERSHIP);
        hasher.update([0x00]);
        hasher.update((ids.len() as u32).to_be_bytes());
        for id in ids {
            hasher.update(id);
        }
        let out = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&out[..32]);
        root
    }

    /// Dựng + ký EpochMarker cho epoch hiện hành (consistency không giữ key —
    /// caller truyền khóa, marker ký bằng identity key của node cục bộ).
    pub fn build_epoch_marker(
        &self,
        key: &DeviceIdentityKey,
        origin_seq: u64,
        now_wall_ms: u64,
        expiry_wall_ms: u64,
    ) -> NsgEvent {
        let mut event = NsgEvent {
            event_id: [0u8; 32],
            origin_id: key.verifying_key().to_bytes(),
            origin_seq,
            epoch: self.epoch,
            causal_parents: Vec::new(),
            evidence_root: None,
            created_wall_ms: now_wall_ms,
            expiry_wall_ms,
            kind: EventKind::EpochMarker,
            signal_class: Some(SignalClass::Verified),
            subject: None,
            obs_channel: None,
            signature: [0u8; 64],
        };
        event.sign(key);
        event
    }
}

/// Vote chỉ đếm khi **đúng** epoch hiện hành: quá khứ = stale, tương lai =
/// bất hợp lệ. Không có nhánh "gần đúng cũng được".
pub fn vote_epoch_fresh(event_epoch: u64, current_epoch: u64) -> bool {
    event_epoch == current_epoch
}

/// Bản ghi cách ly một phía cần đối chiếu khi merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRecord {
    pub subject: NodeId,
    pub until_mono_ms: u64,
}

/// Một "phía" của cuộc merge (membership + quarantine đã ký của phía đó).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSide {
    pub epoch: u64,
    pub attested: Vec<NodeId>,
    pub quarantines: Vec<QuarantineRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAction {
    /// Giữ cách ly. `provisional = true` khi chỉ một phía có thông tin —
    /// TTL đã được ghim về `provisional_ttl_ms` nếu dài hơn.
    Keep { until_mono_ms: u64, provisional: bool },
    /// Mâu thuẫn (một phía isolate, phía kia attest) → về Suspect, chạy lại
    /// corroboration với dữ liệu hợp nhất (plan §6.2 nhánh b).
    DowngradeToSuspect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Nhận epoch phía kia (cao hơn) làm epoch hiện hành.
    AdoptedRemote { epoch: u64, actions: Vec<(NodeId, MergeAction)> },
    /// Giữ epoch cục bộ (bằng hoặc cao hơn).
    KeptLocal { epoch: u64, actions: Vec<(NodeId, MergeAction)> },
    /// View bên kia không xác minh được → QuorumUnavailable (nhánh c).
    Blocked(BlockReason),
}

/// Đối chiếu hai membership view sau partition. Pure function — deterministic
/// (subject xử lý theo thứ tự sorted), không I/O.
pub fn reconcile_merge(
    local: &MergeSide,
    remote: &MergeSide,
    now_mono_ms: u64,
    policy: &ConsistencyPolicy,
) -> MergeOutcome {
    // Nhánh c: bên kia không công bố membership nào mà lại có quarantine —
    // không có gì để đối chiếu, không tin mù (plan §2.4).
    if remote.attested.is_empty() && !remote.quarantines.is_empty() {
        return MergeOutcome::Blocked(BlockReason::MembershipUnknown);
    }

    let (epoch, adopted) = if remote.epoch > local.epoch {
        (remote.epoch, true)
    } else {
        (local.epoch, false)
    };

    // Hợp tập subject (sorted → deterministic).
    let mut subjects: Vec<NodeId> = Vec::new();
    for record in local.quarantines.iter().chain(remote.quarantines.iter()) {
        if !subjects.contains(&record.subject) {
            subjects.push(record.subject);
        }
    }
    subjects.sort_unstable();

    let mut actions: Vec<(NodeId, MergeAction)> = Vec::new();
    for subject in subjects {
        let local_record = local.quarantines.iter().find(|q| q.subject == subject);
        let remote_record = remote.quarantines.iter().find(|q| q.subject == subject);
        match (local_record, remote_record) {
            (Some(l), Some(r)) => {
                // (a) Hai phía cùng isolate → giữ, TTL = min còn lại.
                let until = l.until_mono_ms.min(r.until_mono_ms);
                if until > now_mono_ms {
                    actions.push((subject, MergeAction::Keep { until_mono_ms: until, provisional: false }));
                }
                // TTL đã hết ở merge → bỏ (GC sẽ lift; không tái cách ly).
            }
            (Some(l), None) => {
                if remote.attested.contains(&subject) {
                    // (b) Mâu thuẫn: một phía isolate, phía kia attest.
                    actions.push((subject, MergeAction::DowngradeToSuspect));
                } else {
                    // Phía kia không biết gì → giữ provisional, TTL ghim ngắn.
                    let until = l
                        .until_mono_ms
                        .min(now_mono_ms.saturating_add(policy.provisional_ttl_ms));
                    if until > now_mono_ms {
                        actions.push((subject, MergeAction::Keep { until_mono_ms: until, provisional: true }));
                    }
                }
            }
            (None, Some(r)) => {
                if local.attested.contains(&subject) {
                    actions.push((subject, MergeAction::DowngradeToSuspect));
                } else {
                    let until = r
                        .until_mono_ms
                        .min(now_mono_ms.saturating_add(policy.provisional_ttl_ms));
                    if until > now_mono_ms {
                        actions.push((subject, MergeAction::Keep { until_mono_ms: until, provisional: true }));
                    }
                }
            }
            // Subject đến từ hợp tập hai phía nên (None, None) không thể xảy
            // ra — vẫn `continue` phòng thủ thay vì panic (quy tắc dự án).
            (None, None) => continue,
        }
    }

    if adopted {
        MergeOutcome::AdoptedRemote { epoch, actions }
    } else {
        MergeOutcome::KeptLocal { epoch, actions }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    fn tracker_with_three() -> EpochTracker {
        let mut t = EpochTracker::new(ConsistencyPolicy::default());
        t.on_attested_join(nid(1));
        t.on_attested_join(nid(2));
        t.on_attested_join(nid(3));
        t
    }

    #[test]
    fn majority_loss_triggers_degraded_epoch() {
        let mut t = tracker_with_three();
        assert_eq!(t.evaluate_mode(), MeshMode::Steady);
        assert_eq!(t.epoch, 0);

        // Mất 2/3 — mỗi node miss 3 lần.
        for _ in 0..3 {
            t.on_missed_heartbeat(&nid(2));
            t.on_missed_heartbeat(&nid(3));
        }
        assert_eq!(t.connected_attested(), 1);
        assert_eq!(t.evaluate_mode(), MeshMode::Degraded);
        assert_eq!(t.epoch, 1);
        // Vẫn degraded — không tăng epoch thêm.
        assert_eq!(t.evaluate_mode(), MeshMode::Degraded);
        assert_eq!(t.epoch, 1);
    }

    #[test]
    fn minority_loss_stays_steady() {
        let mut t = tracker_with_three();
        for _ in 0..3 {
            t.on_missed_heartbeat(&nid(1));
        }
        // 2/3 còn kết nối — đa số còn.
        assert_eq!(t.evaluate_mode(), MeshMode::Steady);
        assert_eq!(t.epoch, 0);
    }

    #[test]
    fn recovery_to_steady_keeps_epoch() {
        let mut t = tracker_with_three();
        for _ in 0..3 {
            t.on_missed_heartbeat(&nid(2));
            t.on_missed_heartbeat(&nid(3));
        }
        t.evaluate_mode();
        assert_eq!(t.mode, MeshMode::Degraded);
        assert_eq!(t.epoch, 1);

        // Một heartbeat đơn lẻ là đủ khôi phục kết nối (nhiễu không lật kèo,
        // nhưng heartbeat thật phải được tin).
        t.on_heartbeat(&nid(2));
        t.on_heartbeat(&nid(3));
        assert_eq!(t.evaluate_mode(), MeshMode::Steady);
        assert_eq!(t.epoch, 1); // epoch không lùi
    }

    #[test]
    fn marker_is_signed_and_binds_membership() {
        use crate::identity::keypair::DeviceIdentityKey;
        use crate::identity::rng::OsCryptoRng;

        let key = DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap();
        let t = tracker_with_three();
        let marker = t.build_epoch_marker(&key, 42, 1000, 60_000);
        marker.verify(key.verifying_key()).unwrap();
        assert_eq!(marker.epoch, t.epoch);
        assert_eq!(marker.kind, EventKind::EpochMarker);
        assert_eq!(marker.origin_seq, 42);

        // Membership root ổn định theo tập (sorted) — thêm node thì đổi root.
        let root_before = t.membership_root();
        let mut t2 = tracker_with_three();
        t2.on_attested_join(nid(9));
        assert_ne!(t2.membership_root(), root_before);
    }

    #[test]
    fn merge_keeps_shared_isolation_with_min_ttl() {
        let local = MergeSide {
            epoch: 3,
            attested: vec![nid(1), nid(2)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 5_000 }],
        };
        let remote = MergeSide {
            epoch: 3,
            attested: vec![nid(1), nid(3)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 9_000 }],
        };
        let policy = ConsistencyPolicy::default();
        match reconcile_merge(&local, &remote, 1_000, &policy) {
            MergeOutcome::KeptLocal { epoch, actions } => {
                assert_eq!(epoch, 3);
                assert_eq!(
                    actions,
                    vec![(nid(9), MergeAction::Keep { until_mono_ms: 5_000, provisional: false })]
                );
            }
            other => panic!("nhánh (a) sai: {other:?}"),
        }
    }

    #[test]
    fn merge_conflict_downgrades_to_suspect() {
        // Local isolate X, remote attest X → DowngradeToSuspect (không auto-trust).
        let local = MergeSide {
            epoch: 3,
            attested: vec![nid(1)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 50_000 }],
        };
        let remote = MergeSide {
            epoch: 3,
            attested: vec![nid(1), nid(9)],
            quarantines: vec![],
        };
        let policy = ConsistencyPolicy::default();
        match reconcile_merge(&local, &remote, 1_000, &policy) {
            MergeOutcome::KeptLocal { epoch, actions } => {
                assert_eq!(epoch, 3);
                assert_eq!(actions, vec![(nid(9), MergeAction::DowngradeToSuspect)]);
            }
            other => panic!("nhánh (b) sai: {other:?}"),
        }
    }

    #[test]
    fn merge_one_sided_keep_is_provisional_with_pinned_ttl() {
        // Remote không biết gì về X → giữ provisional, TTL ghim ngắn hơn.
        let local = MergeSide {
            epoch: 2,
            attested: vec![nid(1)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 900_000 }],
        };
        let remote = MergeSide {
            epoch: 2,
            attested: vec![nid(1)],
            quarantines: vec![],
        };
        let policy = ConsistencyPolicy::default();
        match reconcile_merge(&local, &remote, 1_000, &policy) {
            MergeOutcome::KeptLocal { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![(nid(9), MergeAction::Keep { until_mono_ms: 121_000, provisional: true })]
                );
            }
            other => panic!("nhánh provisional sai: {other:?}"),
        }
    }

    #[test]
    fn merge_blocks_when_remote_membership_unknown() {
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
        let policy = ConsistencyPolicy::default();
        assert_eq!(
            reconcile_merge(&local, &remote, 1_000, &policy),
            MergeOutcome::Blocked(BlockReason::MembershipUnknown)
        );
    }

    #[test]
    fn merge_adopts_higher_epoch() {
        let local = MergeSide {
            epoch: 2,
            attested: vec![nid(1)],
            quarantines: vec![],
        };
        let remote = MergeSide {
            epoch: 5,
            attested: vec![nid(1), nid(2)],
            quarantines: vec![QuarantineRecord { subject: nid(8), until_mono_ms: 50_000 }],
        };
        let policy = ConsistencyPolicy::default();
        match reconcile_merge(&local, &remote, 1_000, &policy) {
            MergeOutcome::AdoptedRemote { epoch, actions } => {
                assert_eq!(epoch, 5);
                // Local không attest 8 và không isolate 8 → provisional keep.
                // TTL ghim = min(record 50_000, now 1_000 + provisional 120_000
                // = 121_000) = 50_000 — ghim chỉ rút NGẮN, không kéo dài.
                assert_eq!(
                    actions,
                    vec![(nid(8), MergeAction::Keep { until_mono_ms: 50_000, provisional: true })]
                );
            }
            other => panic!("phải adopt remote: {other:?}"),
        }
    }

    #[test]
    fn expired_isolation_is_dropped_at_merge() {
        let local = MergeSide {
            epoch: 1,
            attested: vec![nid(1)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 500 }],
        };
        let remote = MergeSide {
            epoch: 1,
            attested: vec![nid(1)],
            quarantines: vec![QuarantineRecord { subject: nid(9), until_mono_ms: 500 }],
        };
        let policy = ConsistencyPolicy::default();
        match reconcile_merge(&local, &remote, 1_000, &policy) {
            MergeOutcome::KeptLocal { actions, .. } => assert!(actions.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn vote_freshness_requires_exact_epoch() {
        assert!(vote_epoch_fresh(5, 5));
        assert!(!vote_epoch_fresh(4, 5)); // quá khứ = stale
        assert!(!vote_epoch_fresh(6, 5)); // tương lai = bất hợp lệ
    }

    #[test]
    fn blocked_overlay_is_visible() {
        let mut t = tracker_with_three();
        t.blocked = Some(BlockReason::ConflictingReports);
        assert_eq!(t.blocked, Some(BlockReason::ConflictingReports));
        t.blocked = None;
        assert_eq!(t.blocked, None);
    }
}
