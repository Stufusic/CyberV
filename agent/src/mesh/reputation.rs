//! TrustScore 5 chiều + Reputation Ledger (NSG-1.5)
//!
//! Ref: plan v2 §4 — Identity / Observation / Evidence / Behavior / History,
//! kết hợp fail-closed kiểu **min-cap**: chiều nào Unknown → trần trọng số bị
//! ghim thấp; cold-start node bị ghim thấp hơn nữa (chống Sybil bằng kinh tế
//! học, không chỉ mitigation mô tả). Toàn bộ số học là **per-mille nguyên**
//! (0..=1000) với saturating — không float, không trần.
//!
//! Trung thực (INV-007): `on_observation(probe_verified=false)` **không** tạo
//! điểm Observation — probe chưa chứng minh được gì thì node vẫn Unknown ở
//! chiều đó, weight tự động thấp. Honest-state vào thẳng công thức quorum.

use std::collections::HashMap;

use super::graph::NodeId;

/// Thang đo per-mille: mọi weight/điểm nằm trong 0..=1000.
pub const WEIGHT_SCALE: u32 = 1000;

/// Chỉ số chiều trong mảng `dims`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDim {
    Identity = 0,
    Observation = 1,
    Evidence = 2,
    Behavior = 3,
    History = 4,
}

/// Policy reputation. **Giá trị mặc định là placeholder sở khởi** — khi NSG-3
/// chuyển sang signed policy (kênh INV-011) các giá trị này do authority ký.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationPolicy {
    /// Trần weight khi tồn tại chiều chưa đo được (Unknown).
    pub cap_unknown: u16,
    /// Trần weight cho node cold-start (chưa đủ tuổi + observation sạch).
    pub cold_start_cap: u16,
    /// Trọng số mỗi chiều khi tính tổng S (per-mille, tổng phải = 1000).
    pub dim_weights: [u32; 5],
    /// Mỗi wrong-action (report dẫn tới wrong-action) trừ Behavior bao nhiêu.
    pub decay_step: u16,
    /// Mỗi report được corroboration đúng cộng lại bao nhiêu.
    pub restore_step: u16,
    /// Phải sạch wrong-action tối thiểu khoảng này (wall ms) mới được restore.
    pub restore_cooldown_ms: u64,
    /// Cold-start_clears: tuổi tối thiểu (ngày).
    pub cold_start_days: u64,
    /// Cold-start_clears: số observation tối thiểu.
    pub cold_start_min_observations: u64,
    /// Identity dim khi attest lần đầu — 800 = identity software-anchored
    /// (DPAPI + Ed25519). Khi P2-1 neo TPM thật mới được nâng về 1000.
    pub new_identity_dim: u16,
}

impl Default for ReputationPolicy {
    fn default() -> Self {
        Self {
            cap_unknown: 250,
            // Cold-start cap 150: 4 node mới (4×150 = 600) + 1 node lành mạnh
            // (1000) = 1600 < ngưỡng 1800 — farm Sybil không thể "chở" một
            // node lành vượt ngưỡng, cũng không tự tạo quorum (thiếu verified).
            cold_start_cap: 150,
            // Tổng đúng 1000 — được kiểm bởi test bất biến bên dưới.
            dim_weights: [200, 200, 250, 200, 150],
            decay_step: 600,
            restore_step: 100,
            restore_cooldown_ms: 3_600_000, // 1 giờ
            cold_start_days: 14,
            cold_start_min_observations: 50,
            new_identity_dim: 800,
        }
    }
}

/// Baseline Behavior/History khi attest lần đầu — **trung lập**, không phải
/// Unknown: danh tính đã được chứng minh bằng mật mã nên giả định vô tội với
/// trọng số hạn chế là hợp lý; wrong-action sẽ kéo xuống mức 0 ngay lập tức
/// (decay 600 > baseline 500). Observation/Evidence vẫn là Unknown tới khi có
/// dữ liệu thật (INV-007 — không điểm ảo).
pub const BEHAVIOR_BASELINE: u16 = 500;
pub const HISTORY_BASELINE: u16 = 500;

/// Điểm tin cậy một peer: mỗi chiều `None` = chưa đo được (Unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustScore {
    pub dims: [Option<u16>; 5],
}

impl TrustScore {
    /// Dựng từ mảng đã biết (nạp trạng thái lưu / test). Không tự kiểm —
    /// giá trị ngoài 0..=1000 bị kẹp khi tính weight.
    pub fn from_dims(dims: [Option<u16>; 5]) -> Self {
        Self { dims }
    }
}

/// Hồ sơ reputation một peer.
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub trust: TrustScore,
    pub cold_start: bool,
    enrolled_wall_ms: u64,
    observations: u64,
    wrong_actions: u64,
    corroborated: u64,
    last_wrong_wall_ms: Option<u64>,
}

/// Ledger reputation toàn mesh (cục bộ mỗi node).
#[derive(Debug)]
pub struct ReputationLedger {
    peers: HashMap<NodeId, PeerReputation>,
    policy: ReputationPolicy,
}

impl Default for ReputationLedger {
    fn default() -> Self {
        Self::with_policy(ReputationPolicy::default())
    }
}

impl ReputationLedger {
    pub fn with_policy(policy: ReputationPolicy) -> Self {
        Self { peers: HashMap::new(), policy }
    }

    pub fn policy(&self) -> &ReputationPolicy {
        &self.policy
    }

    pub fn peer(&self, id: &NodeId) -> Option<&PeerReputation> {
        self.peers.get(id)
    }

    /// Node attest thành công — mở hồ sơ. Node **đã có hồ sơ** attest lại
    /// (sau recovery) GIỮ nguyên lịch sử: recovery không reset reputation.
    pub fn on_attested(&mut self, id: NodeId, now_wall_ms: u64) {
        let policy = &self.policy;
        self.peers.entry(id).or_insert_with(|| PeerReputation {
            trust: TrustScore {
                dims: [
                    Some(policy.new_identity_dim),
                    None,                        // Observation — chờ probe verified
                    None,                        // Evidence — chờ kiểm chéo
                    Some(BEHAVIOR_BASELINE),
                    Some(HISTORY_BASELINE),
                ],
            },
            cold_start: true,
            enrolled_wall_ms: now_wall_ms,
            observations: 0,
            wrong_actions: 0,
            corroborated: 0,
            last_wrong_wall_ms: None,
        });
    }

    /// Ghi nhận một observation từ node (dữ liệu node tự phát). Chỉ probe
    /// **verified** mới mở/chốt điểm Observation — trung thực INV-007.
    pub fn on_observation(&mut self, id: &NodeId, probe_verified: bool) {
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.observations = peer.observations.saturating_add(1);
        if !probe_verified {
            return; // không đo được → giữ None (Unknown) → cap thấp tự động
        }
        peer.trust.dims[TrustDim::Observation as usize] = match peer.trust.dims[TrustDim::Observation as usize] {
            None => Some(700),
            Some(v) => Some(v.saturating_add(5).min(WEIGHT_SCALE as u16)),
        };
    }

    /// Evidence của node được kiểm chéo khớp merkle root.
    pub fn on_evidence_verified(&mut self, id: &NodeId) {
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.trust.dims[TrustDim::Evidence as usize] = match peer.trust.dims[TrustDim::Evidence as usize] {
            None => Some(700),
            Some(v) => Some(v.saturating_add(5).min(WEIGHT_SCALE as u16)),
        };
    }

    /// Evidence của node sai / không khớp khi kiểm chéo — trừ trực tiếp.
    pub fn on_evidence_bogus(&mut self, id: &NodeId) {
        let step = self.policy.decay_step;
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.trust.dims[TrustDim::Evidence as usize] = peer.trust.dims[TrustDim::Evidence as usize]
            .map(|v| v.saturating_sub(step));
    }

    /// Report/vote của node dẫn tới wrong-action (đo qua shadow ledger) —
    /// phạt Behavior. Số phạt 1 bước đủ để node hết sức bỏ phiếu (fail-closed:
    /// report sai là failure nguy hiểm nhất của mesh).
    pub fn record_wrong_action(&mut self, id: &NodeId, now_wall_ms: u64) {
        let step = self.policy.decay_step;
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.wrong_actions = peer.wrong_actions.saturating_add(1);
        peer.last_wrong_wall_ms = Some(now_wall_ms);
        // Behavior chưa từng đo được (Unknown) vẫn phải bị phạt: coi như xuất
        // phát điểm 1000 rồi trừ — wrong-action là bằng chứng, không được lãng quên.
        let base = peer.trust.dims[TrustDim::Behavior as usize]
            .unwrap_or(WEIGHT_SCALE as u16);
        peer.trust.dims[TrustDim::Behavior as usize] = Some(base.saturating_sub(step));
    }

    /// Report của node được corroboration xác nhận đúng. Chỉ restore khi đã
    /// sạch wrong-action quá cooldown (plan §4: phục hồi qua chu kỳ benign
    /// sạch quan sát được — không reset thủ công).
    pub fn record_corroborated(&mut self, id: &NodeId, now_wall_ms: u64) {
        let (step, cooldown) = (self.policy.restore_step, self.policy.restore_cooldown_ms);
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.corroborated = peer.corroborated.saturating_add(1);
        let in_cooldown = peer
            .last_wrong_wall_ms
            .is_some_and(|t| now_wall_ms.saturating_sub(t) < cooldown);
        if in_cooldown {
            return;
        }
        peer.trust.dims[TrustDim::Behavior as usize] = peer.trust.dims[TrustDim::Behavior as usize]
            .map(|v| v.saturating_add(step).min(WEIGHT_SCALE as u16));
    }

    /// Heartbeat/vote nhất quán → History tăng chậm (trần 1000).
    pub fn record_consistent(&mut self, id: &NodeId) {
        let Some(peer) = self.peers.get_mut(id) else { return };
        peer.trust.dims[TrustDim::History as usize] = peer.trust.dims[TrustDim::History as usize]
            .map(|v| v.saturating_add(2).min(WEIGHT_SCALE as u16));
    }

    /// Đánh giá lại cold-start. Cần đồng thời: tuổi đủ, observation đủ,
    /// và KHÔNG có wrong-action nào từ trước tới nay.
    pub fn refresh_cold_start(&mut self, id: &NodeId, now_wall_ms: u64) {
        let policy = self.policy.clone();
        let Some(peer) = self.peers.get_mut(id) else { return };
        let age_days = now_wall_ms.saturating_sub(peer.enrolled_wall_ms) / 86_400_000;
        if age_days >= policy.cold_start_days
            && peer.observations >= policy.cold_start_min_observations
            && peer.wrong_actions == 0
        {
            peer.cold_start = false;
        }
    }

    /// Trọng số vote của peer (per-mille). Fail-closed:
    /// - peer chưa có hồ sơ → **0** (không tồn tại = không có quyền lực);
    /// - tồn tại chiều Unknown → cap `cap_unknown`;
    /// - cold-start → cap `cold_start_cap`;
    /// - chiều thấp nhất cũng là trần (weakest-link);
    /// - W = min(caps, tổng có trọng số S).
    pub fn weight_of(&self, id: &NodeId) -> u32 {
        let Some(peer) = self.peers.get(id) else { return 0 };
        let dims = &peer.trust.dims;

        let mut cap = WEIGHT_SCALE;
        if dims.iter().any(Option::is_none) {
            cap = cap.min(self.policy.cap_unknown as u32);
        }
        if peer.cold_start {
            cap = cap.min(self.policy.cold_start_cap as u32);
        }
        if let Some(min_known) = dims.iter().flatten().min() {
            cap = cap.min((*min_known) as u32);
        }

        let weighted_sum: u64 = dims
            .iter()
            .zip(self.policy.dim_weights.iter())
            .map(|(dim, weight)| {
                let d = dim.unwrap_or(0) as u64;
                let w = (*weight).min(WEIGHT_SCALE) as u64;
                d.saturating_mul(w)
            })
            .sum();
        let scaled = (weighted_sum / WEIGHT_SCALE as u64) as u32;

        cap.min(scaled).min(WEIGHT_SCALE)
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

    const DAY_MS: u64 = 86_400_000;

    #[test]
    fn dim_weights_sum_to_scale() {
        let policy = ReputationPolicy::default();
        let total: u32 = policy.dim_weights.iter().sum();
        assert_eq!(total, WEIGHT_SCALE);
    }

    #[test]
    fn unknown_peer_has_zero_power() {
        let ledger = ReputationLedger::default();
        assert_eq!(ledger.weight_of(&nid(1)), 0);
    }

    #[test]
    fn fresh_attested_node_is_capped() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        // I=800, B=H=500 (baseline trung lập), O/E Unknown → cap_unknown 250
        // + cold-cap 150; S = (160+0+0+100+75) = 335 → W = min(150, 335) = 150.
        let w = ledger.weight_of(&nid(1));
        assert_eq!(w, 150);
        assert!(ledger.peer(&nid(1)).unwrap().cold_start);
    }

    #[test]
    fn sybil_farm_stays_below_quorum_threshold() {
        // 6 node mới attest đồng loạt — tổng 900, xa ngưỡng quorum 1800.
        let mut ledger = ReputationLedger::default();
        for s in 1..=6u8 {
            ledger.on_attested(nid(s), 0);
        }
        let total: u32 = (1..=6u8).map(|s| ledger.weight_of(&nid(s))).sum();
        assert_eq!(total, 6 * 150);
        assert!(total < 1800);
    }

    #[test]
    fn unknown_dim_caps_whole_score() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        // Node đã hết cold-start, 4 chiều lên 1000 trừ Observation (Unknown)
        // → vẫn phải cap 250.
        let peer = ledger.peer_mut_for_test(&nid(1));
        peer.trust.dims[TrustDim::Evidence as usize] = Some(1000);
        peer.trust.dims[TrustDim::Behavior as usize] = Some(1000);
        peer.trust.dims[TrustDim::History as usize] = Some(1000);
        peer.cold_start = false;
        let w = ledger.weight_of(&nid(1));
        assert_eq!(w, 250);
    }

    #[test]
    fn weak_link_caps_whole_score() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        let peer = ledger.peer_mut_for_test(&nid(1));
        peer.trust.dims = [Some(1000), Some(1000), Some(1000), Some(300), Some(1000)];
        peer.cold_start = false;
        // S = (200+200+250+60+150) = 860 nhưng Behavior 300 → cap 300.
        assert_eq!(ledger.weight_of(&nid(1)), 300);
    }

    #[test]
    fn hardware_anchored_full_score_reaches_two_vote_quorum() {
        // Node P2-1-target (mọi chiều 1000): 2 node đủ 2000 ≥ 1800.
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        ledger.on_attested(nid(2), 0);
        for s in [1u8, 2] {
            let peer = ledger.peer_mut_for_test(&nid(s));
            peer.trust.dims = [Some(1000); 5];
            peer.cold_start = false;
        }
        assert_eq!(ledger.weight_of(&nid(1)), 1000);
        assert_eq!(ledger.weight_of(&nid(2)), 1000);
    }

    #[test]
    fn software_identity_needs_three_votes() {
        // Node hiện tại (identity software 800, còn lại 1000): W = 800
        // → 2 node = 1600 < 1800; 3 node = 2400 ≥ 1800. Trung thực về nền tảng.
        let mut ledger = ReputationLedger::default();
        for s in 1..=3u8 {
            ledger.on_attested(nid(s), 0);
            let peer = ledger.peer_mut_for_test(&nid(s));
            peer.trust.dims = [Some(800), Some(1000), Some(1000), Some(1000), Some(1000)];
            peer.cold_start = false;
        }
        let w = ledger.weight_of(&nid(1));
        assert_eq!(w, 800);
        assert!(2 * w < 1800);
        assert!(3 * w >= 1800);
    }

    #[test]
    fn wrong_action_decays_behavior_below_quorum_usefulness() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        let peer = ledger.peer_mut_for_test(&nid(1));
        peer.trust.dims = [Some(1000); 5];
        peer.cold_start = false;
        assert_eq!(ledger.weight_of(&nid(1)), 1000);

        ledger.record_wrong_action(&nid(1), 10_000);
        // B = 400 → S = (200+200+250+80+150) = 880 → W = min(400, 880) = 400.
        assert_eq!(ledger.weight_of(&nid(1)), 400);
        // 400 + 1000 (node lành) = 1400 < 1800 → cặp này không còn đủ quorum.
        assert!(ledger.weight_of(&nid(1)) + 1000 < 1800);
    }

    #[test]
    fn restore_respects_cooldown() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        // Cold node (baseline B=500) wrong-action: 500 - 600 → bão hòa 0.
        // Một hành vi sai chấm dứt quyền bỏ phiếu ngay lập tức.
        ledger.record_wrong_action(&nid(1), 10_000);
        assert_eq!(
            ledger.peer(&nid(1)).unwrap().trust.dims[TrustDim::Behavior as usize],
            Some(0)
        );
        assert_eq!(ledger.weight_of(&nid(1)), 0);

        // Trong cooldown: corroboration không restore.
        ledger.record_corroborated(&nid(1), 10_000 + 60_000);
        assert_eq!(
            ledger.peer(&nid(1)).unwrap().trust.dims[TrustDim::Behavior as usize],
            Some(0)
        );

        // Hết cooldown: +100 mỗi lần xác nhận đúng — phục hồi chậm, có kiểm.
        ledger.record_corroborated(&nid(1), 10_000 + 3_600_000 + 1);
        assert_eq!(
            ledger.peer(&nid(1)).unwrap().trust.dims[TrustDim::Behavior as usize],
            Some(100)
        );
    }

    #[test]
    fn cold_start_clears_only_when_clean() {
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        // Đủ tuổi + observation nhưng CHƯA đủ số lượng → vẫn cold.
        ledger.refresh_cold_start(&nid(1), 30 * DAY_MS);
        assert!(ledger.peer(&nid(1)).unwrap().cold_start);

        for _ in 0..50 {
            ledger.on_observation(&nid(1), true);
        }
        ledger.refresh_cold_start(&nid(1), 30 * DAY_MS);
        assert!(!ledger.peer(&nid(1)).unwrap().cold_start);
        // Hết cold-start nhưng còn chiều Unknown → cap_unknown giữ nguyên.
        assert_eq!(ledger.weight_of(&nid(1)), 250);

        // Node có wrong-action thì KHÔNG BAO GIỜ được xóa cold-start
        // (dù đủ tuổi + observation). Node 2 chưa từng được clear.
        ledger.on_attested(nid(2), 0);
        for _ in 0..50 {
            ledger.on_observation(&nid(2), true);
        }
        ledger.record_wrong_action(&nid(2), 10 * DAY_MS);
        ledger.refresh_cold_start(&nid(2), 60 * DAY_MS);
        assert!(ledger.peer(&nid(2)).unwrap().cold_start);
    }

    #[test]
    fn unverified_observations_never_build_trust() {
        // INV-007: probe không verified thì không tạo điểm.
        let mut ledger = ReputationLedger::default();
        ledger.on_attested(nid(1), 0);
        for _ in 0..100 {
            ledger.on_observation(&nid(1), false);
        }
        assert_eq!(ledger.peer(&nid(1)).unwrap().observations, 100);
        assert_eq!(ledger.peer(&nid(1)).unwrap().trust.dims[TrustDim::Observation as usize], None);
    }

    impl ReputationLedger {
        /// Lối truy cập test — sửa hồ sơ trực tiếp để dựng kịch bản đã qua
        /// verify thực tế (tuổi, observation) mà không phải loop nghìn lần.
        #[doc(hidden)]
        pub fn peer_mut_for_test(&mut self, id: &NodeId) -> &mut PeerReputation {
            self.peers.get_mut(id).expect("peer phải tồn tại trong test")
        }
    }
}
