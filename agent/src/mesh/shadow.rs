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
//! Shadow Ledger — sổ ghi quyết định CHƯA thực thi (NSG-3)
//!
//! Ref: plan v2 §2.1 (shadow mode mặc định), §7.2 (UC-2 bước 3), §14
//! (INV-013). Shadow mode là hàng rào trước pilot/auto: quorum đạt → quyết
//! định isolate **ĐƯỢC GHI** nhưng **KHÔNG THỰC THI** — đo wrong-action rate
//! trên benign set trước khi bật hành động thật (NSG-4, gate freeze + D2.3).
//!
//! Bất biến kết cấu (điều kiện đóng NSG-3): ledger **không có API nào thực
//! thi** — không nhận `MeshGraph`, không có đường chuyển `executed` sang
//! true. Test tích hợp chặn: mọi entry `executed == false` vĩnh viễn.

use std::collections::VecDeque;

use super::graph::NodeId;
use super::quorum::{QuorumOutcome, QuorumVerdict};
use super::MeshError;

/// Trần số entry shadow (INV-015 — sẽ chuyển signed policy).
pub const MAX_SHADOW_ENTRIES: usize = 1024;

/// Hành động ĐỀ NGHỊ — chỉ là dữ liệu trong sổ, không phải lệnh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposedAction {
    /// Quorum đạt — đề nghị isolate với TTL (NSG-4 sẽ quyết định thực thi
    /// sau khi wrong-action rate đạt ngưỡng benign set).
    Isolate { ttl_ms: u64 },
    /// Quorum không đạt — chỉ quan sát.
    Observe,
}

/// Kết quả đối chiếu hậu kỳ (replay benign set / xác nhận bên ngoài).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowOutcome {
    /// Chưa đối chiếu.
    Pending,
    /// Đối chiếu xong: đề nghị đúng (subject thực sự xấu).
    ConfirmedCorrect,
    /// Đề nghị SAI (subject lành) — caller phải feed `ReputationLedger::
    /// record_wrong_action` cho các voter (INV-013: report sai làm yếu vote).
    WrongAction,
}

/// Một quyết định đã ghi trong shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub subject: NodeId,
    pub reached: bool,
    pub total_weight: u32,
    /// event_id của các phiếu độc lập được tính — truy vết qua MMR.
    pub accepted_event_ids: Vec<[u8; 32]>,
    pub proposed_action: ProposedAction,
    pub decided_mono_ms: u64,
    pub outcome: ShadowOutcome,
    /// INV-013: KHÔNG BAO GIỜ true — shadow không thực thi. Trường chỉ tồn
    /// tại để dashboard hiển thị bất biến này; không API nào đặt nó.
    pub executed: bool,
}

/// Sổ shadow — bounded, mọi loại bỏ đếm được.
#[derive(Debug, Default)]
pub struct ShadowLedger {
    entries: VecDeque<ShadowEntry>,
    dropped_count: u64,
}

impl ShadowLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    pub fn entries(&self) -> impl Iterator<Item = &ShadowEntry> {
        self.entries.iter()
    }

    /// Bất biến đọc được: toàn bộ entry đều chưa thực thi (shadow mode).
    pub fn all_unexecuted(&self) -> bool {
        self.entries.iter().all(|e| !e.executed)
    }

    pub fn wrong_action_count(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.outcome == ShadowOutcome::WrongAction)
            .count() as u64
    }

    /// Ghi một quyết định quorum vào sổ — proposal, không phải lệnh.
    pub fn record(
        &mut self,
        subject: NodeId,
        outcome: &QuorumOutcome,
        ttl_ms: u64,
        now_mono_ms: u64,
    ) -> Result<(), MeshError> {
        if self.entries.len() >= MAX_SHADOW_ENTRIES {
            self.dropped_count = self.dropped_count.saturating_add(1);
            return Err(MeshError::LimitExceeded {
                kind: "shadow-entry",
                dropped: self.dropped_count,
            });
        }
        let (reached, total_weight, accepted, action) = match &outcome.verdict {
            QuorumVerdict::Reached { total_weight, accepted, .. } => (
                true,
                *total_weight,
                accepted.clone(),
                ProposedAction::Isolate { ttl_ms },
            ),
            QuorumVerdict::NotReached(_) => {
                (false, 0, Vec::new(), ProposedAction::Observe)
            }
        };
        self.entries.push_back(ShadowEntry {
            subject,
            reached,
            total_weight,
            accepted_event_ids: accepted,
            proposed_action: action,
            decided_mono_ms: now_mono_ms,
            outcome: ShadowOutcome::Pending,
            executed: false,
        });
        Ok(())
    }

    /// Đối chiếu hậu kỳ: đánh dấu outcome entry MỚI NHẤT của subject đang
    /// Pending. Trả false nếu không tìm thấy (caller log lại, không âm thầm
    /// với dữ liệu khớp lệnh).
    pub fn mark_outcome(
        &mut self,
        subject: &NodeId,
        outcome: ShadowOutcome,
    ) -> bool {
        let target = self
            .entries
            .iter_mut()
            .rev()
            .find(|e| &e.subject == subject && e.outcome == ShadowOutcome::Pending);
        match target {
            Some(entry) => {
                entry.outcome = outcome;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::events::{ObsChannel, SignalClass};
    use crate::mesh::quorum::{Ballot, NotReachedReason, QuorumPolicy};

    fn nid(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    fn reached_outcome() -> QuorumOutcome {
        // Dựng verdict Reached trực tiếp qua engine với 2 phiếu đầy đủ.
        let b1 = Ballot {
            event_id: [1; 32],
            origin_id: nid(1),
            epoch: 0,
            subject: nid(0xEE),
            signal_class: SignalClass::Verified,
            obs_channel: ObsChannel::Kernel,
            evidence_root: [0xA1; 32],
            causal_parents: vec![],
            path_class: 1,
            weight: 1000,
        };
        let b2 = Ballot {
            event_id: [2; 32],
            origin_id: nid(2),
            epoch: 0,
            subject: nid(0xEE),
            signal_class: SignalClass::Verified,
            obs_channel: ObsChannel::FilesystemAcl,
            evidence_root: [0xA2; 32],
            causal_parents: vec![],
            path_class: 2,
            weight: 1000,
        };
        crate::mesh::quorum::evaluate_quorum(&[b1, b2], nid(0xEE), 0, |_| false, &QuorumPolicy::default())
    }

    #[test]
    fn record_writes_proposal_not_execution() {
        let mut ledger = ShadowLedger::new();
        ledger.record(nid(0xEE), &reached_outcome(), 900_000, 1000).unwrap();
        let entry = ledger.entries().next().unwrap();
        assert!(entry.reached);
        assert_eq!(entry.proposed_action, ProposedAction::Isolate { ttl_ms: 900_000 });
        assert_eq!(entry.outcome, ShadowOutcome::Pending);
        // Bất biến trung tâm của shadow mode:
        assert!(!entry.executed);
        assert!(ledger.all_unexecuted());
    }

    #[test]
    fn not_reached_records_observe_only() {
        let mut ledger = ShadowLedger::new();
        let empty = QuorumOutcome {
            verdict: QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes),
            flood_dropped: 0,
        };
        ledger.record(nid(0x11), &empty, 900_000, 1000).unwrap();
        let entry = ledger.entries().next().unwrap();
        assert!(!entry.reached);
        assert_eq!(entry.proposed_action, ProposedAction::Observe);
        assert!(ledger.all_unexecuted());
    }

    #[test]
    fn wrong_action_outcome_is_recorded_and_countable() {
        let mut ledger = ShadowLedger::new();
        ledger.record(nid(0xEE), &reached_outcome(), 900_000, 1000).unwrap();
        assert!(ledger.mark_outcome(&nid(0xEE), ShadowOutcome::WrongAction));
        assert_eq!(ledger.wrong_action_count(), 1);
        assert!(ledger.all_unexecuted());
        // Đối chiếu entry không tồn tại → false (caller log, không im lặng).
        assert!(!ledger.mark_outcome(&nid(0x77), ShadowOutcome::ConfirmedCorrect));
    }

    #[test]
    fn bound_enforced_with_accounting() {
        let mut ledger = ShadowLedger::new();
        let empty = QuorumOutcome {
            verdict: QuorumVerdict::NotReached(NotReachedReason::NoEligibleVotes),
            flood_dropped: 0,
        };
        for i in 0..MAX_SHADOW_ENTRIES {
            ledger.record(nid((i % 251) as u8), &empty, 1, i as u64).unwrap();
        }
        let err = ledger.record(nid(0xFF), &empty, 1, 9_999_999).unwrap_err();
        assert!(matches!(err, MeshError::LimitExceeded { kind: "shadow-entry", dropped: 1 }));
        assert_eq!(ledger.dropped_count(), 1);
    }
}
