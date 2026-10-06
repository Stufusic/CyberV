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
//! Isolation Desk (I-2 — M-PLAN §6.1/6.2/6.3): coordinator giữa quorum đề
//! nghị (ShadowLedger) và thực thi thật (WFP), có NGƯỜI DUYỆT ở giữa.
//!
//! Luồng: quorum đạt → ShadowLedger ghi đề nghị (KHÔNG thực thi — NSG-3) →
//! UI Isolation Inbox hiển thị → **operator bấm duyệt** → `approve_isolation`
//! mới thực thi WFP thật + graph Isolated. Quyết định cuối là con người →
//! KHÔNG phá freeze gate (auto-pilot I-3 vẫn bị chặn độc lập).
//!
//! Ranh giới trung thực:
//! - ShadowLedger giữ bất biến `executed == false` vĩnh viễn — quyết định
//!   thực thi nằm ở DecisionLog, không đụng sổ shadow;
//! - không mở được WFP (thiếu admin) hoặc peer là loopback → enforcement
//!   **LogicOnly** (graph + ngừng gossip) — KHÔNG giả vờ đã chặn mạng, UI
//!   nhận `LogicOnly` để hiển thị `is_verified: false` cho hành động này;
//! - admin lift không phải recovery có chữ ký authority (INV-014): lift chỉ
//!   hạ về `Suspect` + probation K tick sạch mới được `Attested`.

use std::collections::VecDeque;
use std::net::IpAddr;

use super::graph::NodeId;
use super::wfp::{WfpEngine, WfpError};
use super::MeshError;

/// Chế độ thực thi của một lệnh cách ly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// WFP thật — rule per-IP đã thêm.
    Wfp,
    /// Logic-only: graph + ngừng gossip. KHÔNG có chặn mạng thật — UI phải
    /// hiển thị hành động này là "chưa verified" (INV-007).
    LogicOnly,
    /// Quyết định không thực thi gì (reject đề nghị — chỉ ghi audit).
    NotExecuted,
}

impl EnforcementMode {
    /// Chuỗi cho UI/API — trung thực về chế độ (INV-007).
    pub const fn as_str(self) -> &'static str {
        match self {
            EnforcementMode::Wfp => "WFP",
            EnforcementMode::LogicOnly => "LOGIC_ONLY",
            EnforcementMode::NotExecuted => "NOT_EXECUTED",
        }
    }
}

/// Đề nghị cách ly cho UI Isolation Inbox — chỉ là DỮ LIỆU từ shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationProposal {
    pub subject: NodeId,
    pub total_weight: u32,
    /// event_id các phiếu độc lập — evidence trace cho UI + audit.
    pub accepted_event_ids: Vec<[u8; 32]>,
    pub proposed_mono_ms: u64,
    pub ttl_ms: u64,
}

/// Quyết định của operator trên một đề nghị.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    Approve,
    Lift,
    Reject,
}

/// Một quyết định đã ghi — audit trail hai chiều (isolate + lift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEntry {
    pub subject: NodeId,
    pub action: DecisionAction,
    pub enforcement: EnforcementMode,
    /// Evidence refs: event_id phiếu/alert — truy vết qua MMR (phase13).
    pub evidence_refs: Vec<[u8; 32]>,
    pub decided_mono_ms: u64,
    pub decided_wall_ms: u64,
    /// Lý do ngắn của operator (bounded).
    pub reason: String,
}

/// Trần số quyết định lưu + trần lý do (INV-015).
pub const MAX_DECISIONS: usize = 256;
pub const MAX_REASON_LEN: usize = 200;

/// Sổ quyết định bounded — mọi loại bỏ đếm được.
#[derive(Debug, Default)]
pub struct DecisionLog {
    entries: VecDeque<DecisionEntry>,
    dropped: u64,
}

impl DecisionLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn iter(&self) -> impl Iterator<Item = &DecisionEntry> {
        self.entries.iter()
    }

    /// Mốc quyết định MỚI NHẤT của một subject — dùng để không hiển thị lại
    /// đề nghị đã quyết.
    pub fn latest_decision_mono(&self, subject: &NodeId) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|e| &e.subject == subject)
            .map(|e| e.decided_mono_ms)
    }

    pub fn record(&mut self, entry: DecisionEntry) -> Result<(), MeshError> {
        if self.entries.len() >= MAX_DECISIONS {
            self.dropped = self.dropped.saturating_add(1);
            return Err(MeshError::LimitExceeded {
                kind: "isolation-decision",
                dropped: self.dropped,
            });
        }
        self.entries.push_back(entry);
        Ok(())
    }
}

/// Desk thực thi — WFP thật khi mở được engine, LogicOnly khi không.
pub struct IsolationDesk {
    mode: EnforcementMode,
    wfp: Option<WfpEngine>,
}

impl IsolationDesk {
    /// Mở WFP engine; thất bại (thiếu admin...) → LogicOnly + warn một lần
    /// (không spam, không giả vờ).
    pub fn open() -> Self {
        match WfpEngine::open() {
            Ok(wfp) => {
                tracing::info!("WFP engine mở — cách ly sẽ chặn mạng thật");
                Self { mode: EnforcementMode::Wfp, wfp: Some(wfp) }
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "WFP không khả dụng — cách ly chạy LOGIC-ONLY (không chặn mạng thật)"
                );
                Self { mode: EnforcementMode::LogicOnly, wfp: None }
            }
        }
    }

    /// Desk logic-only thuần (test + cấu hình tắt WFP).
    pub fn logic_only() -> Self {
        Self { mode: EnforcementMode::LogicOnly, wfp: None }
    }

    pub fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Block per-IP tới `until_unix_ms`. Trả chế độ thực thi THẬT cho peer
    /// này: Wfp khi đã thêm rule; LogicOnly khi peer loopback (plan §9 cấm
    /// rule loopback — bảo vệ IPC) hoặc desk không có WFP.
    pub fn block(
        &mut self,
        ip: Option<IpAddr>,
        subject: &[u8; 32],
        until_unix_ms: u64,
    ) -> Result<EnforcementMode, WfpError> {
        let Some(wfp) = self.wfp.as_mut() else {
            return Ok(EnforcementMode::LogicOnly);
        };
        match ip {
            // Peer loopback: plan §9 cấm rule loopback — logic-only là hành
            // vi đúng, không phải lỗi.
            Some(ip) => {
                wfp.block_peer(ip, subject, until_unix_ms)?;
                Ok(EnforcementMode::Wfp)
            }
            None => Ok(EnforcementMode::LogicOnly),
        }
    }

    /// Gỡ block per-IP (admin lift / sweep). Idempotent.
    pub fn unblock(&mut self, subject: &[u8; 32]) -> Result<usize, WfpError> {
        match self.wfp.as_mut() {
            Some(wfp) => wfp.unblock_subject(subject),
            None => Ok(0),
        }
    }

    /// Watchdog/startup reconcile — xóa rule hết hạn (plan §9). Idempotent.
    pub fn sweep(&mut self, now_unix_ms: u64) -> Result<usize, WfpError> {
        match self.wfp.as_mut() {
            Some(wfp) => wfp.sweep_expired(now_unix_ms),
            None => Ok(0),
        }
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

    fn entry(subject: NodeId, action: DecisionAction, mono: u64) -> DecisionEntry {
        DecisionEntry {
            subject,
            action,
            enforcement: EnforcementMode::LogicOnly,
            evidence_refs: vec![[0xAA; 32]],
            decided_mono_ms: mono,
            decided_wall_ms: mono,
            reason: "kiểm thử".into(),
        }
    }

    #[test]
    fn decision_log_latest_decision_wins() {
        let mut log = DecisionLog::new();
        log.record(entry(nid(1), DecisionAction::Approve, 100)).unwrap();
        log.record(entry(nid(1), DecisionAction::Lift, 200)).unwrap();
        assert_eq!(log.latest_decision_mono(&nid(1)), Some(200));
        assert_eq!(log.latest_decision_mono(&nid(2)), None);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn decision_log_bound_is_counted() {
        let mut log = DecisionLog::new();
        for i in 0..MAX_DECISIONS {
            log.record(entry(nid((i % 251) as u8), DecisionAction::Approve, i as u64)).unwrap();
        }
        assert!(matches!(
            log.record(entry(nid(0xFF), DecisionAction::Approve, 99_999)),
            Err(MeshError::LimitExceeded { kind: "isolation-decision", .. })
        ));
        assert_eq!(log.dropped(), 1);
    }

    #[test]
    fn logic_only_desk_is_honest() {
        let mut desk = IsolationDesk::logic_only();
        assert_eq!(desk.mode(), EnforcementMode::LogicOnly);
        // block "thành công" ở mức logic-only — không chạm WFP thật.
        let mode = desk
            .block(Some("192.0.2.5".parse().unwrap()), &[1u8; 32], 1)
            .unwrap();
        assert_eq!(mode, EnforcementMode::LogicOnly);
        assert_eq!(desk.unblock(&[1u8; 32]).unwrap(), 0);
        assert_eq!(desk.sweep(1).unwrap(), 0);
    }
}
