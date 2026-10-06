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
//! Mesh Trust Admission Gate & Enforcement State Machine (Gate 4 / NSG-1.5)
//!
//! Ref: Docs/GATE0_SECURITY_CONTRACT_FREEZE.md Section 3 & 4.
//!
//! Nguyên tắc an ninh:
//! 1. mDNS Discovery != Trust! Một endpoint phát hiện qua mDNS chỉ là Candidate.
//! 2. Chống Sybil Attack: Chỉ cho phép peer được ủy quyền (nằm trong `authorized_peer_set`
//!    hoặc có pinning hợp lệ) tham gia đồ thị và bỏ phiếu Quorum.
//! 3. Chống DoS: Giới hạn cứng `max_pending_handshakes` và trần số peer admitted.
//! 4. State Machine Semantics: Mất Quorum -> DEGRADED (liveness degraded).
//!    Chỉ kích hoạt ISOLATED khi có bằng chứng mâu thuẫn/tấn công chủ động (Active Contradiction).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::graph::NodeId;
use super::MeshError;

/// Ngưỡng số phiên bắt tay dở dang tối đa cho phép đồng thời (chống SYN/Handshake flood DoS).
pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 16;
/// Trần số peer tối đa admitted trong một mạng mesh LAN.
pub const DEFAULT_MAX_ADMITTED_PEERS: usize = 64;
/// Độ lệch epoch tối đa chấp nhận được trước khi coi là stale.
pub const DEFAULT_MAX_EPOCH_LAG: u64 = 2;

/// Trạng thái thực thi của nút trong mạng lưới Mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshEnforcementState {
    /// Tắt hoàn toàn tính năng mesh.
    Off,
    /// Chỉ lắng nghe và thu thập mDNS, không kết nối hay gửi bản tin.
    Discovery,
    /// Đã kết nối và tính toán Quorum nhưng CHỈ ghi vào ShadowLedger, KHÔNG cô lập.
    Shadow,
    /// Mất Quorum / Mạng phân mảnh: suy giảm chức năng mạng, TUYỆT ĐỐI KHÔNG tự cô lập.
    Degraded,
    /// Chế độ thực thi đầy đủ (chỉ khi có Freeze Gate mở + quản trị viên cho phép).
    Enforce,
    /// Phát hiện bằng chứng giả mạo / rollback / tấn công chủ động -> Cách ly an toàn.
    Isolated,
    /// Chờ phục hồi và cấp lại quyền từ quản trị viên (Asymmetric Recovery INV-003).
    Recovery,
}

impl MeshEnforcementState {
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Shadow | Self::Enforce | Self::Degraded)
    }

    pub fn allows_isolation_actions(&self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// Quyết định của Admission Gate đối với một peer candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Admitted,
    RejectedUnauthorized,
    RejectedRevoked,
    RejectedEpochStale,
    RejectedCapacityFull,
}

/// Cấu hình chính sách Admission Gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAdmissionPolicy {
    pub max_pending_handshakes: usize,
    pub max_admitted_peers: usize,
    pub max_epoch_lag: u64,
    /// Bắt buộc peer phải nằm trong danh sách ủy quyền (chống Sybil).
    pub require_authorization: bool,
}

impl Default for MeshAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            max_admitted_peers: DEFAULT_MAX_ADMITTED_PEERS,
            max_epoch_lag: DEFAULT_MAX_EPOCH_LAG,
            // Mặc định: cho phép open discovery ghi nhận Discovered; chế độ nghiêm ngặt bật true.
            require_authorization: false,
        }
    }
}

/// RAII Guard quản lý số lượng phiên bắt tay đang chờ xử lý.
pub struct PendingHandshakeGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for PendingHandshakeGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bộ kiểm soát nhập môn (Trust Admission Controller) cho Mesh.
pub struct MeshAdmissionController {
    policy: MeshAdmissionPolicy,
    authorized_peers: HashSet<NodeId>,
    revoked_peers: HashSet<NodeId>,
    current_epoch: u64,
    pending_handshakes: Arc<AtomicUsize>,
    state: MeshEnforcementState,
}

impl MeshAdmissionController {
    pub fn new(policy: MeshAdmissionPolicy) -> Self {
        Self {
            policy,
            authorized_peers: HashSet::new(),
            revoked_peers: HashSet::new(),
            current_epoch: 1,
            pending_handshakes: Arc::new(AtomicUsize::new(0)),
            state: MeshEnforcementState::Off,
        }
    }

    pub fn state(&self) -> MeshEnforcementState {
        self.state
    }

    pub fn set_state(&mut self, state: MeshEnforcementState) {
        self.state = state;
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        if epoch >= self.current_epoch {
            self.current_epoch = epoch;
        }
    }

    pub fn authorize_peer(&mut self, node_id: NodeId) {
        self.authorized_peers.insert(node_id);
    }

    pub fn revoke_peer(&mut self, node_id: NodeId) {
        self.authorized_peers.remove(&node_id);
        self.revoked_peers.insert(node_id);
    }

    pub fn is_authorized(&self, node_id: &NodeId) -> bool {
        if !self.policy.require_authorization {
            return !self.revoked_peers.contains(node_id);
        }
        self.authorized_peers.contains(node_id) && !self.revoked_peers.contains(node_id)
    }

    /// Giữ một chỗ bắt tay (Handshake Slot). Trả về lỗi nếu vượt quá trần pending handshakes.
    pub fn acquire_handshake_slot(&self) -> Result<PendingHandshakeGuard, MeshError> {
        let current = self.pending_handshakes.fetch_add(1, Ordering::SeqCst);
        if current >= self.policy.max_pending_handshakes {
            self.pending_handshakes.fetch_sub(1, Ordering::SeqCst);
            return Err(MeshError::CapacityExceeded(format!(
                "Quá giới hạn pending handshakes ({}/{}) - Từ chối kết nối mới để chống DoS",
                current, self.policy.max_pending_handshakes
            )));
        }
        Ok(PendingHandshakeGuard {
            counter: self.pending_handshakes.clone(),
        })
    }

    /// Đánh giá tư cách nhập môn của peer candidate (Gate 4).
    pub fn evaluate_candidate(
        &self,
        node_id: &NodeId,
        _vk: &VerifyingKey,
        peer_epoch: u64,
        current_admitted_count: usize,
    ) -> AdmissionVerdict {
        // 1. Kiểm tra danh sách thu hồi
        if self.revoked_peers.contains(node_id) {
            return AdmissionVerdict::RejectedRevoked;
        }

        // 2. Kiểm tra danh sách ủy quyền (Sybil Gate)
        if self.policy.require_authorization && !self.authorized_peers.contains(node_id) {
            return AdmissionVerdict::RejectedUnauthorized;
        }

        // 3. Kiểm tra độ lệch Epoch (Stale Epoch Gate)
        let epoch_diff = self.current_epoch.abs_diff(peer_epoch);
        if epoch_diff > self.policy.max_epoch_lag {
            return AdmissionVerdict::RejectedEpochStale;
        }

        // 4. Kiểm tra sức chứa mạng lưới
        if current_admitted_count >= self.policy.max_admitted_peers {
            return AdmissionVerdict::RejectedCapacityFull;
        }

        AdmissionVerdict::Admitted
    }

    /// Xử lý biến cố Quorum và chuyển trạng thái an toàn:
    /// Bất biến: Mất Quorum CHỈ hạ cấp về `Degraded`, TUYỆT ĐỐI KHÔNG tự `Isolated`!
    pub fn handle_quorum_liveness_loss(&mut self) {
        match self.state {
            MeshEnforcementState::Enforce | MeshEnforcementState::Shadow => {
                tracing::warn!("Mất Quorum hoặc phân mảnh mạng: Chuyển trạng thái sang DEGRADED (Safety over Liveness)");
                self.state = MeshEnforcementState::Degraded;
            }
            _ => {}
        }
    }

    /// Xử lý khi Quorum phục hồi thành công.
    pub fn handle_quorum_restored(&mut self, prefer_enforce: bool) {
        if self.state == MeshEnforcementState::Degraded {
            self.state = if prefer_enforce {
                MeshEnforcementState::Enforce
            } else {
                MeshEnforcementState::Shadow
            };
            tracing::info!(state = ?self.state, "Quorum đã phục hồi đầy đủ");
        }
    }

    /// Kích hoạt cô lập khi phát hiện bằng chứng tấn công/mâu thuẫn chủ động.
    pub fn handle_active_contradiction(&mut self, reason: &str) {
        tracing::error!(reason, "PHÁT HIỆN BẰNG CHỨNG TẤN CÔNG / MÂU THUẪN: Kích hoạt ISOLATED lập tức!");
        self.state = MeshEnforcementState::Isolated;
    }
}
