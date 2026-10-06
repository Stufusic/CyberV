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
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateStagingState {
    Current,
    Staged,
    Verified,
    Active,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStage {
    Staged,
    TpmIncremented,
    SoftwareCommitted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommitMarker {
    pub marker_id: String,
    pub target_version: u32,
    pub package_hash: String,
    pub stage: CommitStage,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartupRecoveryAction {
    CompleteCommit {
        target_version: u32,
    },
    RollbackCleanly {
        target_version: u32,
    },
    NoActionRequired,
    ContradictionDetected {
        software_version: u32,
        tpm_counter: u64,
    },
}

pub struct UpdateStagingManager;

impl UpdateStagingManager {
    /// Chuyển dịch trạng thái cập nhật qua các cổng an toàn
    pub fn advance_state(
        current_state: UpdateStagingState,
        is_verification_passed: bool,
    ) -> Result<UpdateStagingState, &'static str> {
        match current_state {
            UpdateStagingState::Current => {
                if is_verification_passed {
                    Ok(UpdateStagingState::Staged)
                } else {
                    Err("Package unverified; cannot stage")
                }
            }
            UpdateStagingState::Staged => {
                if is_verification_passed {
                    Ok(UpdateStagingState::Verified)
                } else {
                    Ok(UpdateStagingState::RolledBack)
                }
            }
            UpdateStagingState::Verified => {
                if is_verification_passed {
                    Ok(UpdateStagingState::Active)
                } else {
                    Ok(UpdateStagingState::RolledBack)
                }
            }
            UpdateStagingState::Active => Err("Already active"),
            UpdateStagingState::RolledBack => Err("Update was rolled back"),
        }
    }

    /// Khôi phục sự cố crash giữa chừng trong giao dịch cập nhật 2 pha (Phase 24.2 per Docs/rv15.md Section 3)
    pub fn evaluate_startup_recovery(
        marker: Option<&PendingCommitMarker>,
        active_binary_hash: &str,
        active_version: u32,
        tpm_counter: u64,
    ) -> StartupRecoveryAction {
        match marker {
            Some(m) => match m.stage {
                // Trường hợp 1: Đã tăng TPM counter nhưng tiến trình crash trước khi ghi commit hoàn tất
                CommitStage::TpmIncremented => {
                    // Hoàn tất commit CHỈ khi cả hai điều kiện cùng thỏa:
                    // counter TPM khớp target VÀ binary đang active đúng là gói đã cam kết.
                    // Điều kiện "hash || version" cũ cho phép một binary chỉ cần
                    // tự khai đúng version là được hoàn tất dù băm lệch — đã loại bỏ.
                    if (m.target_version as u64) == tpm_counter
                        && active_binary_hash == m.package_hash
                    {
                        StartupRecoveryAction::CompleteCommit {
                            target_version: m.target_version,
                        }
                    } else if (active_version as u64) < tpm_counter {
                        StartupRecoveryAction::ContradictionDetected {
                            software_version: active_version,
                            tpm_counter,
                        }
                    } else {
                        // Trạng thái bất nhất (counter/target/hash không khớp nhau):
                        // fail-closed — hoàn tất commit trên trạng thái này là rollback
                        // ngầm, chuyển sang rollback sạch thay vì "CompleteCommit".
                        StartupRecoveryAction::RollbackCleanly {
                            target_version: m.target_version,
                        }
                    }
                }
                // Trường hợp 2: Mới ghi staging marker nhưng crash trước khi tăng TPM counter
                CommitStage::Staged => {
                    // Chưa tăng TPM counter, khôi phục an toàn về bản trước đó
                    StartupRecoveryAction::RollbackCleanly {
                        target_version: m.target_version,
                    }
                }
                // Trường hợp 3: Đã hoàn tất commit (marker còn sót lại do chưa kịp xóa)
                CommitStage::SoftwareCommitted => StartupRecoveryAction::NoActionRequired,
            },
            None => {
                // Không có marker: kiểm tra xem có contradiction giữa version và counter không
                if (active_version as u64) < tpm_counter {
                    StartupRecoveryAction::ContradictionDetected {
                        software_version: active_version,
                        tpm_counter,
                    }
                } else {
                    StartupRecoveryAction::NoActionRequired
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: u32 = 5;
    const PKG_HASH: &str = "pkg_hash_abc";

    fn marker(stage: CommitStage) -> PendingCommitMarker {
        PendingCommitMarker {
            marker_id: "m1".to_string(),
            target_version: TARGET,
            package_hash: PKG_HASH.to_string(),
            stage,
            timestamp: 1000,
        }
    }

    #[test]
    fn tpm_incremented_with_matching_hash_and_counter_completes() {
        let action = UpdateStagingManager::evaluate_startup_recovery(
            Some(&marker(CommitStage::TpmIncremented)),
            PKG_HASH,
            TARGET,
            TARGET as u64,
        );
        assert_eq!(
            action,
            StartupRecoveryAction::CompleteCommit { target_version: TARGET }
        );
    }

    /// REGRESSION M1: điều kiện "hash || version" cũ cho phép binary chỉ cần
    /// tự khai đúng version là hoàn tất commit dù băm lệch — phải bị chặn.
    #[test]
    fn tpm_incremented_with_mismatched_hash_never_completes() {
        // Version khớp nhưng hash KHÔNG khớp -> không được CompleteCommit
        let action = UpdateStagingManager::evaluate_startup_recovery(
            Some(&marker(CommitStage::TpmIncremented)),
            "different_binary_hash",
            TARGET,
            TARGET as u64,
        );
        assert_ne!(action, StartupRecoveryAction::CompleteCommit { target_version: TARGET });

        // Hash khớp nhưng counter/target lệch -> cũng không được CompleteCommit
        let action2 = UpdateStagingManager::evaluate_startup_recovery(
            Some(&marker(CommitStage::TpmIncremented)),
            PKG_HASH,
            TARGET,
            (TARGET + 1) as u64,
        );
        assert_ne!(action2, StartupRecoveryAction::CompleteCommit { target_version: TARGET });
    }

    /// REGRESSION M1: nhánh else cũ trả CompleteCommit trên trạng thái bất nhất
    /// (active_version > tpm_counter) — giờ phải RollbackCleanly/Contradiction.
    #[test]
    fn inconsistent_state_rolls_back_instead_of_completing() {
        let action = UpdateStagingManager::evaluate_startup_recovery(
            Some(&marker(CommitStage::TpmIncremented)),
            "different_binary_hash",
            TARGET + 2, // active TRƯỚC counter -> trạng thái bất nhất
            TARGET as u64,
        );
        assert!(matches!(
            action,
            StartupRecoveryAction::RollbackCleanly { .. }
                | StartupRecoveryAction::ContradictionDetected { .. }
        ));
    }

    #[test]
    fn software_rollback_detected_without_marker() {
        let action = UpdateStagingManager::evaluate_startup_recovery(None, "hash", 3, 7);
        assert_eq!(
            action,
            StartupRecoveryAction::ContradictionDetected {
                software_version: 3,
                tpm_counter: 7,
            }
        );
    }

    #[test]
    fn staged_stage_rolls_back_and_committed_stage_noops() {
        assert_eq!(
            UpdateStagingManager::evaluate_startup_recovery(
                Some(&marker(CommitStage::Staged)),
                PKG_HASH,
                TARGET - 1,
                TARGET as u64
            ),
            StartupRecoveryAction::RollbackCleanly { target_version: TARGET }
        );
        assert_eq!(
            UpdateStagingManager::evaluate_startup_recovery(
                Some(&marker(CommitStage::SoftwareCommitted)),
                PKG_HASH,
                TARGET,
                TARGET as u64
            ),
            StartupRecoveryAction::NoActionRequired
        );
    }

    #[test]
    fn advance_state_gate_is_fail_closed() {
        // Chưa verify -> không được stage
        assert!(UpdateStagingManager::advance_state(UpdateStagingState::Current, false).is_err());
        // Staged -> verify fail -> RolledBack
        assert_eq!(
            UpdateStagingManager::advance_state(UpdateStagingState::Staged, false).unwrap(),
            UpdateStagingState::RolledBack
        );
        // Active không advance được nữa
        assert!(UpdateStagingManager::advance_state(UpdateStagingState::Active, true).is_err());
    }
}