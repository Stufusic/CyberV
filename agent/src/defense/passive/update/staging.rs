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
                    if (m.target_version as u64) == tpm_counter
                        && (active_binary_hash == m.package_hash
                            || active_version == m.target_version)
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
                        StartupRecoveryAction::CompleteCommit {
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
