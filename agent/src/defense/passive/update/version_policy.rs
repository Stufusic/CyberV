//! Monotonic Anti-Rollback Version Policy (P24.8)
//!
//! Ref: Docs/rv13.md Section 7:
//! "Version policy: Bắt buộc V_new >= V_current + 1. Bác bỏ mọi nỗ lực rollback/downgrade."

use crate::trust::tpm::TpmAssuranceType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionPolicyDecision {
    AllowedUpgrade { increment: u32 },
    RejectedDowngrade { current: u32, target: u32 },
    RejectedReplaySameVersion { version: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareVersionDecision {
    AllowedUpgradeWithCommitMarker {
        increment: u32,
        assurance: TpmAssuranceType,
    },
    RejectedRollbackAgainstHardwareCounter {
        target: u32,
        counter: u64,
        assurance: TpmAssuranceType,
    },
    ContradictionRollbackDetected {
        software_current: u32,
        counter: u64,
        discrepancy: u64,
        assurance: TpmAssuranceType,
    },
    RejectedReplaySameVersion {
        version: u32,
    },
}

pub struct VersionPolicyValidator;

impl VersionPolicyValidator {
    /// Kiểm tra tính hợp lệ của phiên bản mới so với phiên bản hiện tại (phần mềm thuần túy)
    pub fn evaluate(current_version: u32, target_version: u32) -> VersionPolicyDecision {
        if target_version > current_version {
            VersionPolicyDecision::AllowedUpgrade {
                increment: target_version - current_version,
            }
        } else if target_version == current_version {
            VersionPolicyDecision::RejectedReplaySameVersion {
                version: target_version,
            }
        } else {
            VersionPolicyDecision::RejectedDowngrade {
                current: current_version,
                target: target_version,
            }
        }
    }

    /// Đánh giá nâng cao có ràng buộc phần cứng TPM NV Counter (Phase 24.2 per Docs/rv15.md Section 1-3)
    /// Ngữ nghĩa: TPM_NV_COUNTER = highest_accepted_state_version.
    pub fn evaluate_with_hardware_counter(
        software_current: u32,
        target_version: u32,
        tpm_counter: u64,
        assurance: TpmAssuranceType,
    ) -> HardwareVersionDecision {
        let current_u64 = software_current as u64;

        // 1. Kiểm tra Contradiction (Bất nhất đĩa và phần cứng):
        // Nếu phần mềm hiện tại trên đĩa nhỏ hơn giá trị TPM counter,
        // điều đó chứng minh đĩa đã bị snapshot revert hoặc clone đĩa về bản cũ.
        if current_u64 < tpm_counter {
            return HardwareVersionDecision::ContradictionRollbackDetected {
                software_current,
                counter: tpm_counter,
                discrepancy: tpm_counter - current_u64,
                assurance,
            };
        }

        // 2. Kiểm tra Replay cùng phiên bản
        if (target_version as u64) == tpm_counter && target_version == software_current {
            return HardwareVersionDecision::RejectedReplaySameVersion {
                version: target_version,
            };
        }

        // 3. Kiểm tra mục tiêu có thấp hơn hoặc bằng counter phần cứng không
        if (target_version as u64) <= tpm_counter {
            return HardwareVersionDecision::RejectedRollbackAgainstHardwareCounter {
                target: target_version,
                counter: tpm_counter,
                assurance,
            };
        }

        // 4. Cho phép nâng cấp nếu target > tpm_counter
        HardwareVersionDecision::AllowedUpgradeWithCommitMarker {
            increment: target_version - (tpm_counter as u32),
            assurance,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_rejects_downgrade_and_replay() {
        assert_eq!(
            VersionPolicyValidator::evaluate(3, 1),
            VersionPolicyDecision::RejectedDowngrade { current: 3, target: 1 }
        );
        assert_eq!(
            VersionPolicyValidator::evaluate(2, 2),
            VersionPolicyDecision::RejectedReplaySameVersion { version: 2 }
        );
        assert_eq!(
            VersionPolicyValidator::evaluate(1, 2),
            VersionPolicyDecision::AllowedUpgrade { increment: 1 }
        );
    }

    /// Bất biến trung tâm: software_current < tpm_counter là snapshot rollback
    /// (HCE-5) — phải phát hiện bất kể target có hợp lệ hay không.
    #[test]
    fn hardware_counter_contradiction_always_wins() {
        // Software behind counter: rollback detected
        assert!(matches!(
            VersionPolicyValidator::evaluate_with_hardware_counter(
                40,
                41,
                42,
                crate::trust::tpm::TpmAssuranceType::HardwareBacked
            ),
            HardwareVersionDecision::ContradictionRollbackDetected { .. }
        ));
        // Kể cả khi target trùng counter (không "lùi" theo software):
        // chỉ khi software_current == counter mới được advance an toàn
        let ok = VersionPolicyValidator::evaluate_with_hardware_counter(
            42,
            43,
            42,
            crate::trust::tpm::TpmAssuranceType::HardwareBacked
        );
        assert!(matches!(ok, HardwareVersionDecision::AllowedUpgradeWithCommitMarker { .. }));
    }
}