//! Platform State & TPM Recovery Transition (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 9:
//! "TPM Recovery: BIOS update / PCR changed xử lý qua Platform Transition, không phá hủy thiết bị."

use super::measured_boot::PlatformMeasurement;
use super::secure_boot::SecureBootStatus;
use crate::trust::tpm::capability::TpmStatus;
use crate::trust::tpm::TpmError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformTrustState {
    pub tpm_status: TpmStatus,
    pub secure_boot: SecureBootStatus,
    pub measurement: Option<PlatformMeasurement>,
    pub assurance_score: u32, // 0 - 10000
}

impl PlatformTrustState {
    pub fn evaluate(
        tpm_status: TpmStatus,
        secure_boot: SecureBootStatus,
        measurement: Option<PlatformMeasurement>,
    ) -> Self {
        let mut score: u32 = 0;

        // 1. Điểm cốt lõi từ TPM (Tối đa 6000)
        match tpm_status {
            TpmStatus::TpmPresent => score += 6000,
            TpmStatus::TpmDegraded => score += 3000,
            TpmStatus::TpmUnavailable => score += 2000, // Software baseline
        }

        // 2. Điểm từ Secure Boot (Tối đa 2500)
        match secure_boot {
            SecureBootStatus::Enabled => score += 2500,
            SecureBootStatus::Unknown => score += 1000,
            SecureBootStatus::Disabled => {}
        }

        // 3. Điểm từ Measured Boot (Tối đa 1500)
        if measurement.is_some() {
            score += 1500;
        }

        if score > 10000 {
            score = 10000;
        }

        Self {
            tpm_status,
            secure_boot,
            measurement,
            assurance_score: score,
        }
    }
}

/// Bộ xử lý chuyển đổi nền tảng khi có cập nhật Firmware/BIOS hợp lệ
pub struct TpmRecoveryHandler;

impl TpmRecoveryHandler {
    /// Xác minh chuyển đổi trạng thái PCR khi cập nhật firmware
    pub fn validate_firmware_transition(
        current_pcr_digest: &str,
        expected_old_pcr: &str,
        new_firmware_authorized: bool,
    ) -> Result<bool, TpmError> {
        if current_pcr_digest == expected_old_pcr {
            // Không có sự thay đổi PCR
            return Ok(true);
        }

        // PCR đã thay đổi (ví dụ: do cập nhật BIOS/Firmware)
        if new_firmware_authorized {
            // Quá trình chuyển đổi được quản trị viên hoặc chứng chỉ OEM phê chuẩn
            Ok(true)
        } else {
            Err(TpmError::PlatformTransitionRejected(
                "Phát hiện PCR thay đổi nhưng không có phê duyệt nâng cấp Firmware hợp lệ"
                    .to_string(),
            ))
        }
    }
}
