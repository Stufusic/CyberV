//! System Management Mode (SMM) Security (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! "SMM Security: SMM protection state, SMM core lockdown.
//! ĐẶC BIỆT: Không đặt SMI frequency thành security primitive chính vì rất noisy.
//! SMI anomaly chỉ tạo LOW confidence, KHÔNG quy kết FIRMWARE COMPROMISED."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmmSecurityReport {
    pub smm_core_lockdown: bool,
    pub smm_driver_verification: bool,
    pub smm_mitigation_active: bool,
    /// Độ tin cậy đo lường SMI (0 - 10000, giữ ở mức Low/Medium do tính noisy)
    pub smi_telemetry_confidence: u16,
    pub has_smi_frequency_anomaly: bool,
}

impl SmmSecurityReport {
    pub fn hardened() -> Self {
        Self {
            smm_core_lockdown: true,
            smm_driver_verification: true,
            smm_mitigation_active: true,
            smi_telemetry_confidence: 6000,
            has_smi_frequency_anomaly: false,
        }
    }

    pub fn unconstrained() -> Self {
        Self {
            smm_core_lockdown: false,
            smm_driver_verification: false,
            smm_mitigation_active: false,
            smi_telemetry_confidence: 2000,
            has_smi_frequency_anomaly: false,
        }
    }

    pub fn security_score(&self) -> u32 {
        let mut score: u32 = 0;
        if self.smm_core_lockdown {
            score += 4000;
        }
        if self.smm_driver_verification {
            score += 3000;
        }
        if self.smm_mitigation_active {
            score += 3000;
        }

        // Nếu có SMI anomaly, chỉ giảm nhẹ confidence chứ không đánh sập hệ thống
        if self.has_smi_frequency_anomaly {
            score = score.saturating_sub(1000);
        }

        score.min(10000)
    }
}
