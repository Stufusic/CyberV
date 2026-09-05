//! Measured Boot Platform Measurement (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 7:
//! "PlatformMeasurement: pcr_digest, boot_log_digest, secure_boot, policy_version."

use super::boot_log::BootConfigurationLog;
use super::secure_boot::SecureBootStatus;
use crate::trust::tpm::pcr::{PcrBank, PcrPolicy};
use crate::trust::tpm::TpmError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformMeasurement {
    pub pcr_digest: String,
    pub boot_log_digest: String,
    pub secure_boot: bool,
    pub policy_version: u32,
}

impl PlatformMeasurement {
    pub fn collect(
        policy: &PcrPolicy,
        pcr_bank: &PcrBank,
        boot_log: &BootConfigurationLog,
        secure_boot_status: SecureBootStatus,
    ) -> Result<Self, TpmError> {
        let pcr_digest = policy.compute_composite_digest(pcr_bank)?;
        let secure_boot = secure_boot_status == SecureBootStatus::Enabled;

        Ok(Self {
            pcr_digest,
            boot_log_digest: boot_log.composite_digest.clone(),
            secure_boot,
            policy_version: policy.policy_version,
        })
    }
}
