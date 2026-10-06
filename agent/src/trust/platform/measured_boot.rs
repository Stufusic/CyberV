// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
