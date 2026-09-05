//! Platform Boot Integrity (Intel Boot Guard / AMD PSB) (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! "Platform Boot Integrity: Intel Boot Guard, AMD platform security."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareBootTechnology {
    IntelBootGuard,
    AmdPlatformSecureBoot,
    UnknownOrNone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootGuardReport {
    pub technology: HardwareBootTechnology,
    pub is_fused: bool,
    pub verified_boot_enabled: bool,
    pub measured_boot_enabled: bool,
    pub oem_public_key_hash: String,
}

impl BootGuardReport {
    pub fn intel_boot_guard_profile5() -> Self {
        Self {
            technology: HardwareBootTechnology::IntelBootGuard,
            is_fused: true,
            verified_boot_enabled: true,
            measured_boot_enabled: true,
            oem_public_key_hash: "ibg_oem_key_hash_asus_z790_12345".to_string(),
        }
    }

    pub fn amd_psb_active() -> Self {
        Self {
            technology: HardwareBootTechnology::AmdPlatformSecureBoot,
            is_fused: true,
            verified_boot_enabled: true,
            measured_boot_enabled: true,
            oem_public_key_hash: "amd_psb_key_hash_lenovo_98765".to_string(),
        }
    }

    pub fn unconfigured() -> Self {
        Self {
            technology: HardwareBootTechnology::UnknownOrNone,
            is_fused: false,
            verified_boot_enabled: false,
            measured_boot_enabled: false,
            oem_public_key_hash: String::new(),
        }
    }

    pub fn security_score(&self) -> u32 {
        match self.technology {
            HardwareBootTechnology::IntelBootGuard
            | HardwareBootTechnology::AmdPlatformSecureBoot => {
                let mut score = 4000;
                if self.is_fused {
                    score += 2000;
                }
                if self.verified_boot_enabled {
                    score += 2000;
                }
                if self.measured_boot_enabled {
                    score += 2000;
                }
                score.min(10000)
            }
            HardwareBootTechnology::UnknownOrNone => 2000,
        }
    }
}
