//! Firmware Configuration & OEM Signature (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! "Firmware Configuration: version, vendor, update state."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareConfigReport {
    pub bios_vendor: String,
    pub bios_version: String,
    pub release_date: String,
    pub is_oem_signed: bool,
}

impl FirmwareConfigReport {
    pub fn standard_asus() -> Self {
        Self {
            bios_vendor: "American Megatrends Inc. (ASUS ROG)".to_string(),
            bios_version: "2103".to_string(),
            release_date: "2024-08-15".to_string(),
            is_oem_signed: true,
        }
    }

    pub fn unverified_vendor() -> Self {
        Self {
            bios_vendor: "Custom Modded BIOS".to_string(),
            bios_version: "0.0.1".to_string(),
            release_date: "Unknown".to_string(),
            is_oem_signed: false,
        }
    }

    pub fn security_score(&self) -> u32 {
        if self.is_oem_signed {
            10000
        } else {
            3000
        }
    }
}
