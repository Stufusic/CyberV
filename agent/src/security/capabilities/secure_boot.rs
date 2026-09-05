//! Secure Boot & Firmware Capabilities (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 4:
//! Secure Boot PK, KEK, db, dbx revocation precedence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootCapabilities {
    pub uefi_mode: bool,
    pub secure_boot_enabled: bool,
    pub pk_enrolled: bool,
    pub kek_count: u32,
    pub db_count: u32,
    pub dbx_count: u32,
}

impl SecureBootCapabilities {
    pub fn probe() -> Self {
        Self {
            uefi_mode: true,
            secure_boot_enabled: true,
            pk_enrolled: true,
            kek_count: 2,
            db_count: 5,
            dbx_count: 382, // Standard Windows dbx revocation count
        }
    }

    pub fn legacy_bios() -> Self {
        Self {
            uefi_mode: false,
            secure_boot_enabled: false,
            pk_enrolled: false,
            kek_count: 0,
            db_count: 0,
            dbx_count: 0,
        }
    }
}
