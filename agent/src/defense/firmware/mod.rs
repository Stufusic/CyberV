//! Firmware & Platform Integrity (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! Decoupled 4 domains: Secure Boot (with dbx precedence), Boot Guard / PSB,
//! SMM security (non-alarmist SMI), and Firmware Configuration.

pub mod boot_guard;
pub mod config;
pub mod fusion;
pub mod secure_boot;
pub mod smm;

pub use boot_guard::{BootGuardReport, HardwareBootTechnology};
pub use config::FirmwareConfigReport;
pub use fusion::{
    FirmwareEvidenceFusionEngine, FirmwareSecurityReport, FIRMWARE_DERIVATION_VERSION,
};
pub use secure_boot::{ImageValidationResult, SecureBootDbReport};
pub use smm::SmmSecurityReport;
