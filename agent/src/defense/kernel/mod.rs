//! Kernel Tamper Resistance (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! Process registration integrity, ObCallbacks telemetry, Vault Shield, Degradation detection.

pub mod anti_tamper;
pub mod registration;
pub mod telemetry;
pub mod vault_shield;

pub use anti_tamper::{AntiTamperManager, AntiTamperReport, KERNEL_TAMPER_DERIVATION_VERSION};
pub use registration::ProtectedProcessRegistration;
pub use telemetry::{HandleOperationResult, ShieldTelemetry};
pub use vault_shield::{VaultShield, VaultShieldError};
