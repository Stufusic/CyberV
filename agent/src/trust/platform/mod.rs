//! Platform Trust Module (HCE-4)

pub mod boot_log;
pub mod measured_boot;
pub mod platform_state;
pub mod secure_boot;

pub use boot_log::{BootConfigurationLog, BootLogEntry};
pub use measured_boot::PlatformMeasurement;
pub use platform_state::{PlatformTrustState, TpmRecoveryHandler};
pub use secure_boot::{SecureBootEvidence, SecureBootStatus};
