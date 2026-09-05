//! CyberV Trust & Hardware Root of Trust Subsystem (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! TPM 2.0 Root of Trust, Measured Boot, PCR Policies, Platform Attestation.

pub mod identity;
pub mod platform;
pub mod tpm;

pub use identity::{AssuranceLevel, HardwareIdentity, HybridDeviceIdentity, SoftwareIdentity};
pub use platform::{
    BootConfigurationLog, BootLogEntry, PlatformMeasurement, PlatformTrustState,
    SecureBootEvidence, SecureBootStatus, TpmRecoveryHandler,
};
pub use tpm::{
    HashAlgorithm, MockTpmDetector, MockTpmProvider, PcrBank, PcrPolicy, TpmAttestationPayload,
    TpmCapabilities, TpmDetector, TpmError, TpmIdentityKey, TpmProvider, TpmQuote, TpmStatus,
    WindowsTpmDetector,
};
