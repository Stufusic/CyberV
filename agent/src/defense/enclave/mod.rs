//! VBS-Isolated Security Core (FSE-4)
//!
//! Ref: Docs/rv11.md Section 5:
//! Enclave isolation, memory boundary defense, identity binding to TPM 2.0.

pub mod attestation;
pub mod binding;
pub mod boundary;
pub mod capability;

pub use attestation::{
    EnclaveAttestationEngine, EnclaveAttestationReport, EnclaveMeasurement,
    ENCLAVE_DERIVATION_VERSION,
};
pub use binding::{IdentityBindingEngine, IdentityBindingProof};
pub use boundary::{BoundaryError, SecureIsoBuffer, MAX_SECURE_PAYLOAD_SIZE};
pub use capability::{EnclaveCapabilityMatrix, EnclaveStatus};
