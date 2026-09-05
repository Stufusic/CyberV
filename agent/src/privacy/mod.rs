//! Zero-Knowledge Device Attestation & Privacy Layer (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 32-39:
//! Statement, Witness, Circuit, ZK Prover, ZK Verifier, Selective Disclosure.

pub mod circuit;
pub mod prover;
pub mod selective;
pub mod statement;
pub mod verifier;
pub mod witness;

pub use circuit::{CircuitError, CircuitEvaluationResult, HardwareCircuit, CIRCUIT_VERSION};
pub use prover::{ProverError, ZkProof, ZkProver};
pub use selective::{
    DisclosedAttribute, SelectiveDisclosureClaim, SelectiveDisclosureEngine,
    SelectiveDisclosureError,
};
pub use statement::{DevicePolicy, DeviceStatement};
pub use verifier::{NonceTracker, VerifierError, ZkVerifier};
pub use witness::{HardwareLeafWitness, HardwareWitness};
