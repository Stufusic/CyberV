//! CyberV Transparency & Append-Only Log Subsystem (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8:
//! Merkle Mountain Range (MMR), Signed Checkpoints, Anti-Rogue-Admin Guard.

pub mod checkpoint;
pub mod event;
pub mod mmr;
pub mod proof;

pub use checkpoint::SignedCheckpoint;
pub use event::{EventType, RevocationEvent};
pub use mmr::{MerkleMountainRange, MmrInclusionProof, MmrProofStep};
pub use proof::{RevocationVerificationResult, RevocationVerifier};
