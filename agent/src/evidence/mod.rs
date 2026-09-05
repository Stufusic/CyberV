//! CyberV Hardware Evidence Engine (HCE)
//!
//! Ref: Docs/rv9.md:
//! HCE-1 — Physical Constraint Engine
//! HCE-2 — Hardware Topology Engine
//! HCE-3 — Merkle Evidence Engine & Selective Inclusion Proofs

pub mod constraints;
pub mod fusion;
pub mod merkle;
pub mod temporal;
pub mod topology;
pub mod unified;

pub use constraints::{
    ConstraintEvaluation, ConstraintEvaluator, ConstraintResult, PhysicalConstraintEngine,
    PhysicalConstraintReport,
};
pub use fusion::{EvidenceFusionEngine, EvidenceFusionReport, EvidenceRating};
pub use merkle::{
    generate_inclusion_proof, MerkleEvidenceTree, MerkleInclusionProof, MerkleNode,
    MerkleProofStep, MerkleSiblingDirection,
};
pub use topology::{
    BusNode, HardwareTopologyEngine, HardwareTopologyReport, MemoryChannel, MemoryChannelMode,
    MemoryTopology, PciLocation,
};
pub use unified::{EvidenceClass, EvidenceItem, EvidenceSource};
