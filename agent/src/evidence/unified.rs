//! Unified Evidence Object (HCE Section 51)
//!
//! Ref: Docs/rv10.md Section 51:
//! "Tất cả HCE phải trả về một format chung: EvidenceItem.
//! TPM evidence, Temporal evidence, Kernel evidence, Constraint evidence,
//! Topology evidence, Merkle evidence đều trở thành EvidenceItem."

use crate::hardware::models::Confidence;
use serde::{Deserialize, Serialize};

/// Phân lớp bằng chứng (Evidence Classes - Section 52)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceClass {
    Cryptographic,
    Hardware,
    Structural,
    Temporal,
    Platform,
    Behavioral,
}

impl std::fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceClass::Cryptographic => write!(f, "CRYPTOGRAPHIC"),
            EvidenceClass::Hardware => write!(f, "HARDWARE"),
            EvidenceClass::Structural => write!(f, "STRUCTURAL"),
            EvidenceClass::Temporal => write!(f, "TEMPORAL"),
            EvidenceClass::Platform => write!(f, "PLATFORM"),
            EvidenceClass::Behavioral => write!(f, "BEHAVIORAL"),
        }
    }
}

/// Nguồn gốc bằng chứng
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    TpmRootOfTrust,
    TemporalDrift,
    KernelObservation,
    PhysicalConstraints,
    HardwareTopology,
    MerkleGraph,
    VerifiableLog,
    ZeroKnowledgeProof,
    // FSE-1 to FSE-4 Defense Engines
    KernelTamperResistance,
    DmaIommuProtection,
    FirmwarePlatformIntegrity,
    VbsEnclaveCore,
    // Passive Defense Foundation (Phase 24)
    PassiveProcessMitigation,
}

/// Thực thể bằng chứng hợp nhất (Unified Evidence Item)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub evidence_type: String,
    pub evidence_class: EvidenceClass,
    pub schema_version: u32,
    pub derivation_version: u32,
    pub source: EvidenceSource,
    /// Cam kết mật mã (SHA-512 Hex)
    pub commitment: String,
    pub confidence: Confidence,
    /// Điểm đánh giá (0 - 10000)
    pub score: u32,
}

impl EvidenceItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        evidence_type: impl Into<String>,
        evidence_class: EvidenceClass,
        schema_version: u32,
        derivation_version: u32,
        source: EvidenceSource,
        commitment: impl Into<String>,
        confidence: Confidence,
        score: u32,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            evidence_type: evidence_type.into(),
            evidence_class,
            schema_version,
            derivation_version,
            source,
            commitment: commitment.into(),
            confidence,
            score: score.min(10000),
        }
    }
}
