//! Private Hardware Witness (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 35:
//! Private Witness: Hardware leaves, Merkle inclusion paths, virtual evidence,
//! constraint metrics, and blinding factor.

use crate::evidence::merkle::proof::MerkleInclusionProof;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareLeafWitness {
    pub label: String,
    pub canonical_id: String,
    pub leaf_hash_hex: String,
    pub proof: MerkleInclusionProof,
}

/// Nhân chứng bằng chứng phần cứng riêng tư (Private Witness)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareWitness {
    pub leaves: Vec<HardwareLeafWitness>,
    pub tpm_active: bool,
    pub kernel_consistent: bool,
    pub cpu_family: String,
    pub total_memory_bytes: u64,
    /// Hệ số làm mờ bí mật (Blinding Factor) bảo đảm Zero-Knowledge
    pub blinding_factor: String,
}

impl HardwareWitness {
    pub fn new(
        leaves: Vec<HardwareLeafWitness>,
        tpm_active: bool,
        kernel_consistent: bool,
        cpu_family: impl Into<String>,
        total_memory_bytes: u64,
        blinding_factor: impl Into<String>,
    ) -> Self {
        Self {
            leaves,
            tpm_active,
            kernel_consistent,
            cpu_family: cpu_family.into(),
            total_memory_bytes,
            blinding_factor: blinding_factor.into(),
        }
    }
}
