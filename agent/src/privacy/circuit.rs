//! Hardware Constraint Circuit (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 33 & 35:
//! Circuit Versioning, Public Inputs, Private Witness Constraints, Merkle Verification.

use super::statement::DevicePolicy;
use super::witness::HardwareWitness;
use sha2::{Digest, Sha512};
use thiserror::Error;

pub const CIRCUIT_VERSION: u32 = 1;
pub const DOMAIN_CIRCUIT_EVALUATION: &[u8] = b"CYBERV_CIRCUIT_EVALUATION_v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitError {
    #[error("Phiên bản mạch không tương thích: mong muốn {expected}, nhận được {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Gốc Merkle của bằng chứng không khớp với Public Root: {0}")]
    MerkleRootMismatch(String),

    #[error("Bằng chứng Merkle của linh kiện '{0}' không hợp lệ")]
    InvalidMerkleProof(String),

    #[error("Chính sách yêu cầu TPM 2.0 hợp lệ nhưng nhân chứng không đạt")]
    TpmRequirementFailed,

    #[error("Chính sách yêu cầu tính nhất quán Kernel Probe nhưng nhân chứng không đạt")]
    KernelRequirementFailed,

    #[error("Dung lượng bộ nhớ {actual} bytes nhỏ hơn mức tối thiểu yêu cầu {required} bytes")]
    InsufficientMemory { required: u64, actual: u64 },

    #[error("Họ CPU '{0}' không nằm trong danh sách cho phép của chính sách")]
    CpuFamilyNotAllowed(String),

    #[error("Nonce thử thách rỗng hoặc không hợp lệ")]
    InvalidNonce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitEvaluationResult {
    pub circuit_version: u32,
    pub constraints_satisfied: bool,
    pub constraint_digest: String,
}

pub struct HardwareCircuit;

impl HardwareCircuit {
    /// Đánh giá các ràng buộc phần cứng bí mật dựa trên Public Statement và Private Witness
    pub fn evaluate(
        witness: &HardwareWitness,
        policy: &DevicePolicy,
        public_root: &str,
        nonce: &str,
        circuit_version: u32,
    ) -> Result<CircuitEvaluationResult, CircuitError> {
        if circuit_version != CIRCUIT_VERSION {
            return Err(CircuitError::VersionMismatch {
                expected: CIRCUIT_VERSION,
                actual: circuit_version,
            });
        }

        if nonce.trim().is_empty() {
            return Err(CircuitError::InvalidNonce);
        }

        // 1. Ràng buộc Merkle: Mọi lá linh kiện phải có bằng chứng bao hàm hợp lệ dẫn đến public_root
        if witness.leaves.is_empty() {
            return Err(CircuitError::MerkleRootMismatch(
                "Không có lá linh kiện nào trong nhân chứng".to_string(),
            ));
        }

        for leaf in &witness.leaves {
            if leaf.proof.root_hash_hex != public_root {
                return Err(CircuitError::MerkleRootMismatch(format!(
                    "Leaf {} root {} != expected {}",
                    leaf.label, leaf.proof.root_hash_hex, public_root
                )));
            }
            if !leaf.proof.verify() {
                return Err(CircuitError::InvalidMerkleProof(leaf.label.clone()));
            }
        }

        // 2. Ràng buộc TPM
        if policy.require_tpm && !witness.tpm_active {
            return Err(CircuitError::TpmRequirementFailed);
        }

        // 3. Ràng buộc Kernel Cross-Validation
        if policy.require_kernel_consistent && !witness.kernel_consistent {
            return Err(CircuitError::KernelRequirementFailed);
        }

        // 4. Ràng buộc bộ nhớ RAM
        if policy.min_memory_bytes > 0 && witness.total_memory_bytes < policy.min_memory_bytes {
            return Err(CircuitError::InsufficientMemory {
                required: policy.min_memory_bytes,
                actual: witness.total_memory_bytes,
            });
        }

        // 5. Ràng buộc họ CPU
        if !policy.allowed_cpu_families.is_empty() {
            let cpu_matched = policy
                .allowed_cpu_families
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&witness.cpu_family));
            if !cpu_matched {
                return Err(CircuitError::CpuFamilyNotAllowed(
                    witness.cpu_family.clone(),
                ));
            }
        }

        // 6. Tính toán Constraint Digest (SHA-512 trên tất cả các kết quả ràng buộc)
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_CIRCUIT_EVALUATION);
        hasher.update(circuit_version.to_be_bytes());
        hasher.update((public_root.len() as u32).to_be_bytes());
        hasher.update(public_root.as_bytes());
        hasher.update((policy.policy_id.len() as u32).to_be_bytes());
        hasher.update(policy.policy_id.as_bytes());
        hasher.update(policy.version.to_be_bytes());
        hasher.update((nonce.len() as u32).to_be_bytes());
        hasher.update(nonce.as_bytes());
        hasher.update((witness.blinding_factor.len() as u32).to_be_bytes());
        hasher.update(witness.blinding_factor.as_bytes());

        let digest = format!("{:0128x}", hasher.finalize());

        Ok(CircuitEvaluationResult {
            circuit_version,
            constraints_satisfied: true,
            constraint_digest: digest,
        })
    }
}
