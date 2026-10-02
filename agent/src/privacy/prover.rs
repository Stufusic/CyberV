//! Zero-Knowledge Device Prover (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 34 & 35:
//! Synthesizes private hardware witness into verifiable ZK proof
//! without leaking raw hardware serials or configuration details.

use super::circuit::{CircuitError, HardwareCircuit};
use super::statement::DevicePolicy;
use super::witness::HardwareWitness;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fmt::Write as _;
use thiserror::Error;

pub const DOMAIN_ZK_PROOF: &[u8] = b"CYBERV_ZK_DEVICE_PROOF_v1";

pub const DOMAIN_ZK_DEVICE_SIGNATURE: &[u8] = b"CYBERV_ZK_DEVICE_SIGNATURE_v1\0";

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Lỗi đánh giá mạch ràng buộc: {0}")]
    CircuitFailed(#[from] CircuitError),

    #[error("Không thể tạo bằng chứng: {0}")]
    GenerationFailed(String),
}

/// Bằng chứng Zero-Knowledge về sự tuân thủ chính sách phần cứng (ZK Device Proof)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof {
    pub proof_id: String,
    pub circuit_version: u32,
    pub public_root: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub nonce: String,
    /// Cam kết mật mã chứng minh (Proof Commitment - SHA-512)
    pub proof_commitment: String,
    /// Chữ ký Ed25519 của DEVICE IDENTITY KEY trên toàn bộ ngữ cảnh proof.
    /// H7 fix: "circuit" chỉ chạy trên máy prover nên commitment tự nó không có
    /// soundness (ai cũng tự tính được). Ký bằng khóa định danh thiết bị biến
    /// proof thành SIGNED ATTESTED CLAIM: chỉ thiết bị giữ khóa private mới
    /// sinh được proof hợp lệ cho commitment/nonce/root này.
    #[serde(default)]
    pub device_signature_hex: String,
    /// Bằng chứng nén nhị phân
    pub proof_bytes: Vec<u8>,
    pub issued_at: u64,
}

impl ZkProof {
    /// Byte payload mà device identity key ký — length-prefixed toàn bộ.
    pub fn canonical_device_signature_bytes(&self) -> Vec<u8> {
        fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN_ZK_DEVICE_SIGNATURE);
        msg.extend_from_slice(&self.circuit_version.to_be_bytes());
        push_field(&mut msg, self.public_root.as_bytes());
        push_field(&mut msg, self.policy_id.as_bytes());
        msg.extend_from_slice(&self.policy_version.to_be_bytes());
        push_field(&mut msg, self.nonce.as_bytes());
        push_field(&mut msg, self.proof_commitment.as_bytes());
        msg
    }
}

pub struct ZkProver;

impl ZkProver {
    /// Sinh bằng chứng từ nhân chứng phần cứng bí mật, ký bằng khóa định danh
    /// thiết bị (signed attested claim — xem `device_signature_hex`).
    pub fn prove(
        witness: &HardwareWitness,
        policy: &DevicePolicy,
        public_root: &str,
        nonce: &str,
        circuit_version: u32,
        device_identity_key: &SigningKey,
    ) -> Result<ZkProof, ProverError> {
        // 1. Đánh giá toàn bộ các ràng buộc trong mạch
        let eval_result =
            HardwareCircuit::evaluate(witness, policy, public_root, nonce, circuit_version)?;

        // 2. Tính toán Proof Commitment
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_ZK_PROOF);
        hasher.update(circuit_version.to_be_bytes());
        hasher.update((public_root.len() as u32).to_be_bytes());
        hasher.update(public_root.as_bytes());
        hasher.update((policy.policy_id.len() as u32).to_be_bytes());
        hasher.update(policy.policy_id.as_bytes());
        hasher.update(policy.version.to_be_bytes());
        hasher.update((nonce.len() as u32).to_be_bytes());
        hasher.update(nonce.as_bytes());
        hasher.update((eval_result.constraint_digest.len() as u32).to_be_bytes());
        hasher.update(eval_result.constraint_digest.as_bytes());

        let proof_commitment = format!("{:0128x}", hasher.finalize());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let proof_id = format!("zkproof:{}:{:x}", &proof_commitment[..16], now);

        let proof = ZkProof {
            proof_id,
            circuit_version,
            public_root: public_root.to_string(),
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
            nonce: nonce.to_string(),
            proof_commitment,
            device_signature_hex: String::new(),
            proof_bytes: Vec::new(),
            issued_at: now,
        };

        // Ký ngữ cảnh proof bằng khóa định danh thiết bị
        let signature = device_identity_key.sign(&proof.canonical_device_signature_bytes());
        let mut sig_hex = String::with_capacity(128);
        for b in signature.to_bytes() {
            let _ = write!(sig_hex, "{:02x}", b);
        }

        // Đóng gói proof_bytes chứa commitment và metadata
        let proof_payload = format!(
            "v={}&cr={}&pi={}&pv={}&n={}&c={}",
            circuit_version, public_root, policy.policy_id, policy.version, nonce, proof.proof_commitment
        );

        Ok(ZkProof {
            device_signature_hex: sig_hex,
            proof_bytes: proof_payload.into_bytes(),
            ..proof
        })
    }
}
