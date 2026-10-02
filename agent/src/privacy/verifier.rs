//! Zero-Knowledge Device Verifier (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 34, 38 & 39:
//! Verifies ZK proofs against public statement inputs:
//! root, policy_id, nonce freshness, anti-replay, and circuit version.

use super::circuit::CIRCUIT_VERSION;
use super::prover::ZkProof;
use super::statement::DevicePolicy;
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifierError {
    #[error("Phiên bản mạch không tương thích: mong muốn {expected}, nhận được {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Gốc Merkle của bằng chứng ({proof_root}) không khớp với kỳ vọng ({expected_root})")]
    RootMismatch {
        expected_root: String,
        proof_root: String,
    },

    #[error("Chính sách trong bằng chứng ({proof_policy} v{proof_version}) không khớp với kỳ vọng ({expected_policy} v{expected_version})")]
    PolicyMismatch {
        expected_policy: String,
        expected_version: u32,
        proof_policy: String,
        proof_version: u32,
    },

    #[error("Nonce thử thách ({proof_nonce}) không khớp với kỳ vọng ({expected_nonce})")]
    NonceMismatch {
        expected_nonce: String,
        proof_nonce: String,
    },

    #[error("Phát hiện tấn công phát lại (Replay Attack): Nonce '{0}' đã được sử dụng trước đó")]
    NonceReplayed(String),

    #[error("Bằng chứng bị hỏng hoặc cam kết không hợp lệ")]
    CorruptedProof,
    #[error("Chữ ký thiết bị trên proof không hợp lệ (không phải thiết bị giữ khóa private)")]
    DeviceSignatureInvalid,
}

/// Bộ theo dõi Nonce chống tấn công phát lại (Anti-Replay Nonce Tracker)
#[derive(Debug, Default, Clone)]
pub struct NonceTracker {
    used_nonces: HashSet<String>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self {
            used_nonces: HashSet::new(),
        }
    }

    pub fn is_used(&self, nonce: &str) -> bool {
        self.used_nonces.contains(nonce)
    }

    pub fn mark_used(&mut self, nonce: impl Into<String>) {
        self.used_nonces.insert(nonce.into());
    }
}

pub struct ZkVerifier;

impl ZkVerifier {
    /// Xác minh tính hợp lệ của bằng chứng Zero-Knowledge
    pub fn verify(
        proof: &ZkProof,
        expected_root: &str,
        expected_policy: &DevicePolicy,
        expected_nonce: &str,
        tracker: &mut NonceTracker,
        expected_device_pubkey: &VerifyingKey,
    ) -> Result<bool, VerifierError> {
        // 1. Kiểm tra phiên bản mạch (Không chấp nhận old circuit hoặc cross-version)
        if proof.circuit_version != CIRCUIT_VERSION {
            return Err(VerifierError::VersionMismatch {
                expected: CIRCUIT_VERSION,
                actual: proof.circuit_version,
            });
        }

        // 2. Chống Replay Attack: Kiểm tra xem Nonce đã từng được dùng chưa
        if tracker.is_used(&proof.nonce) {
            return Err(VerifierError::NonceReplayed(proof.nonce.clone()));
        }

        // 3. Kiểm tra tính khớp của Nonce
        if proof.nonce != expected_nonce {
            return Err(VerifierError::NonceMismatch {
                expected_nonce: expected_nonce.to_string(),
                proof_nonce: proof.nonce.clone(),
            });
        }

        // 4. Kiểm tra Public Root Merkle
        if proof.public_root != expected_root {
            return Err(VerifierError::RootMismatch {
                expected_root: expected_root.to_string(),
                proof_root: proof.public_root.clone(),
            });
        }

        // 5. Kiểm tra tính hợp lệ của Policy ID & Version
        if proof.policy_id != expected_policy.policy_id
            || proof.policy_version != expected_policy.version
        {
            return Err(VerifierError::PolicyMismatch {
                expected_policy: expected_policy.policy_id.clone(),
                expected_version: expected_policy.version,
                proof_policy: proof.policy_id.clone(),
                proof_version: proof.policy_version,
            });
        }

        // 6. Kiểm tra tính toàn vẹn của Proof Payload
        if proof.proof_commitment.len() != 128 || proof.proof_bytes.is_empty() {
            return Err(VerifierError::CorruptedProof);
        }

        let payload_str = match String::from_utf8(proof.proof_bytes.clone()) {
            Ok(s) => s,
            Err(_) => return Err(VerifierError::CorruptedProof),
        };

        if !payload_str.contains(&proof.proof_commitment) {
            return Err(VerifierError::CorruptedProof);
        }

        // 7. H7 fix: kiểm tra CHỮ KÝ DEVICE IDENTITY trên toàn bộ ngữ cảnh
        // proof. Commitment tự nó chỉ là hash các input công khai — không có
        // soundness; chỉ thiết bị giữ khóa private mới ký được binding này.
        let sig_bytes = hex_decode_64(&proof.device_signature_hex)
            .ok_or(VerifierError::DeviceSignatureInvalid)?;
        let signature = Signature::from_bytes(&sig_bytes);
        expected_device_pubkey
            .verify_strict(&proof.canonical_device_signature_bytes(), &signature)
            .map_err(|_| VerifierError::DeviceSignatureInvalid)?;

        // Đánh dấu Nonce đã được tiêu thụ thành công (chỉ sau khi mọi kiểm tra pass)
        tracker.mark_used(expected_nonce);

        Ok(true)
    }
}

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    let bytes = s.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 64];
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
    }
    Some(out)
}
