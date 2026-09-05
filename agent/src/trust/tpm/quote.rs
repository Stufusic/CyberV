//! TPM 2.0 Attestation Quote & Replay Protection (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 8:
//! "Attestation payload must bind: nonce, device_id, protocol_version,
//! PCR selection, measurement digest. Chống replay."

use super::errors::TpmError;
use super::pcr::{PcrBank, PcrPolicy};
use crate::fingerprint::canonical::CanonicalEncoder;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_TPM_QUOTE: &[u8] = b"CYBERV/DBS/TPM_QUOTE/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmAttestationPayload {
    pub protocol_version: u32,
    pub device_id: String,
    pub nonce: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub pcr_composite_digest: String,
    pub timestamp: u64,
}

impl TpmAttestationPayload {
    /// Tính toán chuỗi byte chính tắc (Canonical Bytes) trước khi ký
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.add_field("device_id", &self.device_id);
        encoder.add_field("nonce", &self.nonce);
        encoder.add_field("pcr_composite_digest", &self.pcr_composite_digest);
        encoder.add_field("policy_id", &self.policy_id);
        encoder.add_field("policy_version", &self.policy_version.to_string());
        encoder.add_field("protocol_version", &self.protocol_version.to_string());
        encoder.add_field("timestamp", &self.timestamp.to_string());

        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_TPM_QUOTE);
        hasher.update(encoder.to_canonical_bytes());
        hasher.finalize().to_vec()
    }
}

/// Gói tin TPM Quote hoàn chỉnh gồm payload và chữ ký phần cứng
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmQuote {
    pub payload: TpmAttestationPayload,
    pub signature_hex: String,
    pub tpm_public_key_hex: String,
}

impl TpmQuote {
    /// Tạo TPM Quote từ chính sách PCR, ngân hàng PCR và khóa ký
    pub fn generate(
        device_id: impl Into<String>,
        nonce: impl Into<String>,
        policy: &PcrPolicy,
        pcr_bank: &PcrBank,
        timestamp: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, TpmError> {
        let pcr_composite_digest = policy.compute_composite_digest(pcr_bank)?;
        let payload = TpmAttestationPayload {
            protocol_version: 1,
            device_id: device_id.into(),
            nonce: nonce.into(),
            policy_id: policy.policy_id.clone(),
            policy_version: policy.policy_version,
            pcr_composite_digest,
            timestamp,
        };

        let digest_to_sign = payload.to_canonical_bytes();
        let signature = ed25519_dalek::Signer::sign(signing_key, &digest_to_sign);
        let verifying_key = signing_key.verifying_key();
        let tpm_public_key_hex = encode_hex(verifying_key.as_bytes());

        Ok(Self {
            payload,
            signature_hex: encode_hex(&signature.to_bytes()),
            tpm_public_key_hex,
        })
    }

    /// Xác minh tính hợp lệ của TPM Quote (chữ ký, nonce, pcr digest)
    pub fn verify(
        &self,
        expected_nonce: &str,
        expected_device_id: &str,
        policy: &PcrPolicy,
        pcr_bank: &PcrBank,
    ) -> Result<bool, TpmError> {
        // 1. Chống replay nonce
        if self.payload.nonce != expected_nonce {
            return Err(TpmError::NonceMismatch);
        }

        // 2. Ràng buộc device_id
        if self.payload.device_id != expected_device_id {
            return Err(TpmError::QuoteVerificationFailed(
                "Device ID mismatch in TPM Quote".to_string(),
            ));
        }

        // 3. Xác minh PCR composite digest
        let expected_pcr_digest = policy.compute_composite_digest(pcr_bank)?;
        if self.payload.pcr_composite_digest != expected_pcr_digest {
            return Err(TpmError::PcrMismatch {
                expected: expected_pcr_digest,
                actual: self.payload.pcr_composite_digest.clone(),
            });
        }

        // 4. Giải mã và xác thực chữ ký Ed25519
        let pub_key_bytes = hex_to_bytes32(&self.tpm_public_key_hex).ok_or_else(|| {
            TpmError::QuoteVerificationFailed("Invalid public key hex format".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes).map_err(|e| {
            TpmError::QuoteVerificationFailed(format!("Invalid verifying key: {}", e))
        })?;

        let sig_bytes = hex_to_bytes64(&self.signature_hex).ok_or_else(|| {
            TpmError::QuoteVerificationFailed("Invalid signature hex format".to_string())
        })?;
        let signature = Signature::from_bytes(&sig_bytes);

        let digest_to_sign = self.payload.to_canonical_bytes();
        verifying_key
            .verify_strict(&digest_to_sign, &signature)
            .map_err(|e| TpmError::QuoteVerificationFailed(format!("Signature mismatch: {}", e)))?;

        Ok(true)
    }
}

// Helpers hex decoder
fn hex_to_bytes32(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn hex_to_bytes64(hex_str: &str) -> Option<[u8; 64]> {
    if hex_str.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for i in 0..64 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
