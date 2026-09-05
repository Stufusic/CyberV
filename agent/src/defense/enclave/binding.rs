//! Identity Binding Proof between TPM 2.0 and VBS Enclave (FSE-4)
//!
//! Ref: Docs/rv11.md Section 5:
//! "Identity Binding Proof: Chứng minh rằng khóa trong Enclave được ràng buộc mật thiết
//! với TPM 2.0 PCR commitment (chứ không phải 2 hệ thống rời rạc).
//! Dùng SHA-512 (NSA Suite B / CNSA)."

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fmt::Write;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBindingProof {
    pub tpm_ak_pub_sha512: String,
    pub pcr_digest_sha512: String,
    pub enclave_pubkey_sha512: String,
    pub binding_nonce_hex: String,
    pub combined_proof_digest: String,
}

pub struct IdentityBindingEngine;

impl IdentityBindingEngine {
    /// Tính toán SHA-512 digest từ một byte slice
    pub fn compute_sha512_hex(data: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(data);
        bytes_to_hex(&hasher.finalize())
    }

    /// Ràng buộc khóa định danh TPM với khóa Enclave thông qua Nonce và PCR commitment
    pub fn create_binding(
        tpm_ak_pub: &[u8],
        pcr_digest: &[u8],
        enclave_pubkey: &[u8],
        nonce: &[u8; 32],
    ) -> IdentityBindingProof {
        let tpm_ak_pub_sha512 = Self::compute_sha512_hex(tpm_ak_pub);
        let pcr_digest_sha512 = Self::compute_sha512_hex(pcr_digest);
        let enclave_pubkey_sha512 = Self::compute_sha512_hex(enclave_pubkey);
        let binding_nonce_hex = bytes_to_hex(nonce);

        // Combined proof: H(tpm_ak || pcr_digest || enclave_pubkey || nonce)
        let mut hasher = Sha512::new();
        hasher.update(tpm_ak_pub);
        hasher.update(pcr_digest);
        hasher.update(enclave_pubkey);
        hasher.update(nonce);
        let combined_proof_digest = bytes_to_hex(&hasher.finalize());

        IdentityBindingProof {
            tpm_ak_pub_sha512,
            pcr_digest_sha512,
            enclave_pubkey_sha512,
            binding_nonce_hex,
            combined_proof_digest,
        }
    }

    /// Kiểm tra tính toàn vẹn của Identity Binding Proof
    pub fn verify_binding(
        proof: &IdentityBindingProof,
        tpm_ak_pub: &[u8],
        pcr_digest: &[u8],
        enclave_pubkey: &[u8],
        nonce: &[u8; 32],
    ) -> bool {
        // Kiểm tra từng hash thành phần
        if proof.tpm_ak_pub_sha512 != Self::compute_sha512_hex(tpm_ak_pub) {
            return false;
        }
        if proof.pcr_digest_sha512 != Self::compute_sha512_hex(pcr_digest) {
            return false;
        }
        if proof.enclave_pubkey_sha512 != Self::compute_sha512_hex(enclave_pubkey) {
            return false;
        }
        if proof.binding_nonce_hex != bytes_to_hex(nonce) {
            return false;
        }

        // Kiểm tra digest tổng hợp
        let mut hasher = Sha512::new();
        hasher.update(tpm_ak_pub);
        hasher.update(pcr_digest);
        hasher.update(enclave_pubkey);
        hasher.update(nonce);
        let expected = bytes_to_hex(&hasher.finalize());

        proof.combined_proof_digest == expected
    }
}
