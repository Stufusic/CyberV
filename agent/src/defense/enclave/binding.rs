// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
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

        // Combined proof: H(len(tpm_ak)||tpm_ak || len(pcr)||pcr || len(ak)||ak || nonce)
        // M6/L6 fix: length-prefix mọi thành phần — không thể nhập nhằng ranh giới
        // giữa các byte-array có nội dung khác nhau.
        let combined_proof_digest = compute_combined_digest(
            tpm_ak_pub,
            pcr_digest,
            enclave_pubkey,
            nonce,
        );

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

        // Kiểm tra digest tổng hợp (cùng encoding length-prefixed khi tạo)
        let expected = compute_combined_digest(tpm_ak_pub, pcr_digest, enclave_pubkey, nonce);

        proof.combined_proof_digest == expected
    }
}

/// H(len(a)||a || len(b)||b || len(c)||c || nonce) — canonical, không nhập nhằng
fn compute_combined_digest(
    tpm_ak_pub: &[u8],
    pcr_digest: &[u8],
    enclave_pubkey: &[u8],
    nonce: &[u8; 32],
) -> String {
    let mut hasher = Sha512::new();
    for part in [tpm_ak_pub, pcr_digest, enclave_pubkey] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hasher.update(nonce);
    bytes_to_hex(&hasher.finalize())
}
