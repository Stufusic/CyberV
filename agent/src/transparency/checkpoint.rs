// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
//! Signed Transparency Log Checkpoint (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8 Section 44:
//! "Checkpoint: log_id, tree_size, mmr_root, timestamp, authority_signature."

use crate::fingerprint::canonical::CanonicalEncoder;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_CHECKPOINT: &[u8] = b"CYBERV/DBS/CHECKPOINT/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub log_id: String,
    pub tree_size: u64,
    pub mmr_root: String,
    pub timestamp: u64,
    pub authority_signature_hex: String,
    pub authority_public_key_hex: String,
}

impl SignedCheckpoint {
    /// Tính toán chuỗi byte chính tắc trước khi ký
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.add_field("log_id", &self.log_id);
        encoder.add_field("mmr_root", &self.mmr_root);
        encoder.add_field("timestamp", &self.timestamp.to_string());
        encoder.add_field("tree_size", &self.tree_size.to_string());

        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_CHECKPOINT);
        hasher.update(encoder.to_canonical_bytes());
        hasher.finalize().to_vec()
    }

    /// Ký phát hành checkpoint mới bằng khóa thẩm quyền của Server (Authority Key)
    pub fn sign(
        log_id: impl Into<String>,
        tree_size: u64,
        mmr_root: impl Into<String>,
        timestamp: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let log_id_str = log_id.into();
        let mmr_root_str = mmr_root.into();

        let mut encoder = CanonicalEncoder::new();
        encoder.add_field("log_id", &log_id_str);
        encoder.add_field("mmr_root", &mmr_root_str);
        encoder.add_field("timestamp", &timestamp.to_string());
        encoder.add_field("tree_size", &tree_size.to_string());

        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_CHECKPOINT);
        hasher.update(encoder.to_canonical_bytes());
        let digest_to_sign = hasher.finalize();

        let signature = signing_key.sign(&digest_to_sign);
        let verifying_key = signing_key.verifying_key();

        let authority_signature_hex = signature
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let authority_public_key_hex = verifying_key
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        Self {
            log_id: log_id_str,
            tree_size,
            mmr_root: mmr_root_str,
            timestamp,
            authority_signature_hex,
            authority_public_key_hex,
        }
    }

    /// Xác minh tính TỰ-NHẤT QUÁN của chữ ký trên Checkpoint (khóa nhúng trong
    /// checkpoint tự xác minh chính nó). CHỈ dùng cho kiểm tra cấu trúc/số học —
    /// TUYỆT ĐỐI không dùng làm quyết định an ninh: bất kỳ ai cũng tự sinh keypair
    /// rồi tự ký checkpoint hợp lệ (rogue-key bypass). Quyết định tin cậy phải
    /// qua `verify_with_pinned_authority`.
    pub fn verify(&self) -> bool {
        let pub_key_bytes = match hex_to_bytes32(&self.authority_public_key_hex) {
            Some(b) => b,
            None => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pub_key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let sig_bytes = match hex_to_bytes64(&self.authority_signature_hex) {
            Some(b) => b,
            None => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);

        let digest = self.to_canonical_bytes();
        verifying_key.verify(&digest, &signature).is_ok()
    }

    /// Xác minh Checkpoint bằng KHÓA THẨM QUYỀN ĐƯỢC PIN CỐ ĐỊNH (HCE-8).
    /// Khóa công khai nhúng trong checkpoint buộc phải trùng khớp khóa thẩm quyền
    /// đã pin — chặn triệt để rogue-key: attacker tự sinh keypair và tự ký
    /// checkpoint sẽ bị từ chối tại bước so khớp khóa trước cả khi verify chữ ký.
    pub fn verify_with_pinned_authority(&self, pinned_authority_key: &VerifyingKey) -> bool {
        let embedded = match hex_to_bytes32(&self.authority_public_key_hex) {
            Some(b) => b,
            None => return false,
        };
        if embedded != *pinned_authority_key.as_bytes() {
            return false;
        }
        self.verify()
    }
}

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
