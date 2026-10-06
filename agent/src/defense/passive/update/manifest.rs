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
//! Update Package Manifest & Dual-Hash Signature (P24.8)
//!
//! Ref: Docs/rv13.md Section 7:
//! "Release signing key -> Manifest signature -> Package hash."
//!
//! INV-005 (Package Staging Gate): manifest chỉ được chấp nhận khi
//! (1) chữ ký Ed25519 của Release Authority được kiểm tra bằng khóa công khai
//!     được PIN CỐ ĐỊNH (không bao giờ tin khóa/nội dung do gói tự khai),
//! (2) băm SHA-512 trên byte gói thực tế khớp `package_sha512`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fmt::Write;

pub const DOMAIN_PACKAGE_MANIFEST: &[u8] = b"CYBERV/PKG/MANIFEST/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePackageManifest {
    pub version: u32,
    pub package_sha512: String,
    pub release_key_id: String,
    pub manifest_signature_hex: String,
    pub target_arch: String,
}

fn push_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

impl UpdatePackageManifest {
    /// Byte payload bất biến được Release Authority ký: mọi trường độ dài thay đổi
    /// đều prefix độ dài (u32 BE) để loại bỏ nhập nhằng phép nối chuỗi.
    pub fn canonical_signed_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN_PACKAGE_MANIFEST);
        msg.extend_from_slice(&self.version.to_be_bytes());
        push_len_prefixed(&mut msg, self.package_sha512.as_bytes());
        push_len_prefixed(&mut msg, self.release_key_id.as_bytes());
        push_len_prefixed(&mut msg, self.target_arch.as_bytes());
        msg
    }

    /// Ký manifest bằng Release Authority private key (dùng bởi release tooling).
    pub fn sign(mut self, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&self.canonical_signed_bytes());
        let mut hex = String::with_capacity(sig.to_bytes().len() * 2);
        for b in sig.to_bytes() {
            let _ = write!(hex, "{:02x}", b);
        }
        self.manifest_signature_hex = hex;
        self
    }

    /// Kiểm tra chữ ký manifest bằng Release Authority Public Key được PIN.
    /// Trả về false cho MỌI trường hợp: hex sai định dạng, chữ ký sai, khóa sai,
    /// hay nội dung manifest bị thay đổi sau khi ký.
    pub fn verify_signature(&self, trusted_release_public_key: &VerifyingKey) -> bool {
        let sig_bytes = match hex_decode_64(&self.manifest_signature_hex) {
            Some(b) => b,
            None => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        trusted_release_public_key
            .verify(&self.canonical_signed_bytes(), &signature)
            .is_ok()
    }

    /// Cổng ràng buộc gói (cột mốc thứ hai của chuỗi tin cậy): băm SHA-512 trên
    /// byte gói THỰC TẾ đã staged rồi đối chiếu với cam kết `package_sha512`.
    /// Manifest chữ ký hợp lệ nhưng gói lệch băm vẫn phải bị chặn ở đây.
    pub fn verify_package_binding(&self, actual_package_bytes: &[u8]) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(actual_package_bytes);
        let out = hasher.finalize();
        let mut hex = String::with_capacity(out.len() * 2);
        for b in out {
            let _ = write!(hex, "{:02x}", b);
        }
        hex.as_bytes() == self.package_sha512.to_ascii_lowercase().as_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn sample_manifest(key_id: &str) -> UpdatePackageManifest {
        UpdatePackageManifest {
            version: 2,
            package_sha512: "a".repeat(128),
            release_key_id: key_id.to_string(),
            manifest_signature_hex: String::new(),
            target_arch: "x86_64".to_string(),
        }
    }

    #[test]
    fn verify_signature_accepts_pinned_key() {
        let sk = test_key();
        let manifest = sample_manifest("release_key_2026_primary").sign(&sk);
        assert!(manifest.verify_signature(&sk.verifying_key()));
    }

    #[test]
    fn verify_signature_rejects_other_key() {
        let sk = test_key();
        let other = test_key();
        let manifest = sample_manifest("release_key_2026_primary").sign(&sk);
        assert!(!manifest.verify_signature(&other.verifying_key()));
    }

    #[test]
    fn verify_signature_rejects_tampered_field() {
        let sk = test_key();
        let mut manifest = sample_manifest("release_key_2026_primary").sign(&sk);
        manifest.version += 1;
        assert!(!manifest.verify_signature(&sk.verifying_key()));
    }

    #[test]
    fn verify_signature_rejects_garbage_hex() {
        let sk = test_key();
        let mut manifest = sample_manifest("release_key_2026_primary").sign(&sk);
        manifest.manifest_signature_hex = "zzzz".to_string();
        assert!(!manifest.verify_signature(&sk.verifying_key()));
    }

    #[test]
    fn package_binding_detects_substituted_bytes() {
        let sk = test_key();
        let pkg = b"legitimate package payload";
        let mut hasher = Sha512::new();
        hasher.update(pkg);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            let _ = write!(hex, "{:02x}", b);
        }
        let manifest = UpdatePackageManifest {
            version: 2,
            package_sha512: hex,
            release_key_id: "release_key_2026_primary".to_string(),
            manifest_signature_hex: String::new(),
            target_arch: "x86_64".to_string(),
        }
        .sign(&sk);

        assert!(manifest.verify_package_binding(pkg));
        assert!(!manifest.verify_package_binding(b"malicious payload"));
    }
}
