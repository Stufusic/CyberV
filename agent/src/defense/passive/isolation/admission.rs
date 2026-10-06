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
//! Broker Policy Admission Control (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 6:
//! "SynchronizePolicy là attack surface rất lớn.
//! Broker không được tin Worker chỉ vì Worker đã qua handshake.
//! Broker phải độc lập kiểm tra Master signature, monotonic version, issuer, expiration, schema, invariants."

use super::protocol::MAX_IPC_FRAME_SIZE;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain separator của thông điệp ký chính sách (length-prefixed).
pub const DOMAIN_POLICY_ADMISSION: &[u8] = b"CYBERV/BROKER/POLICY/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyEnvelope {
    pub version: u32,
    pub issuer: String,
    pub tenant_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub policy_json: String,
    pub signature_hex: String,
}

impl SignedPolicyEnvelope {
    /// Byte payload canonical được Master Authority ký (M3 fix).
    ///
    /// Thay thế phép nối `"{}:{}:{}..."` không injective (tenant "a:b" có thể
    /// được diễn giải lại thành issuer "a" + tenant "b" với cùng chuỗi byte).
    /// Mọi trường độ dài thay đổi được prefix độ dài (u32 BE), số liệu fixed-width
    /// đặt theo thứ tự cố định — hai tập trường khác nhau không thể tạo cùng bytes.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN_POLICY_ADMISSION);
        msg.extend_from_slice(&self.version.to_be_bytes());
        push_field(&mut msg, self.issuer.as_bytes());
        push_field(&mut msg, self.tenant_id.as_bytes());
        msg.extend_from_slice(&self.not_before.to_be_bytes());
        msg.extend_from_slice(&self.not_after.to_be_bytes());
        push_field(&mut msg, self.policy_json.as_bytes());
        msg
    }

    /// Ký envelope bằng Master Authority private key (dùng bởi authority + test)
    pub fn sign_with(mut self, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&self.canonical_signing_bytes());
        self.signature_hex = encode_hex(&sig.to_bytes());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAdmissionError {
    OversizedPayload(usize),
    InvalidMasterSignature(String),
    VersionRollbackAttempt { current: u32, submitted: u32 },
    ExpiredPolicy { not_after: u64, now: u64 },
    PrematurePolicy { not_before: u64, now: u64 },
    TenantMismatch { expected: String, found: String },
    InvariantViolation(String),
    MalformedJson(String),
}

/// Bộ kiểm soát tiếp nhận chính sách độc lập trên tiến trình Core Broker
#[derive(Debug, Clone)]
pub struct BrokerPolicyAdmissionController {
    pub active_policy_version: u32,
    pub active_tenant_id: String,
    pub master_public_key: VerifyingKey,
}

impl BrokerPolicyAdmissionController {
    pub fn new(
        active_policy_version: u32,
        active_tenant_id: &str,
        master_public_key: VerifyingKey,
    ) -> Self {
        Self {
            active_policy_version,
            active_tenant_id: active_tenant_id.to_string(),
            master_public_key,
        }
    }

    /// Quy trình thẩm định 6 bước độc lập trước khi áp dụng chính sách vào Broker
    pub fn verify_and_admit(
        &mut self,
        signed_policy_bytes: &[u8],
        now: u64,
    ) -> Result<u32, PolicyAdmissionError> {
        // 1. Kiểm tra kích thước khung payload
        if signed_policy_bytes.len() > MAX_IPC_FRAME_SIZE {
            return Err(PolicyAdmissionError::OversizedPayload(
                signed_policy_bytes.len(),
            ));
        }

        // 2. Giải mã cấu trúc phong bì chính sách
        let envelope: SignedPolicyEnvelope = serde_json::from_slice(signed_policy_bytes)
            .map_err(|e| PolicyAdmissionError::MalformedJson(e.to_string()))?;

        // 3. Kiểm tra tính tăng đơn điệu của phiên bản (Strict Monotonic Anti-Rollback)
        if envelope.version <= self.active_policy_version {
            return Err(PolicyAdmissionError::VersionRollbackAttempt {
                current: self.active_policy_version,
                submitted: envelope.version,
            });
        }

        // 4. Kiểm tra Tenant ID
        if envelope.tenant_id != self.active_tenant_id {
            return Err(PolicyAdmissionError::TenantMismatch {
                expected: self.active_tenant_id.clone(),
                found: envelope.tenant_id,
            });
        }

        // 5. Kiểm tra thời hạn hiệu lực của chính sách
        if now < envelope.not_before {
            return Err(PolicyAdmissionError::PrematurePolicy {
                not_before: envelope.not_before,
                now,
            });
        }
        if now > envelope.not_after {
            return Err(PolicyAdmissionError::ExpiredPolicy {
                not_after: envelope.not_after,
                now,
            });
        }

        // 6. Kiểm tra Chữ ký số Master Authority Key (Ed25519)
        let signature_bytes = decode_hex(&envelope.signature_hex)
            .map_err(|e| PolicyAdmissionError::InvalidMasterSignature(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| PolicyAdmissionError::InvalidMasterSignature(e.to_string()))?;

        let canonical_bytes = envelope.canonical_signing_bytes();

        if self
            .master_public_key
            .verify_strict(&canonical_bytes, &signature)
            .is_err()
        {
            return Err(PolicyAdmissionError::InvalidMasterSignature(
                "Ed25519 signature verification failed".to_string(),
            ));
        }

        // 7. Kiểm tra các quy tắc an toàn bất biến (Invariant Validation)
        // Không cho phép bất kỳ chính sách nào hạ thấp rào chắn bảo vệ phần cứng.
        // Phân tích cấu trúc JSON đệ quy — substring matching có thể bị qua mặt
        // bằng biến thể whitespace/unicode escape trong JSON.
        let policy_tree: serde_json::Value = serde_json::from_str(&envelope.policy_json)
            .map_err(|e| PolicyAdmissionError::MalformedJson(e.to_string()))?;
        for forbidden in ["disable_tpm", "disable_driver", "disable_safe_mode"] {
            if json_contains_true_flag(&policy_tree, forbidden) {
                return Err(PolicyAdmissionError::InvariantViolation(format!(
                    "Chính sách không được phép vô hiệu hóa cờ bảo vệ bắt buộc: {}",
                    forbidden
                )));
            }
        }

        // Đạt toàn bộ kiểm tra: Cập nhật phiên bản chính sách mới
        self.active_policy_version = envelope.version;
        Ok(envelope.version)
    }
}

/// Duyệt đệ quy cây JSON tìm cờ bảo vệ có giá trị boolean `true` ở bất kỳ cấp nào
/// (bất chấp khoảng trắng, thứ tự khóa hay unicode escape của chuỗi JSON).
fn json_contains_true_flag(value: &serde_json::Value, flag_name: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k.eq_ignore_ascii_case(flag_name) && v == &serde_json::Value::Bool(true) {
                    return true;
                }
                if json_contains_true_flag(v, flag_name) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(items) => items.iter().any(|v| json_contains_true_flag(v, flag_name)),
        _ => false,
    }
}

/// Giải mã hex an toàn trên byte (không slice theo index chuỗi UTF-8):
/// cắt theo `&str[..]` tại index lệch ranh giới ký tự đa byte sẽ panic.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("Hex string has odd length".to_string());
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(chunk[0])
            .ok_or_else(|| format!("Invalid hex digit at byte offset {}", i * 2))?;
        let lo = hex_val(chunk[1])
            .ok_or_else(|| format!("Invalid hex digit at byte offset {}", i * 2 + 1))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_controller() -> (BrokerPolicyAdmissionController, SigningKey) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        (
            BrokerPolicyAdmissionController::new(10, "tenant-cyberv-corp", sk.verifying_key()),
            sk,
        )
    }

    fn sample_envelope(policy_json: &str) -> SignedPolicyEnvelope {
        SignedPolicyEnvelope {
            version: 11,
            issuer: "CyberV Master Authority".to_string(),
            tenant_id: "tenant-cyberv-corp".to_string(),
            not_before: 1000,
            not_after: 2000,
            policy_json: policy_json.to_string(),
            signature_hex: String::new(),
        }
    }

    /// REGRESSION H4: hex chứa ký tự UTF-8 đa byte (byte length chẵn nhưng
    /// không chia đều theo char boundary) phải trả Err, KHÔNG panic.
    #[test]
    fn decode_hex_never_panics_on_multibyte_utf8() {
        // "€" = 3 byte, "€€" = 6 byte (chẵn) nhưng index 1/2 lệch char boundary
        assert!(decode_hex("\u{20AC}\u{20AC}").is_err());
        assert!(decode_hex("€€€").is_err());
        assert!(decode_hex("日本").is_err());
        // Hex hợp lệ vẫn hoạt động
        assert_eq!(decode_hex("0A1b").unwrap(), vec![0x0a, 0x1b]);
        assert!(decode_hex("zz").is_err());
        assert!(decode_hex("abc").is_err()); // lẻ
        assert!(decode_hex("").unwrap().is_empty());
    }

    /// REGRESSION M2: invariant check bằng JSON walk phải bắt được cờ nested
    /// và biến thể whitespace mà substring matching cũ bỏ lọt.
    #[test]
    fn invariant_check_catches_nested_and_whitespace_variants() {
        for tricky_json in [
            r#"{"disable_tpm" :   true}"#,                      // whitespace
            r#"{"config": {"disable_tpm": true}}"#,              // nested
            r#"{"a": [{"disable_driver": true}]}"#,              // trong mảng
            r#"{"disable_safe_mode":TRUE}"#,                     // serde chấp nhận? -> JSON spec không; giữ surface
        ] {
            let (mut ctrl, sk) = test_controller();
            let envelope = sample_envelope(tricky_json).sign_with(&sk);
            let raw = serde_json::to_vec(&envelope).unwrap();
            let result = ctrl.verify_and_admit(&raw, 1500);
            if tricky_json.ends_with("TRUE}") {
                // Chuẩn JSON không có TRUE thường -> phải bị MalformedJson
                assert!(matches!(
                    result,
                    Err(PolicyAdmissionError::MalformedJson(_)) | Err(PolicyAdmissionError::InvariantViolation(_))
                ));
            } else {
                assert!(
                    matches!(result, Err(PolicyAdmissionError::InvariantViolation(_))),
                    "JSON {:?} phải bị chặn bởi invariant gate",
                    tricky_json
                );
            }
        }
    }

    /// REGRESSION M3: canonical length-prefixed chống cross-field ambiguity —
    /// envelope tenant "a:b" không thể tái diễn giải thành issuer/tenant khác.
    #[test]
    fn canonical_signing_bytes_are_injective_over_field_splits() {
        let a = SignedPolicyEnvelope {
            version: 1,
            issuer: "i:a".to_string(),
            tenant_id: "b".to_string(),
            not_before: 1,
            not_after: 2,
            policy_json: "{}".to_string(),
            signature_hex: String::new(),
        };
        let b = SignedPolicyEnvelope {
            version: 1,
            issuer: "i".to_string(),
            tenant_id: "a:b".to_string(),
            not_before: 1,
            not_after: 2,
            policy_json: "{}".to_string(),
            signature_hex: String::new(),
        };
        // Với phép nối ":" hai envelope này từng tạo CÙNG chuỗi ký.
        // Với length-prefix, chúng phải khác nhau.
        assert_ne!(a.canonical_signing_bytes(), b.canonical_signing_bytes());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let sk_seed = {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        };
        let sk = SigningKey::from_bytes(&sk_seed);

        // Controller 1: envelope hợp lệ được chấp nhận
        let (mut ctrl1, _) = test_controller_with_key(&sk);
        let envelope = sample_envelope(r#"{"allow_threshold": 8000}"#).sign_with(&sk);
        assert!(ctrl1.verify_and_admit(&serde_json::to_vec(&envelope).unwrap(), 1500).is_ok());

        // Controller 2 (cùng khóa pin, version reset về 10): envelope bị đổi
        // policy_json sau khi ký -> chữ ký không còn khớp canonical bytes
        let (mut ctrl2, _) = test_controller_with_key(&sk);
        let mut tampered = envelope.clone();
        tampered.policy_json = r#"{"allow_threshold": 100}"#.to_string();
        assert!(matches!(
            ctrl2.verify_and_admit(&serde_json::to_vec(&tampered).unwrap(), 1500),
            Err(PolicyAdmissionError::InvalidMasterSignature(_))
        ));
    }

    /// Controller với khóa pin có trước (dùng chung signing key giữa các controller)
    fn test_controller_with_key(
        sk: &SigningKey,
    ) -> (BrokerPolicyAdmissionController, SigningKey) {
        (
            BrokerPolicyAdmissionController::new(10, "tenant-cyberv-corp", sk.verifying_key()),
            sk.clone(),
        )
    }
}