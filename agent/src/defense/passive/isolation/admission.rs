//! Broker Policy Admission Control (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 6:
//! "SynchronizePolicy là attack surface rất lớn.
//! Broker không được tin Worker chỉ vì Worker đã qua handshake.
//! Broker phải độc lập kiểm tra Master signature, monotonic version, issuer, expiration, schema, invariants."

use super::protocol::MAX_IPC_FRAME_SIZE;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

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

        let canonical_content = format!(
            "{}:{}:{}:{}:{}:{}",
            envelope.version,
            envelope.issuer,
            envelope.tenant_id,
            envelope.not_before,
            envelope.not_after,
            envelope.policy_json
        );

        if self
            .master_public_key
            .verify_strict(canonical_content.as_bytes(), &signature)
            .is_err()
        {
            return Err(PolicyAdmissionError::InvalidMasterSignature(
                "Ed25519 signature verification failed".to_string(),
            ));
        }

        // 7. Kiểm tra các quy tắc an toàn bất biến (Invariant Validation)
        // Không cho phép bất kỳ chính sách nào hạ thấp rào chắn bảo vệ phần cứng
        if envelope.policy_json.contains("\"disable_tpm\": true")
            || envelope.policy_json.contains("\"disable_tpm\":true")
        {
            return Err(PolicyAdmissionError::InvariantViolation(
                "Chính sách không được phép vô hiệu hóa kiểm tra TPM".to_string(),
            ));
        }
        if envelope.policy_json.contains("\"disable_driver\": true")
            || envelope.policy_json.contains("\"disable_driver\":true")
        {
            return Err(PolicyAdmissionError::InvariantViolation(
                "Chính sách không được phép vô hiệu hóa Kernel Driver".to_string(),
            ));
        }
        if envelope.policy_json.contains("\"disable_safe_mode\": true")
            || envelope.policy_json.contains("\"disable_safe_mode\":true")
        {
            return Err(PolicyAdmissionError::InvariantViolation(
                "Chính sách không được phép tắt Safe Recovery Mode".to_string(),
            ));
        }

        // Đạt toàn bộ kiểm tra: Cập nhật phiên bản chính sách mới
        self.active_policy_version = envelope.version;
        Ok(envelope.version)
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Hex string has odd length".to_string());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex digit at {}: {}", i, e))
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
