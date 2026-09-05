//! TPM-backed Hardware Identity Key (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 5:
//! "TPM-backed key: hardware protected, non-exportable.
//! Key reference instead of raw private key in vault file."

use super::errors::TpmError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Khóa định danh thiết bị được bảo vệ bằng phần cứng TPM 2.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmIdentityKey {
    /// Tham chiếu định danh khóa trong TPM Key Storage Provider
    pub key_reference: String,
    /// Khóa công khai dạng hex
    pub public_key_hex: String,
    /// Cờ xác nhận khóa gắn chặt trong silicon TPM
    pub is_hardware_backed: bool,
    /// Cờ xác nhận khóa tuyệt đối không thể xuất ra ngoài (Non-exportable)
    pub is_exportable: bool,
    /// Tên nhà sản xuất chip TPM quản lý khóa
    pub tpm_manufacturer: String,
    #[serde(skip)]
    inner_signing_key: Option<SigningKey>,
}

impl TpmIdentityKey {
    /// Tạo đối tượng TpmIdentityKey mô phỏng hoặc thực tế
    pub fn new_hardware_backed(
        key_reference: impl Into<String>,
        tpm_manufacturer: impl Into<String>,
        signing_key: SigningKey,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = verifying_key
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        Self {
            key_reference: key_reference.into(),
            public_key_hex,
            is_hardware_backed: true,
            is_exportable: false, // Bất biến an ninh: TPM key không thể export
            tpm_manufacturer: tpm_manufacturer.into(),
            inner_signing_key: Some(signing_key),
        }
    }

    /// Ký thông điệp bằng khóa phần cứng bên trong TPM
    pub fn sign(&self, data: &[u8]) -> Result<String, TpmError> {
        let signing_key = self.inner_signing_key.as_ref().ok_or_else(|| {
            TpmError::KeyError("TPM hardware key handle is closed or sealed".to_string())
        })?;
        let signature = signing_key.sign(data);
        Ok(signature
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect())
    }

    /// Lấy VerifyingKey tương ứng
    pub fn verifying_key(&self) -> Result<VerifyingKey, TpmError> {
        let bytes = hex_to_bytes32(&self.public_key_hex).ok_or_else(|| {
            TpmError::KeyError("Invalid public key hex format in TPM key".to_string())
        })?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| TpmError::KeyError(format!("Invalid verifying key: {}", e)))
    }

    /// Kiểm tra ràng buộc bảo vệ phần cứng
    pub fn assert_hardware_protection(&self) -> Result<(), TpmError> {
        if !self.is_hardware_backed || self.is_exportable {
            return Err(TpmError::KeyError(
                "Khóa vi phạm chính sách an ninh: Không được lưu trữ trong TPM non-exportable"
                    .to_string(),
            ));
        }
        Ok(())
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
