//! Vault Shield & File Integrity Protection (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Bảo vệ tệp database và khóa định danh của CyberV trên ổ đĩa."

use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultShieldError {
    #[error("Tệp vault không tồn tại: {0}")]
    NotFound(String),

    #[error(
        "Can thiệp trái phép vào tệp vault: cam kết SHA-512 không khớp ({expected} != {actual})"
    )]
    IntegrityViolation { expected: String, actual: String },

    #[error("Lỗi I/O khi khóa hoặc truy cập vault: {0}")]
    IoError(String),
}

/// Bộ bảo vệ tính toàn vẹn và khóa tệp Vault trên ổ đĩa
#[derive(Debug, Clone)]
pub struct VaultShield {
    vault_path: PathBuf,
    expected_commitment: Option<String>,
}

impl VaultShield {
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault_path: vault_path.as_ref().to_path_buf(),
            expected_commitment: None,
        }
    }

    /// Tính cam kết SHA-512 của tệp vault
    pub fn compute_file_commitment(&self) -> Result<String, VaultShieldError> {
        let bytes = std::fs::read(&self.vault_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultShieldError::NotFound(self.vault_path.display().to_string())
            } else {
                VaultShieldError::IoError(e.to_string())
            }
        })?;

        let mut hasher = Sha512::new();
        hasher.update(b"CYBERV_VAULT_FILE_SHIELD_v1");
        hasher.update(&bytes);
        Ok(format!("{:0128x}", hasher.finalize()))
    }

    /// Khóa chốt cam kết hiện tại của Vault
    pub fn lock_baseline(&mut self) -> Result<String, VaultShieldError> {
        let commitment = self.compute_file_commitment()?;
        self.expected_commitment = Some(commitment.clone());
        Ok(commitment)
    }

    /// Kiểm tra xem tệp vault có bị thay thế hoặc sửa đổi trái phép hay không
    pub fn verify_integrity(&self) -> Result<bool, VaultShieldError> {
        let expected = match &self.expected_commitment {
            Some(exp) => exp,
            None => return Ok(true), // Chưa khóa baseline
        };

        let current = self.compute_file_commitment()?;
        if &current != expected {
            return Err(VaultShieldError::IntegrityViolation {
                expected: expected.clone(),
                actual: current,
            });
        }

        Ok(true)
    }
}
