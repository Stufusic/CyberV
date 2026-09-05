//! TPM PCR Evidence & Policy Engine (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! "PcrPolicy: required_pcrs, algorithm, policy_version.
//! SecureBootPolicy-v1 (PCR 7), MeasuredBootPolicy-v1 (PCR 0, 2, 7)."

use super::errors::TpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

pub const DOMAIN_PCR_COMPOSITE: &[u8] = b"CYBERV/DBS/PCR_DIGEST/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

/// Chính sách lựa chọn PCR được phiên bản hóa
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrPolicy {
    pub policy_id: String,
    pub required_pcrs: Vec<u32>,
    pub algorithm: HashAlgorithm,
    pub policy_version: u32,
}

impl PcrPolicy {
    /// Chính sách đo lường Secure Boot (PCR 7)
    pub fn secure_boot_policy() -> Self {
        Self {
            policy_id: "SecureBootPolicy-v1".to_string(),
            required_pcrs: vec![7],
            algorithm: HashAlgorithm::Sha512,
            policy_version: 1,
        }
    }

    /// Chính sách đo lường Measured Boot (PCR 0: Firmware, PCR 2: Option ROMs, PCR 7: Secure Boot)
    pub fn measured_boot_policy() -> Self {
        Self {
            policy_id: "MeasuredBootPolicy-v1".to_string(),
            required_pcrs: vec![0, 2, 7],
            algorithm: HashAlgorithm::Sha512,
            policy_version: 1,
        }
    }

    /// Chính sách nền tảng đầy đủ (PCR 0, 1, 2, 7, 11: BitLocker/Access control)
    pub fn full_platform_policy() -> Self {
        Self {
            policy_id: "FullPlatformPolicy-v1".to_string(),
            required_pcrs: vec![0, 1, 2, 7, 11],
            algorithm: HashAlgorithm::Sha512,
            policy_version: 1,
        }
    }

    /// Tính toán composite digest cho các PCR được chỉ định trong policy
    pub fn compute_composite_digest(&self, pcr_bank: &PcrBank) -> Result<String, TpmError> {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_PCR_COMPOSITE);
        hasher.update(self.policy_version.to_be_bytes());
        hasher.update((self.policy_id.len() as u32).to_be_bytes());
        hasher.update(self.policy_id.as_bytes());

        for &pcr in &self.required_pcrs {
            let val = pcr_bank.values.get(&pcr).ok_or_else(|| {
                TpmError::InvalidPcrSelection(format!("Missing required PCR {}", pcr))
            })?;
            hasher.update(pcr.to_be_bytes());
            hasher.update((val.len() as u32).to_be_bytes());
            hasher.update(val.as_bytes());
        }

        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Ngân hàng giá trị PCR của chip TPM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrBank {
    pub algorithm: HashAlgorithm,
    pub values: BTreeMap<u32, String>, // PCR Index -> Hex Digest
}

impl Default for PcrBank {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha512)
    }
}

impl PcrBank {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            values: BTreeMap::new(),
        }
    }

    pub fn set_pcr(&mut self, index: u32, value_hex: impl Into<String>) {
        self.values.insert(index, value_hex.into());
    }

    pub fn get_pcr(&self, index: u32) -> Option<&String> {
        self.values.get(&index)
    }
}
