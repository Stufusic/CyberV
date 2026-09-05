//! Hardware-backed TPM Identity (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 5:
//! "TPM-backed key: hardware protected, non-exportable."

use crate::trust::tpm::{TpmError, TpmIdentityKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIdentity {
    pub key: TpmIdentityKey,
}

impl HardwareIdentity {
    pub fn new(key: TpmIdentityKey) -> Self {
        Self { key }
    }

    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex.clone()
    }

    pub fn sign(&self, data: &[u8]) -> Result<String, TpmError> {
        self.key.sign(data)
    }

    pub fn assert_protected(&self) -> Result<(), TpmError> {
        self.key.assert_hardware_protection()
    }
}
