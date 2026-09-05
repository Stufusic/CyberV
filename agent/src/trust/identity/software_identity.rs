//! Software-based Identity Fallback (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 4 & 5:
//! "Consumer mode: TPM unavailable -> software fallback -> lower assurance."

use crate::identity::DeviceIdentityKey;

#[derive(Clone)]
pub struct SoftwareIdentity {
    pub key: DeviceIdentityKey,
}

impl SoftwareIdentity {
    pub fn new(key: DeviceIdentityKey) -> Self {
        Self { key }
    }

    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let sig = self.key.sign(data);
        sig.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
