//! TPM Security Capabilities (Phase 15.5)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmCapabilities {
    pub present: bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub sha256_supported: bool,
    pub sha512_supported: bool,
    pub endorsement_key_available: bool,
}

impl TpmCapabilities {
    pub fn probe() -> Self {
        Self {
            present: true,
            version_major: 2,
            version_minor: 0,
            sha256_supported: true,
            sha512_supported: true,
            endorsement_key_available: true,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            present: false,
            version_major: 0,
            version_minor: 0,
            sha256_supported: false,
            sha512_supported: false,
            endorsement_key_available: false,
        }
    }
}
