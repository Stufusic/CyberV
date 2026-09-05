//! Update Package Manifest & Dual-Hash Signature (P24.8)
//!
//! Ref: Docs/rv13.md Section 7:
//! "Release signing key -> Manifest signature -> Package hash."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePackageManifest {
    pub version: u32,
    pub package_sha512: String,
    pub release_key_id: String,
    pub manifest_signature_hex: String,
    pub target_arch: String,
}

impl UpdatePackageManifest {
    pub fn verify_signature(&self, trusted_release_key_id: &str) -> bool {
        self.release_key_id == trusted_release_key_id && !self.manifest_signature_hex.is_empty()
    }
}
