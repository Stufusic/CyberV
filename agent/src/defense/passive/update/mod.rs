//! Secure Update Subsystem (P24.8)
//!
//! Ref: Docs/rv13.md Section 7:
//! Staged installation, atomic activation, anti-rollback and manifest verification.

pub mod manifest;
pub mod staging;
pub mod version_policy;

pub use manifest::UpdatePackageManifest;
pub use staging::{
    CommitStage, PendingCommitMarker, StartupRecoveryAction, UpdateStagingManager,
    UpdateStagingState,
};
pub use version_policy::{HardwareVersionDecision, VersionPolicyDecision, VersionPolicyValidator};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateIntegrityReport {
    pub manifest_verified: bool,
    pub anti_rollback_passed: bool,
    pub staging_state: UpdateStagingState,
    pub update_score: u32, // 0 - 10000
    pub summary: String,
}

impl UpdateIntegrityReport {
    pub fn verified_active() -> Self {
        Self {
            manifest_verified: true,
            anti_rollback_passed: true,
            staging_state: UpdateStagingState::Active,
            update_score: 10000,
            summary:
                "Secure Update: Manifest verified, Anti-rollback compliant, Atomic swap verified"
                    .to_string(),
        }
    }
}
