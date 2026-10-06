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
//! Secure Update Subsystem (P24.8)
//!
//! Ref: Docs/rv13.md Section 7:
//! Staged installation, atomic activation, anti-rollback and manifest verification.

pub mod authority;
pub mod manifest;
pub mod staging;
pub mod version_policy;

pub use authority::{
    load_pinned_authority_key, parse_authority_public_key, verify_update_manifest,
    UPDATE_AUTHORITY_PUBKEY_ENV,
};
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
