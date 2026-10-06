// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
//! CyberV Identity Storage Abstraction
//!
//! Provides long-lived, stable device identity persistence protected by OS encryption (DPAPI)
//! without tying vault encryption keys to hardware mutation hashes (preventing deadlock).

pub mod error;
pub mod mock;
pub mod models;
pub mod windows_dpapi;

pub use error::StorageError;
pub use mock::MockSecureStorage;
pub use models::PersistedIdentity;
pub use windows_dpapi::WindowsDpapiStorage;

/// Interface for loading and persisting the stable device identity
pub trait DeviceSecureStorage: Send + Sync {
    /// Loads the stored identity, returning Ok(None) if no identity exists yet
    fn load_identity(&self) -> Result<Option<PersistedIdentity>, StorageError>;

    /// Atomically persists the identity to protected storage
    fn save_identity(&self, identity: &PersistedIdentity) -> Result<(), StorageError>;

    /// Wipes the stored identity
    fn clear_identity(&self) -> Result<(), StorageError>;

    /// Rotates the signing key of the persisted identity while preserving device_id and creation time
    fn rotate_identity_key(
        &self,
        new_key: &crate::identity::keypair::DeviceIdentityKey,
    ) -> Result<PersistedIdentity, StorageError> {
        let existing = self.load_identity()?.ok_or_else(|| {
            StorageError::CorruptVault(
                "Cannot rotate key: No existing identity in vault".to_string(),
            )
        })?;

        let updated = PersistedIdentity::new(
            existing.device_id,
            existing.device_seed,
            new_key.secret_bytes(),
            existing.created_at,
        );

        self.save_identity(&updated)?;
        Ok(updated)
    }
}
