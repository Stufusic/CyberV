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
//! Mock In-Memory Secure Storage for Tests and CI
//!
//! Ref: rv4.md #5, #20: Storage testing without platform dependencies

use super::error::StorageError;
use super::models::PersistedIdentity;
use super::DeviceSecureStorage;
use std::sync::{Arc, RwLock};

/// Thread-safe in-memory vault for testing
#[derive(Clone, Default)]
pub struct MockSecureStorage {
    vault_bytes: Arc<RwLock<Option<Vec<u8>>>>,
}

impl MockSecureStorage {
    pub fn new() -> Self {
        Self {
            vault_bytes: Arc::new(RwLock::new(None)),
        }
    }
}

impl DeviceSecureStorage for MockSecureStorage {
    fn load_identity(&self) -> Result<Option<PersistedIdentity>, StorageError> {
        let guard = self
            .vault_bytes
            .read()
            .map_err(|e| StorageError::LockFailure(e.to_string()))?;
        match guard.as_ref() {
            Some(bytes) => Ok(Some(PersistedIdentity::from_vault_bytes(bytes)?)),
            None => Ok(None),
        }
    }

    fn save_identity(&self, identity: &PersistedIdentity) -> Result<(), StorageError> {
        let bytes = identity.to_vault_bytes();
        let mut guard = self
            .vault_bytes
            .write()
            .map_err(|e| StorageError::LockFailure(e.to_string()))?;
        *guard = Some(bytes);
        Ok(())
    }

    fn clear_identity(&self) -> Result<(), StorageError> {
        let mut guard = self
            .vault_bytes
            .write()
            .map_err(|e| StorageError::LockFailure(e.to_string()))?;
        *guard = None;
        Ok(())
    }
}
