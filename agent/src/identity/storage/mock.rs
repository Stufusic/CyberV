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
