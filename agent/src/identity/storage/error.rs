//! Storage error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error during vault access: {0}")]
    Io(#[from] std::io::Error),

    #[error("Vault file format invalid or corrupt: {0}")]
    CorruptVault(String),

    #[error("DPAPI encryption/decryption failed: {0}")]
    Dpapi(String),

    #[error("Storage lock failure: {0}")]
    LockFailure(String),
}
