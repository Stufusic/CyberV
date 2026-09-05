//! Error types for CyberV Identity & Cryptographic Operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Random number generator failure: {0}")]
    RngFailure(String),

    #[error("Key generation failure: {0}")]
    KeyGeneration(String),

    #[error("Invalid secret key bytes length: expected 32 bytes, got {0}")]
    InvalidSecretLength(usize),

    #[error("Invalid public key hex or format: {0}")]
    InvalidPublicKey(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("HKDF key derivation failure: {0}")]
    KdfFailure(String),

    #[error("Storage failure: {0}")]
    Storage(String),
}
