//! CyberV Device Cryptographic Identity Subsystem
//!
//! Manages stable Ed25519 device keypairs, secret encapsulation without leaky serialization,
//! secure random number generation, OS-protected identity persistence, and HKDF state-bound derivation.
//!
//! Ref: rv4.md: "Identity Sống Lâu — State Sống Ngắn".

pub mod error;
pub mod kdf;
pub mod keypair;
pub mod rng;
pub mod secret;
pub mod storage;

pub use error::IdentityError;
pub use kdf::{derive_state_bound_bytes, derive_state_bound_material};
pub use keypair::DeviceIdentityKey;
pub use rng::{OsCryptoRng, SecureRandom};
pub use secret::Secret32;
pub use storage::{
    DeviceSecureStorage, MockSecureStorage, PersistedIdentity, StorageError, WindowsDpapiStorage,
};
