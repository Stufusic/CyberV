//! Cryptographic Random Number Generator Abstraction
//!
//! Ref: rv4.md #8:
//! "Thay SigningKey::generate(&mut OsRng) thành CryptoRngProvider / SecureRandom...
//! Production: Windows/OS CSPRNG. Test: Deterministic test RNG (chỉ cho phép trong test)."

use super::error::IdentityError;

/// Trait providing cryptographically secure random bytes
pub trait SecureRandom: Send + Sync {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), IdentityError>;
}

/// Production CSPRNG backed by the operating system kernel entropy pool
#[derive(Default)]
pub struct OsCryptoRng;

impl SecureRandom for OsCryptoRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), IdentityError> {
        getrandom::getrandom(dest).map_err(|e| IdentityError::RngFailure(e.to_string()))
    }
}
