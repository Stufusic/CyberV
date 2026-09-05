//! Secret32: An encapsulated 32-byte secret protected by ZeroizeOnDrop
//!
//! Ref: rv4.md #6:
//! "pub struct Secret32(Zeroizing<[u8; 32]>);
//! không implement Serialize/Debug/Display tùy tiện...
//! Không bao giờ PersistedIdentity -> JSON."

use super::error::IdentityError;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Safe 32-byte secret wrapper that zeroes memory on drop and prevents serialization leaks
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    /// Creates a new Secret32 from an array
    pub fn new(bytes: [u8; 32]) -> Self {
        Secret32(Zeroizing::new(bytes))
    }

    /// Creates a Secret32 from a slice, returning an error if length != 32
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdentityError> {
        if slice.len() != 32 {
            return Err(IdentityError::InvalidSecretLength(slice.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Ok(Secret32::new(arr))
    }

    /// Access the secret bytes temporarily
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Clone for Secret32 {
    fn clone(&self) -> Self {
        let mut copy = [0u8; 32];
        copy.copy_from_slice(self.0.as_ref());
        Secret32::new(copy)
    }
}

impl PartialEq for Secret32 {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_ref();
        let b = other.0.as_ref();
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

impl Eq for Secret32 {}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret32([REDACTED_SECRET_32])")
    }
}
