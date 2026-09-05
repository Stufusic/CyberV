//! Device Identity Key (Ed25519 Keypair)
//!
//! Ref: rv4.md #7, #8, #15, #16:
//! "CSPRNG -> Ed25519 SigningKey -> public key...
//! Device Identity là STABLE... không đồng nghĩa hardware mutation -> new signing key."

use super::error::IdentityError;
use super::rng::SecureRandom;
use super::secret::Secret32;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Manages the stable Ed25519 device identity keypair
#[derive(Clone)]
pub struct DeviceIdentityKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl DeviceIdentityKey {
    /// Generates a fresh Ed25519 keypair using the provided cryptographically secure RNG
    pub fn generate(rng: &mut impl SecureRandom) -> Result<Self, IdentityError> {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Reconstructs the keypair from persisted secret bytes
    pub fn from_secret_bytes(bytes: &Secret32) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(bytes.as_bytes());
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Access the underlying private key bytes in a zeroizing wrapper
    pub fn secret_bytes(&self) -> Secret32 {
        Secret32::new(self.signing_key.to_bytes())
    }

    /// Access the public verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Exports public key as a 64-character lowercase hex string
    pub fn public_key_hex(&self) -> String {
        let bytes = self.verifying_key.to_bytes();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Signs a payload, returning a 64-byte Ed25519 signature
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing_key.sign(payload).to_bytes()
    }

    /// Verifies a 64-byte signature against the payload and public key
    pub fn verify(
        verifying_key: &VerifyingKey,
        payload: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let signature = Signature::from_bytes(signature_bytes);
        verifying_key
            .verify(payload, &signature)
            .map_err(|e| IdentityError::SignatureVerification(e.to_string()))
    }

    /// Parses a public verifying key from a 64-character hex string
    pub fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey, IdentityError> {
        if hex_str.len() != 64 {
            return Err(IdentityError::InvalidPublicKey(format!(
                "Expected 64 hex characters, got {}",
                hex_str.len()
            )));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_hex = &hex_str[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_hex, 16)
                .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
        }
        VerifyingKey::from_bytes(&bytes).map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))
    }
}
