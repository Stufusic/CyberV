//! Persisted Device Identity Data Models
//!
//! Ref: rv4.md #6:
//! "PersistedIdentity: device_id, device_seed, signing_key...
//! Vault serializer riêng: PersistedVault -> encrypted bytes.
//! Không bao giờ PersistedIdentity -> JSON."

use super::error::StorageError;
use crate::identity::secret::Secret32;
use sha2::{Digest, Sha512};

const VAULT_MAGIC: &[u8; 16] = b"CYBERV_VAULT_v1\0";

/// Encapsulates the long-lived, stable device identity
pub struct PersistedIdentity {
    pub device_id: String,
    pub device_seed: Secret32,
    pub signing_key: Secret32,
    pub created_at: u64,
}

impl PersistedIdentity {
    pub fn new(
        device_id: String,
        device_seed: Secret32,
        signing_key: Secret32,
        created_at: u64,
    ) -> Self {
        Self {
            device_id,
            device_seed,
            signing_key,
            created_at,
        }
    }

    /// Serializes identity to binary vault bytes with SHA-512 integrity checksum
    pub fn to_vault_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(VAULT_MAGIC);
        buffer.extend_from_slice(&self.created_at.to_be_bytes());

        let dev_id_bytes = self.device_id.as_bytes();
        let dev_id_len = dev_id_bytes.len() as u16;
        buffer.extend_from_slice(&dev_id_len.to_be_bytes());
        buffer.extend_from_slice(dev_id_bytes);

        buffer.extend_from_slice(self.device_seed.as_bytes());
        buffer.extend_from_slice(self.signing_key.as_bytes());

        // Append SHA-512 checksum of the payload
        let checksum = Sha512::digest(&buffer);
        buffer.extend_from_slice(&checksum);

        buffer
    }

    /// Deserializes identity from binary vault bytes, validating magic header and checksum
    pub fn from_vault_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        // Minimum size: 16 (magic) + 8 (created_at) + 2 (len) + 0 (id) + 32 (seed) + 32 (key) + 64 (checksum) = 154 bytes
        if bytes.len() < 154 {
            return Err(StorageError::CorruptVault(format!(
                "Vault bytes too short: {}",
                bytes.len()
            )));
        }

        let payload_len = bytes.len() - 64;
        let payload = &bytes[..payload_len];
        let expected_checksum = &bytes[payload_len..];

        let actual_checksum = Sha512::digest(payload);
        if actual_checksum.as_slice() != expected_checksum {
            return Err(StorageError::CorruptVault(
                "Vault checksum mismatch - data corrupted or tampered".to_string(),
            ));
        }

        if &payload[..16] != VAULT_MAGIC {
            return Err(StorageError::CorruptVault(
                "Invalid vault magic header".to_string(),
            ));
        }

        let created_at = u64::from_be_bytes(
            payload[16..24]
                .try_into()
                .map_err(|_| StorageError::CorruptVault("Failed to read timestamp".into()))?,
        );

        let dev_id_len = u16::from_be_bytes(
            payload[24..26]
                .try_into()
                .map_err(|_| StorageError::CorruptVault("Failed to read id length".into()))?,
        ) as usize;

        let dev_id_end = 26 + dev_id_len;
        if dev_id_end + 64 > payload_len {
            return Err(StorageError::CorruptVault(
                "Invalid device_id length in vault".to_string(),
            ));
        }

        let device_id = String::from_utf8(payload[26..dev_id_end].to_vec())
            .map_err(|e| StorageError::CorruptVault(format!("Invalid UTF-8 device_id: {}", e)))?;

        let device_seed = Secret32::from_slice(&payload[dev_id_end..dev_id_end + 32])
            .map_err(|e| StorageError::CorruptVault(e.to_string()))?;

        let signing_key = Secret32::from_slice(&payload[dev_id_end + 32..dev_id_end + 64])
            .map_err(|e| StorageError::CorruptVault(e.to_string()))?;

        Ok(Self {
            device_id,
            device_seed,
            signing_key,
            created_at,
        })
    }
}
