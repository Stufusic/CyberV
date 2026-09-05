//! Verifiable Revocation Event Model (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8 Section 42, 43:
//! "Signed Event, Append-Only Log, MMR Entry Hash."

use crate::fingerprint::canonical::CanonicalEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_LOG_ENTRY: &[u8] = b"CYBERV/DBS/LOG_ENTRY/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    DeviceRevoked,
    DeviceUnrevoked,
    KeyRotated,
    SecurityPolicyUpdated,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::DeviceRevoked => "DEVICE_REVOKED",
            EventType::DeviceUnrevoked => "DEVICE_UNREVOKED",
            EventType::KeyRotated => "KEY_ROTATED",
            EventType::SecurityPolicyUpdated => "SECURITY_POLICY_UPDATED",
        }
    }
}

/// Sự kiện kiểm toán bất biến trong sổ cái thu hồi
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub event_version: u32,
    pub device_id: String,
    pub event_type: EventType,
    pub state_hash: String,
    pub reason_code: String,
    pub timestamp: u64,
    pub previous_event_hash: String,
}

impl RevocationEvent {
    pub fn new(
        device_id: impl Into<String>,
        event_type: EventType,
        state_hash: impl Into<String>,
        reason_code: impl Into<String>,
        timestamp: u64,
        previous_event_hash: impl Into<String>,
    ) -> Self {
        Self {
            event_version: 1,
            device_id: device_id.into(),
            event_type,
            state_hash: state_hash.into(),
            reason_code: reason_code.into(),
            timestamp,
            previous_event_hash: previous_event_hash.into(),
        }
    }

    /// Mã hóa sự kiện sang dạng byte chuẩn tắc (RFC 8785)
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        encoder.add_field("device_id", &self.device_id);
        encoder.add_field("event_type", self.event_type.as_str());
        encoder.add_field("event_version", &self.event_version.to_string());
        encoder.add_field("previous_event_hash", &self.previous_event_hash);
        encoder.add_field("reason_code", &self.reason_code);
        encoder.add_field("state_hash", &self.state_hash);
        encoder.add_field("timestamp", &self.timestamp.to_string());
        encoder.to_canonical_bytes()
    }

    /// Tính băm cam kết entry hash (SHA-512 hex 128 ký tự)
    pub fn entry_hash(&self) -> String {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_LOG_ENTRY);
        hasher.update(self.event_version.to_be_bytes());
        hasher.update(self.to_canonical_bytes());
        format!("{:x}", hasher.finalize())
    }
}
