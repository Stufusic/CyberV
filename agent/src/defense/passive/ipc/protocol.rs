//! Hardened IPC Protocol & Message Schema (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! "Strict message schema + Request size limit (<= 64KB) + No arbitrary command execution."

use serde::{Deserialize, Serialize};

pub const MAX_IPC_MESSAGE_SIZE: usize = 65536; // 64 KB Safe Limit

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    Handshake { client_version: String, nonce_hex: String },
    GetStatus,
    AttestationChallenge { nonce_hex: String },
    HeartbeatPing { timestamp: u64 },
    EmergencyAlert { alert_reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcMessageEnvelope {
    pub message_id: String,
    pub command: IpcCommand,
    pub sender_pid: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcProtocolError {
    MessageTooLarge(usize),
    EmptyPayload,
    DeserializationError(String),
}

pub struct IpcProtocolValidator;

impl IpcProtocolValidator {
    /// Xác thực và giải mã an toàn thông điệp IPC từ buffer thô
    pub fn parse_and_validate(raw_bytes: &[u8]) -> Result<IpcMessageEnvelope, IpcProtocolError> {
        if raw_bytes.is_empty() {
            return Err(IpcProtocolError::EmptyPayload);
        }

        if raw_bytes.len() > MAX_IPC_MESSAGE_SIZE {
            return Err(IpcProtocolError::MessageTooLarge(raw_bytes.len()));
        }

        serde_json::from_slice::<IpcMessageEnvelope>(raw_bytes)
            .map_err(|e| IpcProtocolError::DeserializationError(e.to_string()))
    }
}
