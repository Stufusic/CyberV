//! Hardened Multi-Layer IPC Protocol & Envelope Specification (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 5:
//! "RPC Envelope: protocol_version, session_id, request_id, sequence_number, command, payload_length, payload, MAC/AEAD tag.
//! Message Bounds <= 64KB. Replay protection with strict monotonic sequence numbers."

use serde::{Deserialize, Serialize};

/// Giới hạn kích thước khung thông điệp tối đa 64 KB (Strict Security Boundary)
pub const MAX_IPC_FRAME_SIZE: usize = 65536;

/// Phiên bản giao thức IPC hiện tại
pub const CURRENT_IPC_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerRpcCommand {
    /// Lấy trạng thái tổng quan của Core Broker
    GetStatus,
    /// Yêu cầu Broker ký số challenge bằng Ed25519 Identity Key trong Vault
    SignChallenge { challenge_bytes: Vec<u8> },
    /// Đọc giá trị TPM NV Monotonic Counter
    GetTpmNvCounter { nv_index: u32 },
    /// Lấy dữ liệu bằng chứng phần cứng và nền tảng (Platform Evidence)
    GetPlatformEvidence,
    /// Nạp chính sách an ninh mới tải từ Internet (Bắt buộc qua Admission Controller)
    SubmitPolicyForAdmission { policy_bytes: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcEnvelope {
    pub protocol_version: u16,
    pub session_id: u64,
    pub request_id: u64,
    pub sequence_number: u64,
    pub command: BrokerRpcCommand,
    pub payload: Vec<u8>,
    pub auth_tag: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcFrameError {
    OversizedFrame(usize),
    EmptyFrame,
    SequenceReplay { expected: u64, actual: u64 },
    SequenceOutOfOrder { expected: u64, actual: u64 },
    SessionMismatch { expected: u64, actual: u64 },
    AuthenticationTagInvalid,
    ProtocolVersionUnsupported(u16),
    SerializationError(String),
}

/// Trình quản lý và xác thực phiên IPC (Replay Protection & Monotonic Frame Ordering)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcSessionValidator {
    pub session_id: u64,
    pub expected_sequence_number: u64,
}

impl RpcSessionValidator {
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            expected_sequence_number: 1,
        }
    }

    /// Thẩm định khung thông điệp và tiến tới số thứ tự tiếp theo
    pub fn validate_and_advance(&mut self, envelope: &RpcEnvelope) -> Result<(), IpcFrameError> {
        // 1. Kiểm tra kích thước payload
        if envelope.payload.len() > MAX_IPC_FRAME_SIZE {
            return Err(IpcFrameError::OversizedFrame(envelope.payload.len()));
        }

        // 2. Kiểm tra phiên bản giao thức
        if envelope.protocol_version != CURRENT_IPC_PROTOCOL_VERSION {
            return Err(IpcFrameError::ProtocolVersionUnsupported(
                envelope.protocol_version,
            ));
        }

        // 3. Kiểm tra Session ID
        if envelope.session_id != self.session_id {
            return Err(IpcFrameError::SessionMismatch {
                expected: self.session_id,
                actual: envelope.session_id,
            });
        }

        // 4. Kiểm tra Replay & Thứ tự khung tuần tự nghiêm ngặt (Strict Monotonic Nonce/Sequence)
        if envelope.sequence_number < self.expected_sequence_number {
            return Err(IpcFrameError::SequenceReplay {
                expected: self.expected_sequence_number,
                actual: envelope.sequence_number,
            });
        }

        if envelope.sequence_number > self.expected_sequence_number {
            return Err(IpcFrameError::SequenceOutOfOrder {
                expected: self.expected_sequence_number,
                actual: envelope.sequence_number,
            });
        }

        // Tăng số thứ tự kỳ vọng cho khung tiếp theo
        self.expected_sequence_number += 1;
        Ok(())
    }
}
