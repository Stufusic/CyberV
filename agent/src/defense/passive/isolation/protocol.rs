// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! Hardened Multi-Layer IPC Protocol & Envelope Specification (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 5:
//! "RPC Envelope: protocol_version, session_id, request_id, sequence_number, command, payload_length, payload, MAC/AEAD tag.
//! Message Bounds <= 64KB. Replay protection with strict monotonic sequence numbers."
//!
//! Mỗi frame BẮT BUỘC mang HMAC-SHA512 (truncated 16 byte) với session key
//! sinh ra khi bắt tay phiên. MAC phủ TOÀN BỘ các trường kẻ tấn công có thể
//! thay đổi (version, session, request, sequence, command, payload) — frame
//! MAC sai bị từ chối TRƯỚC khi validator xét sequence, đóng đường desync
//! DoS và vô hiệu hóa `auth_tag` mock trước đây.

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Giới hạn kích thước khung thông điệp tối đa 64 KB (Strict Security Boundary)
pub const MAX_IPC_FRAME_SIZE: usize = 65536;

/// Phiên bản giao thức IPC hiện tại
pub const CURRENT_IPC_PROTOCOL_VERSION: u16 = 1;

pub const DOMAIN_BROKER_FRAME_MAC: &[u8] = b"CYBERV/BROKER/FRAME/MAC/v1\0";

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

#[derive(Debug, Clone, PartialEq, Eq)]
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

type HmacSha512 = Hmac<sha2::Sha512>;

/// Tính MAC của frame bằng session key của phiên: HMAC-SHA512, cắt 16 byte.
/// Mọi trường của envelope đều được đưa vào MAC với prefix độ dài —
/// không có trường nào có thể bị thay đổi mà không phá vỡ MAC.
pub fn compute_frame_mac(session_key: &[u8; 32], envelope: &RpcEnvelope) -> [u8; 16] {
    let mut mac = HmacSha512::new_from_slice(session_key)
        .expect("HMAC-SHA512 accepts every key length; 32-byte key is always valid");

    mac.update(DOMAIN_BROKER_FRAME_MAC);
    mac.update(&envelope.protocol_version.to_be_bytes());
    mac.update(&envelope.session_id.to_be_bytes());
    mac.update(&envelope.request_id.to_be_bytes());
    mac.update(&envelope.sequence_number.to_be_bytes());

    let cmd_bytes = serde_json::to_vec(&envelope.command)
        .unwrap_or_default(); // BrokerRpcCommand serialize với any input không bao giờ lỗi
    mac.update(&(cmd_bytes.len() as u32).to_be_bytes());
    mac.update(&cmd_bytes);

    mac.update(&(envelope.payload.len() as u32).to_be_bytes());
    mac.update(&envelope.payload);

    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

/// So sánh theo hằng thời gian (constant-time) — chặn timing oracle
fn constant_time_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Sinh session key ngẫu nhiên bằng OS CSPRNG (dùng khi broker/worker bắt tay phiên)
pub fn generate_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Trình quản lý và xác thực phiên IPC (Replay Protection & Monotonic Frame Ordering)
#[derive(Debug, Clone)]
pub struct RpcSessionValidator {
    pub session_id: u64,
    pub expected_sequence_number: u64,
    /// Khóa phiên dùng để xác thực MAC của mọi frame (sinh khi bắt tay phiên)
    pub session_key: [u8; 32],
}

impl PartialEq for RpcSessionValidator {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.expected_sequence_number == other.expected_sequence_number
            && constant_time_eq(&self.session_key, &other.session_key)
    }
}

impl Eq for RpcSessionValidator {}

impl RpcSessionValidator {
    /// Tạo validator phiên với session key ngẫu nhiên (OS CSPRNG)
    pub fn new(session_id: u64) -> Self {
        Self::with_session_key(session_id, generate_session_key())
    }

    /// Tạo validator với khóa phiên cụ thể (dùng khi cả hai bên nhận khóa
    /// từ kết quả bắt tay — ví dụ bộ kiểm thử mô phỏng handshake).
    pub fn with_session_key(session_id: u64, session_key: [u8; 32]) -> Self {
        Self {
            session_id,
            expected_sequence_number: 1,
            session_key,
        }
    }

    /// Thẩm định khung thông điệp và tiến tới số thứ tự tiếp theo.
    /// MAC được kiểm tra TRƯỚC TIÊN: frame chưa xác thực không được phép
    /// biết được bất kỳ thông tin nào về trạng thái sequence của phiên.
    pub fn validate_and_advance(&mut self, envelope: &RpcEnvelope) -> Result<(), IpcFrameError> {
        // 0. Xác thực MAC — đóng cổng frame giả mạo/tráo nội dung
        let expected_tag = compute_frame_mac(&self.session_key, envelope);
        if !constant_time_eq(&expected_tag, &envelope.auth_tag) {
            return Err(IpcFrameError::AuthenticationTagInvalid);
        }

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
        self.expected_sequence_number = self.expected_sequence_number.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_envelope(session_key: &[u8; 32], seq: u64, payload: Vec<u8>) -> RpcEnvelope {
        let envelope = RpcEnvelope {
            protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
            session_id: 7,
            request_id: 1,
            sequence_number: seq,
            command: BrokerRpcCommand::GetStatus,
            payload,
            auth_tag: [0u8; 16],
        };
        let tag = compute_frame_mac(session_key, &envelope);
        RpcEnvelope { auth_tag: tag, ..envelope }
    }

    #[test]
    fn frame_mac_binds_all_fields() {
        let key = [0x33u8; 32];
        let env = signed_envelope(&key, 1, vec![1, 2, 3]);
        let mut validator = RpcSessionValidator::with_session_key(7, key);
        assert!(validator.validate_and_advance(&env).is_ok());

        // Đổi 1 bit payload -> MAC phải gãy
        let original_tag = env.auth_tag;
        let mut tampered = env.clone();
        tampered.payload = vec![1, 2, 4];
        tampered.auth_tag = original_tag;
        let mut v2 = RpcSessionValidator::with_session_key(7, key);
        assert_eq!(
            v2.validate_and_advance(&tampered),
            Err(IpcFrameError::AuthenticationTagInvalid)
        );
    }

    #[test]
    fn wrong_session_key_rejected() {
        let env = signed_envelope(&[0x44u8; 32], 1, vec![]);
        let mut validator = RpcSessionValidator::with_session_key(7, [0x55u8; 32]);
        assert_eq!(
            validator.validate_and_advance(&env),
            Err(IpcFrameError::AuthenticationTagInvalid)
        );
    }
}
