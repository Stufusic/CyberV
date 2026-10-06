// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
    /// I-2: truy vấn Isolation Inbox — đề nghị cách ly đang chờ operator
    /// duyệt + chế độ enforcement hiện hành (trung thực WFP/logic-only).
    IsolationInbox,
    /// I-2: quyết định của operator (human-in-the-loop — không phá freeze
    /// gate). `subject_hex`: 64 ký tự hex; `action`: approve|lift|reject;
    /// `reason`: ≤ 200 ký tự — ghi DecisionLog.
    IsolationDecision { subject_hex: String, action: String, reason: String },
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
