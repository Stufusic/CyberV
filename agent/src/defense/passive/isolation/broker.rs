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
//! Core Broker Architecture & High-Integrity Host (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 4, 5:
//! "Core Broker (SYSTEM / High Integrity): Holds Vault, TPM, Driver, Local Policy.
//! Zero network sockets, zero arbitrary HTTP/JSON parsers from Internet."

use super::protocol::{
    generate_session_key, BrokerRpcCommand, IpcFrameError, RpcEnvelope, RpcSessionValidator,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Danh sách SID được ủy quyền kết nối vào Core Broker
pub const EXPECTED_WORKER_APPCONTAINER_SID: &str = "S-1-15-2-CYBERV-WORKER-DAEMON";

/// Giới hạn số phiên đồng thời — chặn cạn kiệt bộ nhớ bởi đăng ký phiên vô hạn
pub const MAX_ACTIVE_SESSIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerStatus {
    pub is_vault_locked: bool,
    pub is_tpm_ready: bool,
    pub is_driver_connected: bool,
    pub active_sessions_count: usize,
    pub has_network_sockets: bool,
}

/// Lỗi xác thực hoặc giao tiếp của Broker
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    UnauthorizedClientSid(String),
    UntrustedExecutable(String),
    SessionNotFound(u64),
    SessionLimitReached,
    ProtocolError(IpcFrameError),
    VaultAccessDenied,
}

/// Tiến trình Core Broker quản lý tài nguyên cấp cao
pub struct CoreBroker {
    sessions: HashMap<u64, RpcSessionValidator>,
    is_vault_unlocked: bool,
    is_tpm_ready: bool,
    is_driver_connected: bool,
}

impl Default for CoreBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreBroker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            is_vault_unlocked: true,
            is_tpm_ready: true,
            is_driver_connected: true,
        }
    }

    /// Thẩm định danh tính tiến trình client kết nối vào Named Pipe
    /// (Kiểm tra Token SID và Chữ ký số Authenticode)
    pub fn authorize_client_connection(
        &self,
        client_sid: &str,
        client_executable_name: &str,
        is_client_signature_valid: bool,
    ) -> Result<(), BrokerError> {
        // 1. Kiểm tra SID của client phải là Worker hoặc SYSTEM
        if client_sid != EXPECTED_WORKER_APPCONTAINER_SID && client_sid != "S-1-5-18" {
            return Err(BrokerError::UnauthorizedClientSid(client_sid.to_string()));
        }

        // 2. Kiểm tra tên file thực thi và chữ ký số
        if client_executable_name != "CyberVWorker.exe" || !is_client_signature_valid {
            return Err(BrokerError::UntrustedExecutable(
                client_executable_name.to_string(),
            ));
        }

        Ok(())
    }

    /// Đăng ký một phiên IPC mới: sinh khóa phiên ngẫu nhiên (mô phỏng kết quả
    /// bắt tay key-exchange) và trả về cho worker. Phiên mới yêu cầu MAC frame.
    /// Trả lỗi khi vượt giới hạn phiên đồng thời (chặn DoS đăng ký phiên).
    pub fn register_session(&mut self, session_id: u64) -> Result<[u8; 32], BrokerError> {
        if self.sessions.len() >= MAX_ACTIVE_SESSIONS {
            return Err(BrokerError::SessionLimitReached);
        }
        let session_key = generate_session_key();
        self.sessions.insert(
            session_id,
            RpcSessionValidator::with_session_key(session_id, session_key),
        );
        Ok(session_key)
    }

    /// Xử lý khung RPC gửi từ Worker — frame phải mang MAC hợp lệ
    /// (kiểm tra trong validate_and_advance) trước khi lệnh được thực thi.
    pub fn handle_rpc_frame(
        &mut self,
        envelope: &RpcEnvelope,
    ) -> Result<BrokerRpcCommand, BrokerError> {
        let session = self
            .sessions
            .get_mut(&envelope.session_id)
            .ok_or(BrokerError::SessionNotFound(envelope.session_id))?;

        session
            .validate_and_advance(envelope)
            .map_err(BrokerError::ProtocolError)?;

        // Khung thông điệp hợp lệ: Trả về command để thực thi
        Ok(envelope.command.clone())
    }

    /// Báo cáo trạng thái Core Broker (Bảo đảm Zero-Network Sockets)
    pub fn get_status(&self) -> BrokerStatus {
        BrokerStatus {
            is_vault_locked: !self.is_vault_unlocked,
            is_tpm_ready: self.is_tpm_ready,
            is_driver_connected: self.is_driver_connected,
            active_sessions_count: self.sessions.len(),
            has_network_sockets: false, // Bất biến kiến trúc: Broker không bao giờ mở socket mạng
        }
    }
}
