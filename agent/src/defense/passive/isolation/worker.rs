//! Network Worker Daemon Architecture & Low-Integrity Sandbox (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 4:
//! "Worker Daemon (AppContainer / Low Integrity): Handles Supabase HTTP, JSON, Dashboard IPC.
//! An exploited parser gives the attacker zero private keys, zero TPM access, zero driver handle."

use super::protocol::{BrokerRpcCommand, RpcEnvelope, CURRENT_IPC_PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSandboxProfile {
    pub is_appcontainer_active: bool,
    pub token_integrity_level: String, // "Low" or "AppContainer"
    pub has_driver_access: bool,
    pub has_vault_access: bool,
}

/// Tiến trình Network Worker Daemon xử lý mạng bên ngoài
pub struct NetworkWorkerDaemon {
    pub session_id: u64,
    pub current_sequence_number: u64,
    pub sandbox_profile: WorkerSandboxProfile,
}

impl NetworkWorkerDaemon {
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            current_sequence_number: 1,
            sandbox_profile: WorkerSandboxProfile {
                is_appcontainer_active: true,
                token_integrity_level: "AppContainer".to_string(),
                has_driver_access: false, // Bị hạn chế hoàn toàn
                has_vault_access: false,  // Không có khóa giải mã
            },
        }
    }

    /// Tạo khung RPC gửi sang Core Broker
    pub fn create_rpc_request(
        &mut self,
        request_id: u64,
        command: BrokerRpcCommand,
        payload: Vec<u8>,
    ) -> RpcEnvelope {
        let seq = self.current_sequence_number;
        self.current_sequence_number += 1;

        RpcEnvelope {
            protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
            session_id: self.session_id,
            request_id,
            sequence_number: seq,
            command,
            payload,
            auth_tag: [0xAA; 16], // Mock MAC/Poly1305 tag
        }
    }

    /// Kiểm tra quyền truy cập: Worker tuyệt đối không thể đọc file Vault trực tiếp
    pub fn try_read_vault_file(&self) -> Result<(), &'static str> {
        if !self.sandbox_profile.has_vault_access {
            Err("Access Denied: AppContainer sandbox blocks direct vault file access")
        } else {
            Ok(())
        }
    }
}
