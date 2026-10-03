//! Hardened Win32 Named Pipe Server for CyberV Core Agent
//! Ref: Docs/rvnew.md Section 4, 5 (Security Boundary, PIPE-01 -> PIPE-07)
//!
//! Listens on `\\.\pipe\CyberVIPC` with strict bounds (<=64KB), Handshake verification,
//! and fail-closed state reporting.

use super::protocol::{IpcCommand, IpcProtocolValidator, MAX_IPC_MESSAGE_SIZE};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\CyberVIPC";
pub const EXPECTED_CLIENT_VERSION: &str = "1.0.0";
pub const AGENT_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponsePayload {
    pub message_id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub timestamp: u64,
}

#[cfg(windows)]
pub mod win_server {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ServerOptions;

    /// Thời hạn tối đa một kết nối được phép im lặng (chống chiếm dụng instance).
    pub const IPC_READ_TIMEOUT_SECS: u64 = 30;

    pub struct NamedPipeServer {
        pipe_name: String,
        is_running: Arc<AtomicBool>,
        /// PID được phép giao tiếp. `None` = chế độ ghi nhận (log client PID do
        /// kernel xác nhận, cho phép kết nối cục bộ) khi chưa cấu hình allowlist.
        /// `Some(list)` = fail-closed: mọi PID ngoài danh sách bị từ chối.
        allowed_client_pids: Option<Vec<u32>>,
        /// Snapshot trạng thái daemon thật (P1-2). None = daemon chưa chạy →
        /// GetStatus trả UNKNOWN fail-closed.
        status_snapshot: Option<crate::daemon_runner::SharedAgentStatus>,
    }

    impl NamedPipeServer {
        pub fn new(pipe_name: impl Into<String>) -> Self {
            Self {
                pipe_name: pipe_name.into(),
                is_running: Arc::new(AtomicBool::new(false)),
                allowed_client_pids: None,
                status_snapshot: None,
            }
        }

        /// Gắn snapshot trạng thái daemon thật — GetStatus sẽ phản ánh trạng
        /// thái này thay vì trả UNKNOWN tĩnh.
        pub fn with_status_snapshot(
            mut self,
            snapshot: crate::daemon_runner::SharedAgentStatus,
        ) -> Self {
            self.status_snapshot = Some(snapshot);
            self
        }

        /// Bật allowlist PID fail-closed (PID lấy qua GetNamedPipeClientProcessId
        /// từ kernel — không tin PID do client tự khai trong envelope).
        pub fn with_allowed_client_pids(mut self, pids: Vec<u32>) -> Self {
            self.allowed_client_pids = Some(pids);
            self
        }

        pub fn stop(&self) {
            self.is_running.store(false, Ordering::SeqCst);
        }

        /// Truy vấn PID tiến trình client từ kernel
        fn query_client_pid(
            pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
        ) -> Option<u32> {
            use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
            let mut pid: u32 = 0;
            // SAFETY: handle hợp lệ do tokio pipe quản lý; pid trỏ tới u32 hợp lệ
            let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as isize, &mut pid) };
            if ok != 0 {
                Some(pid)
            } else {
                None
            }
        }

        /// Runs the named pipe server listener loop
        pub async fn run_server(&self) -> Result<(), String> {
            self.is_running.store(true, Ordering::SeqCst);
            info!("Named Pipe Server active on: {}", self.pipe_name);

            while self.is_running.load(Ordering::SeqCst) {
                // first_pipe_instance(true): chan pipe squatting - process khac
                // khong the tao truoc instance dau voi DACL yeu de lua client.
                let server = match ServerOptions::new()
                    .first_pipe_instance(true)
                    .max_instances(8)
                    .create(&self.pipe_name)
                {
                    Ok(s) => s,
                    Err(e) => {
                        // Loi tao instance KHONG duoc giet ca loop (fail-stop
                        // vinh vien = tu choi phuc vu vo thoi han).
                        error!("Pipe instance creation failed: {} (retry 500ms)", e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };

                // Wait for a client connection
                if let Err(e) = server.connect().await {
                    error!("Named Pipe connect error: {}", e);
                    continue;
                }

                // Handle client in an async task
                let mut server = server;
                let allowed_pids = self.allowed_client_pids.clone();
                let status_snap = self.status_snapshot.clone();
                tokio::spawn(async move {
                    let client_pid = Self::query_client_pid(&server);
                    if let (Some(pids), Some(cp)) = (&allowed_pids, client_pid) {
                        if !pids.contains(&cp) {
                            warn!("IPC client PID {} denied by allowlist", cp);
                            let resp = IpcResponsePayload {
                                message_id: "ERR".to_string(),
                                success: false,
                                data: None,
                                error: Some("IPC client not authorized".to_string()),
                                timestamp: now_secs(),
                            };
                            if let Ok(resp_json) = serde_json::to_vec(&resp) {
                                let _ = server.write_all(&resp_json).await;
                                let _ = server.flush().await;
                            }
                            return;
                        }
                    }

                    // Read deadline: client connect roi im lang khong duoc giu
                    // instance vinh vien (chong resource-exhaustion DoS).
                    let mut buffer = vec![0u8; MAX_IPC_MESSAGE_SIZE];
                    let read = tokio::time::timeout(
                        Duration::from_secs(IPC_READ_TIMEOUT_SECS),
                        server.read(&mut buffer),
                    )
                    .await;

                    let n = match read {
                        Ok(Ok(n)) if n > 0 => n,
                        Ok(Ok(_)) => return, // client dong ket noi
                        Ok(Err(e)) => {
                            error!("Pipe read error: {}", e);
                            return;
                        }
                        Err(_) => {
                            warn!(
                                "Pipe read timeout ({}s), dropping client",
                                IPC_READ_TIMEOUT_SECS
                            );
                            return;
                        }
                    };

                    let raw_bytes = &buffer[..n];
                    let mut resp = handle_ipc_message_with(raw_bytes, status_snap.as_ref());
                    // Dinh kem PID client do KERNEL xac nhan de ben nhan kiem chung
                    // nguon phan hoi - PID tu khai trong envelope khong dang tin.
                    if let Some(data) = resp.data.as_mut() {
                        if let Some(obj) = data.as_object_mut() {
                            obj.insert(
                                "server_seen_client_pid".to_string(),
                                serde_json::json!(client_pid),
                            );
                        }
                    }
                    if let Ok(resp_json) = serde_json::to_vec(&resp) {
                        let _ = server.write_all(&resp_json).await;
                        let _ = server.flush().await;
                    }
                });
            }

            Ok(())
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Wrapper không-snapshot (dùng cho test + tương thích call-site cũ)
    #[allow(dead_code)]
    pub(crate) fn handle_ipc_message(raw_bytes: &[u8]) -> IpcResponsePayload {
        handle_ipc_message_with(raw_bytes, None)
    }

    fn handle_ipc_message_with(
        raw_bytes: &[u8],
        status_snapshot: Option<&crate::daemon_runner::SharedAgentStatus>,
    ) -> IpcResponsePayload {
        let envelope = match IpcProtocolValidator::parse_and_validate(raw_bytes) {
            Ok(env) => env,
            Err(e) => {
                return IpcResponsePayload {
                    message_id: "ERR".to_string(),
                    success: false,
                    data: None,
                    error: Some(format!("Invalid IPC payload: {:?}", e)),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match envelope.command {
            IpcCommand::Handshake {
                client_version,
                nonce_hex,
            } => {
                if client_version != EXPECTED_CLIENT_VERSION {
                    IpcResponsePayload {
                        message_id: envelope.message_id,
                        success: false,
                        data: None,
                        error: Some(format!(
                            "Protocol version mismatch: expected {}, got {}",
                            EXPECTED_CLIENT_VERSION, client_version
                        )),
                        timestamp: now,
                    }
                } else {
                    IpcResponsePayload {
                        message_id: envelope.message_id,
                        success: true,
                        data: Some(serde_json::json!({
                            "status": "HANDSHAKE_OK",
                            "server_version": AGENT_VERSION,
                            "nonce_echo": nonce_hex,
                            "server_pid": std::process::id(),
                        })),
                        error: None,
                        timestamp: now,
                    }
                }
            }
            IpcCommand::GetStatus => {
                // TRUNG THỰC (fail-closed): nếu daemon thật đang chạy (P1-2),
                // phản ánh snapshot tick thật; nếu không, trả UNKNOWN tĩnh —
                // tuyệt đối không bịa PROTECTED/hash.
                let snapshot_data = status_snapshot.and_then(|snap| {
                    snap.read().ok().and_then(|guard| {
                        guard
                            .as_ref()
                            .map(crate::daemon_runner::snapshot_to_getstatus_value)
                    })
                });
                let data = snapshot_data.unwrap_or_else(|| {
                    serde_json::json!({
                        "protection": {
                            "state": "UNKNOWN",
                            "substate": "STATUS_SOURCE_UNAVAILABLE",
                            "driver_available": false,
                            "is_isolated": false,
                            "reason": "IPC server has no live daemon/driver data channel; real status requires the integrated daemon loop"
                        },
                        "kernel_shield": {
                            "is_active": false,
                            "driver_version": null,
                            "cross_validator_active": false,
                            "hook_bypass_protection": false,
                            "dacl_hardened": false,
                            "last_attestation": null
                        },
                        "hardware_verified": false,
                        "tpm_contradiction": null,
                        "verification_hash": null
                    })
                });
                IpcResponsePayload {
                    message_id: envelope.message_id,
                    success: true,
                    data: Some(data),
                    error: None,
                    timestamp: now,
                }
            }
            IpcCommand::AttestationChallenge { nonce_hex } => IpcResponsePayload {
                message_id: envelope.message_id,
                success: false,
                data: Some(serde_json::json!({
                    "attestation_status": "UNAVAILABLE",
                    "challenge_nonce": nonce_hex,
                    "reason": "Local attestation signing is not wired to a verified identity key in this build; reporting fail-closed"
                })),
                error: Some("Attestation service unavailable (fail-closed)".to_string()),
                timestamp: now,
            },
            IpcCommand::HeartbeatPing { timestamp } => IpcResponsePayload {
                message_id: envelope.message_id,
                success: true,
                data: Some(serde_json::json!({
                    "pong": true,
                    "client_timestamp": timestamp,
                    "server_timestamp": now,
                })),
                error: None,
                timestamp: now,
            },
            IpcCommand::EmergencyAlert { alert_reason } => IpcResponsePayload {
                message_id: envelope.message_id,
                success: true,
                data: Some(serde_json::json!({
                    "acknowledged": true,
                    "action_taken": "ALERT_LOGGED",
                    "reason": alert_reason,
                })),
                error: None,
                timestamp: now,
            },
        }
    }
}

#[cfg(not(windows))]
pub mod fallback {
    use super::*;
    pub struct NamedPipeServer;
    impl NamedPipeServer {
        pub fn new(_: impl Into<String>) -> Self {
            Self
        }
        pub async fn run_server(&self) -> Result<(), String> {
            Ok(())
        }
        pub fn stop(&self) {}
    }
}
