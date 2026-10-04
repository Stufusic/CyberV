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
    use crate::identity::rng::{OsCryptoRng, SecureRandom};
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
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
        /// Khóa identity để ký handshake pipe (P1-1). `None` = fail-closed:
        /// mọi kết nối chỉ nhận ERR rồi bị đóng — không có phiên plaintext.
        identity_key: Option<crate::identity::keypair::DeviceIdentityKey>,
    }

    impl NamedPipeServer {
        pub fn new(pipe_name: impl Into<String>) -> Self {
            Self {
                pipe_name: pipe_name.into(),
                is_running: Arc::new(AtomicBool::new(false)),
                allowed_client_pids: None,
                status_snapshot: None,
                identity_key: None,
            }
        }

        /// Gắn khóa identity (P1-1) — bắt buộc để phục vụ phiên AEAD. Không
        /// có khóa = server từ chối mọi kết nối (fail-closed, INV-012).
        pub fn with_identity_key_opt(
            mut self,
            key: Option<crate::identity::keypair::DeviceIdentityKey>,
        ) -> Self {
            self.identity_key = key;
            self
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

                // P1-1: áp DACL THẬT lên instance ngay sau khi tạo. Thất bại
                // thì warn TO và vẫn phục vụ với default DACL — fail-stop
                // (đóng instance) = tự chối phục vụ vô thời hạn, không hơn.
                if let Err(e) = crate::defense::passive::ipc::PipeAclManager::apply_hardened_dacl(
                    server.as_raw_handle(),
                ) {
                    warn!("Áp DACL hardened thất bại (fallback default DACL): {e}");
                }

                // Handle client in an async task
                let mut server = server;
                let allowed_pids = self.allowed_client_pids.clone();
                let status_snap = self.status_snapshot.clone();
                let identity_key = self.identity_key.clone();
                tokio::spawn(async move {
                    let client_pid = Self::query_client_pid(&server);
                    if let (Some(pids), Some(cp)) = (&allowed_pids, client_pid) {
                        if !pids.contains(&cp) {
                            warn!("IPC client PID {} denied by allowlist", cp);
                            send_plaintext_err(&mut server, "IPC client not authorized").await;
                            return;
                        }
                    }

                    // P1-1: phiên AEAD BẮT BUỘC. Không có khóa identity =
                    // fail-closed: chỉ trả ERR plaintext rồi đóng (không bao
                    // giờ phục vụ envelope qua kênh không xác thực server).
                    let Some(identity) = identity_key.as_ref() else {
                        warn!("IPC server thiếu khóa identity — từ chối kết nối (fail-closed)");
                        send_plaintext_err(&mut server, "IPC server identity unavailable (fail-closed)")
                            .await;
                        return;
                    };

                    // ---- Bắt tay 2 bước (P1-1): PipeHello → PipeHelloAck ----
                    let hello_frame = match read_wire_frame(&mut server, PIPE_HANDSHAKE_MAX).await {
                        Ok(f) => f,
                        Err(e) => {
                            warn!("IPC handshake read lỗi: {e}");
                            return;
                        }
                    };
                    let hello = match crate::mesh::pipe_session::PipeHello::decode(&hello_frame)
                    {
                        Ok(h) => h,
                        Err(e) => {
                            warn!("PipeHello không hợp lệ: {e}");
                            send_plaintext_err(&mut server, "Invalid handshake").await;
                            return;
                        }
                    };
                    let mut server_seed = [0u8; 32];
                    if OsCryptoRng.fill(&mut server_seed).is_err() {
                        error!("OS RNG thất bại — đóng kết nối (fail-closed)");
                        return;
                    }
                    let server_eph = x25519_dalek::StaticSecret::from(server_seed);
                    let server_pk = x25519_dalek::PublicKey::from(&server_eph).to_bytes();
                    let (ack, mut session) = match crate::mesh::pipe_session::server_handle_pipe_hello(
                        &hello,
                        identity,
                        &server_eph,
                        &server_pk,
                    ) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("Bắt tay pipe thất bại: {e}");
                            send_plaintext_err(&mut server, "Handshake rejected").await;
                            return;
                        }
                    };
                    if server.write_all(&ack.encode()).await.is_err() || server.flush().await.is_err()
                    {
                        return;
                    }
                    info!("IPC phiên AEAD thiết lập xong (PID {:?})", client_pid);

                    // ---- Vòng lặp phiên: frame AEAD → envelope JSON → phản hồi ----
                    // Mỗi frame phải mở bằng tag AEAD hợp lệ; replay/tamper →
                    // đóng kết nối (client phải bắt tay lại).
                    loop {
                        let frame = match tokio::time::timeout(
                            Duration::from_secs(IPC_READ_TIMEOUT_SECS),
                            read_wire_frame(&mut server, MAX_IPC_FRAME_BOUND),
                        )
                        .await
                        {
                            Ok(Ok(f)) => f,
                            Ok(Err(e)) => {
                                info!("IPC kết nối kết thúc: {e}");
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
                        let (_frame_type, payload) = match session.open(&frame) {
                            Ok(x) => x,
                            Err(e) => {
                                // Replay/tamper — đóng ngay, không phản hồi.
                                warn!("Frame AEAD không hợp lệ, đóng kết nối: {e}");
                                return;
                            }
                        };
                        let mut resp =
                            handle_ipc_message_with(&payload, status_snap.as_ref());
                        // Đính kèm PID client do KERNEL xác nhận — PID tự khai
                        // trong envelope không đáng tin.
                        if let Some(data) = resp.data.as_mut() {
                            if let Some(obj) = data.as_object_mut() {
                                obj.insert(
                                    "server_seen_client_pid".to_string(),
                                    serde_json::json!(client_pid),
                                );
                            }
                        }
                        let resp_json = match serde_json::to_vec(&resp) {
                            Ok(j) => j,
                            Err(e) => {
                                error!("Serialize phản hồi thất bại: {e}");
                                return;
                            }
                        };
                        let out = match session.seal(1, &resp_json) {
                            Ok(o) => o,
                            Err(e) => {
                                error!("Seal phản hồi thất bại: {e}");
                                return;
                            }
                        };
                        if server.write_all(&out).await.is_err() || server.flush().await.is_err() {
                            return;
                        }
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

    /// Trần frame bắt tay (PipeHello/PipeHelloAck — kích thước nhỏ cố định).
    pub const PIPE_HANDSHAKE_MAX: usize = 512;
    /// Trần frame phiên: envelope ≤ 64KB + header AEAD + tag Poly1305.
    pub const MAX_IPC_FRAME_BOUND: usize = MAX_IPC_MESSAGE_SIZE + 128;

    /// Đọc 1 frame wire: `len(u32 BE) || body`. Chặn bound TRƯỚC khi cấp phát.
    async fn read_wire_frame(
        server: &mut tokio::net::windows::named_pipe::NamedPipeServer,
        max: usize,
    ) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        server.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame vượt giới hạn: {len}"),
            ));
        }
        let mut body = vec![0u8; len];
        server.read_exact(&mut body).await?;
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);
        Ok(full)
    }

    /// Phản hồi lỗi PRE-HANDSHAKE — plaintext CÓ CHỦ ĐÍCH: trước khi phiên
    /// AEAD thiết lập thì chưa có khóa để mã hóa; nội dung chỉ là lỗi chung
    /// chung, không lộ trạng thái nào (INV-012 không bị vi phạm vì không có
    /// envelope lệnh nào được phục vụ qua kênh plaintext).
    async fn send_plaintext_err(
        server: &mut tokio::net::windows::named_pipe::NamedPipeServer,
        error: &str,
    ) {
        let resp = IpcResponsePayload {
            message_id: "ERR".to_string(),
            success: false,
            data: None,
            error: Some(error.to_string()),
            timestamp: now_secs(),
        };
        if let Ok(resp_json) = serde_json::to_vec(&resp) {
            let _ = server.write_all(&resp_json).await;
            let _ = server.flush().await;
        }
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
