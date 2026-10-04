//! Windows Service Control Manager Integration & Daemon Packaging (Production Deployment)
//!
//! Ref: Docs/REQUIREMENTS.md Section 3 & 4
//! Provides native Windows Service lifecycle management for CyberV Agent:
//! - Service Name: `CyberVAgent`
//! - Start Type: Automatic (`SERVICE_AUTO_START`), Runs as `LocalSystem`
//! - Service Control Handler: Responds to STOP, SHUTDOWN, PAUSE, CONTINUE
//! - SCM Management: install, uninstall, start, stop, query status

pub const SERVICE_NAME: &str = "CyberVAgent";
pub const SERVICE_DISPLAY_NAME: &str = "CyberV Device-Binding Security Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Continuous hardware root-of-trust, kernel protection and attestation agent for CyberV.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown(u32),
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::NotInstalled => write!(f, "NOT_INSTALLED"),
            ServiceState::Stopped => write!(f, "STOPPED"),
            ServiceState::StartPending => write!(f, "START_PENDING"),
            ServiceState::StopPending => write!(f, "STOP_PENDING"),
            ServiceState::Running => write!(f, "RUNNING"),
            ServiceState::ContinuePending => write!(f, "CONTINUE_PENDING"),
            ServiceState::PausePending => write!(f, "PAUSE_PENDING"),
            ServiceState::Paused => write!(f, "PAUSED"),
            ServiceState::Unknown(code) => write!(f, "UNKNOWN ({})", code),
        }
    }
}

#[cfg(windows)]
mod win32_service {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::Foundation::{GetLastError, NO_ERROR};
    use windows_sys::Win32::System::Services::*;

    pub(crate) fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub fn get_current_exe_path() -> Result<PathBuf, String> {
        std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {}", e))
    }

    pub fn log_service_event(msg: &str) {
        if let Ok(program_data) = std::env::var("ProgramData") {
            let log_dir = std::path::Path::new(&program_data).join("CyberV").join("logs");
            let _ = std::fs::create_dir_all(&log_dir);
            let log_file = log_dir.join("agent_service.log");
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_file) {
                use std::io::Write;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = writeln!(file, "[{}] [PID:{}] {}", now, std::process::id(), msg);
            }
        }
    }

    /// Đăng ký CyberVAgent vào Windows Service Control Manager (SCM)
    pub fn install_service(custom_exe_path: Option<&std::path::Path>) -> Result<(), String> {
        let exe_path = match custom_exe_path {
            Some(p) => p.to_path_buf(),
            None => get_current_exe_path()?,
        };

        let binary_path_with_arg = format!("\"{}\" --service", exe_path.display());
        let wide_service_name = to_wide_null(SERVICE_NAME);
        let wide_display_name = to_wide_null(SERVICE_DISPLAY_NAME);
        let wide_bin_path = to_wide_null(&binary_path_with_arg);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
            if scm == 0 {
                return Err(format!(
                    "OpenSCManagerW failed (error code: {}). Make sure to run as Administrator.",
                    GetLastError()
                ));
            }

            let service = CreateServiceW(
                scm,
                wide_service_name.as_ptr(),
                wide_display_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                wide_bin_path.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(), // Runs under LocalSystem account
                std::ptr::null(),
            );

            if service == 0 {
                let err = GetLastError();
                CloseServiceHandle(scm);
                return Err(format!(
                    "CreateServiceW failed (error code: {}). If already installed, uninstall first.",
                    err
                ));
            }

            // Gán Description cho dịch vụ
            let wide_desc = to_wide_null(SERVICE_DESCRIPTION);
            let mut desc_info = SERVICE_DESCRIPTIONW {
                lpDescription: wide_desc.as_ptr() as *mut u16,
            };
            ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                &mut desc_info as *mut _ as *mut _,
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
        }

        Ok(())
    }

    /// Gỡ bỏ CyberVAgent khỏi Windows SCM
    pub fn uninstall_service() -> Result<(), String> {
        let wide_service_name = to_wide_null(SERVICE_NAME);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
            if scm == 0 {
                return Err(format!("OpenSCManagerW failed (error: {})", GetLastError()));
            }

            let service = OpenServiceW(scm, wide_service_name.as_ptr(), SERVICE_ALL_ACCESS);
            if service == 0 {
                let err = GetLastError();
                CloseServiceHandle(scm);
                return Err(format!("OpenServiceW failed (error: {})", err));
            }

            // Dừng dịch vụ nếu đang chạy
            let mut status: SERVICE_STATUS = std::mem::zeroed();
            ControlService(service, SERVICE_CONTROL_STOP, &mut status);

            let deleted = DeleteService(service);
            let err = GetLastError();

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if deleted == 0 {
                return Err(format!("DeleteService failed (error: {})", err));
            }
        }

        Ok(())
    }

    /// Khởi động dịch vụ qua SCM
    pub fn start_service() -> Result<(), String> {
        let wide_service_name = to_wide_null(SERVICE_NAME);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
            if scm == 0 {
                return Err(format!("OpenSCManagerW failed (error: {})", GetLastError()));
            }

            let service = OpenServiceW(scm, wide_service_name.as_ptr(), SERVICE_START);
            if service == 0 {
                let err = GetLastError();
                CloseServiceHandle(scm);
                return Err(format!("OpenServiceW failed (error: {})", err));
            }

            let res = StartServiceW(service, 0, std::ptr::null_mut());
            let err = GetLastError();

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if res == 0 && err != NO_ERROR {
                return Err(format!("StartServiceW failed (error: {})", err));
            }
        }

        Ok(())
    }

    /// Dừng dịch vụ qua SCM
    pub fn stop_service() -> Result<(), String> {
        let wide_service_name = to_wide_null(SERVICE_NAME);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
            if scm == 0 {
                return Err(format!("OpenSCManagerW failed (error: {})", GetLastError()));
            }

            let service = OpenServiceW(scm, wide_service_name.as_ptr(), SERVICE_STOP);
            if service == 0 {
                let err = GetLastError();
                CloseServiceHandle(scm);
                return Err(format!("OpenServiceW failed (error: {})", err));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let res = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            let err = GetLastError();

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if res == 0 {
                return Err(format!("ControlService(STOP) failed (error: {})", err));
            }
        }

        Ok(())
    }

    /// Truy vấn trạng thái dịch vụ hiện tại từ SCM
    pub fn query_service_status() -> Result<ServiceState, String> {
        let wide_service_name = to_wide_null(SERVICE_NAME);

        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm == 0 {
                return Err(format!("OpenSCManagerW failed (error: {})", GetLastError()));
            }

            let service = OpenServiceW(scm, wide_service_name.as_ptr(), SERVICE_QUERY_STATUS);
            if service == 0 {
                let err = GetLastError();
                CloseServiceHandle(scm);
                if err == 1060 {
                    return Ok(ServiceState::NotInstalled);
                }
                return Err(format!("OpenServiceW failed (error: {})", err));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let res = QueryServiceStatus(service, &mut status);
            let err = GetLastError();

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if res == 0 {
                return Err(format!("QueryServiceStatus failed (error: {})", err));
            }

            let state = match status.dwCurrentState {
                SERVICE_STOPPED => ServiceState::Stopped,
                SERVICE_START_PENDING => ServiceState::StartPending,
                SERVICE_STOP_PENDING => ServiceState::StopPending,
                SERVICE_RUNNING => ServiceState::Running,
                SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
                SERVICE_PAUSE_PENDING => ServiceState::PausePending,
                SERVICE_PAUSED => ServiceState::Paused,
                other => ServiceState::Unknown(other),
            };

            Ok(state)
        }
    }

    // Global state for service control handler
    static mut SERVICE_STATUS_HANDLE: isize = 0;
    static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" fn service_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut std::ffi::c_void,
        _context: *mut std::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                log_service_event("SCM control handler: received STOP/SHUTDOWN signal.");
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOP_PENDING,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 1,
                    dwWaitHint: 5000,
                };
                SetServiceStatus(SERVICE_STATUS_HANDLE, &status);
                SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
        }
    }

    unsafe extern "system" fn service_main_thunk(_argc: u32, _argv: *mut *mut u16) {
        log_service_event(&format!(
            "CyberVAgent service starting (PID: {}). Registering SCM Handler...",
            std::process::id()
        ));

        let wide_service_name = to_wide_null(SERVICE_NAME);
        let handle = RegisterServiceCtrlHandlerExW(
            wide_service_name.as_ptr(),
            Some(service_handler),
            std::ptr::null_mut(),
        );

        if handle == 0 {
            log_service_event(&format!(
                "RegisterServiceCtrlHandlerExW failed (error: {})",
                GetLastError()
            ));
            return;
        }

        SERVICE_STATUS_HANDLE = handle;

        // Report SERVICE_RUNNING
        let running_status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_RUNNING,
            dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        SetServiceStatus(handle, &running_status);
        log_service_event("Service status transitioned to SERVICE_RUNNING. Background security loop active.");

        // FIX C2 (FSE-1): Đăng ký PID tiến trình vào Ring-0 Shield ngay khi
        // service khởi động — trước đây agent không bao giờ gọi IOCTL đăng ký
        // nên ObCallbacks không bao giờ có mục tiêu để bảo vệ.
        attempt_kernel_shield_registration();

        // P1-2: SharedAgentStatus — snapshot trạng thái daemon thật cho IPC GetStatus
        let agent_status = crate::daemon_runner::new_shared_status();
        let heartbeat_status = agent_status.clone();

        // Spawn Tokio runtime thread: IPC Named Pipe Server + AgentDaemon thật
        // (nếu có cấu hình). Không config = keep-alive only, trạng thái UNKNOWN
        // fail-closed — tuyệt đối không chạy daemon với giá trị đoán.
        std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                rt.block_on(async {
                    // P1-1: khóa identity cho handshake pipe (từ DPAPI vault).
                    // Không nạp được = server chạy fail-closed (mọi kết nối
                    // chỉ nhận ERR) — không bao giờ phục vụ phiên plaintext.
                    let pipe_identity =
                        crate::daemon_runner::load_or_create_identity().ok().map(|(k, _)| k);
                    // P1-1b: xuất public key cho UI pin (best-effort). UI đọc
                    // file này để pin khóa agent — thiếu file → UI fail-closed
                    // UNKNOWN. ProgramData do SYSTEM ghi: Users chỉ đọc được,
                    // không thay thế được (pinning trust anchor).
                    if let Some(ref key) = pipe_identity {
                        let pub_hex = key.public_key_hex();
                        let pin_dir = std::env::var("PROGRAMDATA").unwrap_or_default();
                        if !pin_dir.is_empty() {
                            let dir = std::path::Path::new(&pin_dir).join("CyberV");
                            let pin_path = dir.join("agent_public_key.hex");
                            match std::fs::create_dir_all(&dir)
                                .and_then(|_| std::fs::write(&pin_path, format!("{}\n", pub_hex)))
                            {
                                Ok(()) => log_service_event(&format!(
                                    "IPC: agent public key published cho UI pinning ({})",
                                    pin_path.display()
                                )),
                                Err(e) => log_service_event(&format!(
                                    "IPC: KHÔNG publish được public key ({e}) — UI sẽ fail-closed"
                                )),
                            }
                        }
                    }
                    let server = crate::defense::passive::ipc::server::win_server::NamedPipeServer::new(
                        crate::defense::passive::ipc::server::DEFAULT_PIPE_NAME,
                    )
                    .with_status_snapshot(agent_status.clone())
                    .with_identity_key_opt(pipe_identity);
                    let ipc_task = tokio::spawn(async move {
                        let _ = server.run_server().await;
                    });

                    match crate::service_config::AgentServiceConfig::load_from_default_path() {
                        Ok(Some(config)) => {
                            log_service_event(&format!(
                                "Daemon: config loaded — starting real AgentDaemon loop (interval {}s).",
                                config.attestation_interval_secs
                            ));
                            let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                            // Bridge SHUTDOWN_FLAG (static) -> Arc flag của loop
                            {
                                let flag = shutdown_flag.clone();
                                tokio::spawn(async move {
                                    loop {
                                        if SHUTDOWN_FLAG.load(Ordering::SeqCst) {
                                            flag.store(true, Ordering::SeqCst);
                                            break;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                    }
                                });
                            }
                            let run_result = crate::daemon_runner::run_configured_daemon(
                                config,
                                agent_status.clone(),
                                shutdown_flag,
                            )
                            .await;
                            match run_result {
                                Ok(()) => log_service_event("Daemon loop ended cleanly (shutdown)."),
                                Err(e) => log_service_event(&format!("Daemon loop stopped: {}", e)),
                            }
                        }
                        Ok(None) => {
                            log_service_event(
                                "Daemon NOT WIRED: no agent_config.json found (fail-closed UNKNOWN status). Place config at %ProgramData%/CyberV/agent_config.json.",
                            );
                        }
                        Err(e) => {
                            log_service_event(&format!("Daemon NOT WIRED: config error: {}", e));
                        }
                    }

                    let _ = ipc_task.await;
                });
            }
        });

        // Heartbeat — TRUNG THỰC: phản ánh trạng thái daemon thật từ snapshot
        // (hoặc NOT WIRED khi chưa cấu hình), không bao giờ tuyên bố "intact".
        let mut tick_count = 0u64;
        while !SHUTDOWN_FLAG.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(5));
            tick_count += 1;
            if tick_count.is_multiple_of(12) {
                let status_line = match heartbeat_status.read() {
                    Ok(guard) => match guard.as_ref() {
                        Some(snap) => format!(
                            "daemon state={} driver={} last_attested={}",
                            snap.state,
                            if snap.driver_available { "yes" } else { "no" },
                            snap.last_attested_at.map(|t| t.to_string()).unwrap_or_else(|| "never".to_string())
                        ),
                        None => "daemon: no snapshot yet".to_string(),
                    },
                    Err(_) => "daemon: status lock poisoned".to_string(),
                };
                log_service_event(&format!(
                    "Service Heartbeat: Iteration #{}. Monitoring: {}.",
                    tick_count / 12,
                    status_line
                ));
            }
        }

        log_service_event("Exiting background security loop. Transitioning to SERVICE_STOPPED...");

        // Report SERVICE_STOPPED
        let stopped_status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_STOPPED,
            dwControlsAccepted: 0,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        SetServiceStatus(handle, &stopped_status);
        log_service_event("Service stopped cleanly.");
    }

    /// Khởi chạy vòng lặp Service Dispatcher của Windows
    pub fn run_service_dispatcher() -> Result<(), String> {
        let mut wide_service_name = to_wide_null(SERVICE_NAME);
        let service_table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: wide_service_name.as_mut_ptr(),
                lpServiceProc: Some(service_main_thunk),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        unsafe {
            let res = StartServiceCtrlDispatcherW(service_table.as_ptr());
            if res == 0 {
                let err = GetLastError();
                return Err(format!(
                    "StartServiceCtrlDispatcherW failed (error: {}). Are you running inside Windows Service SCM?",
                    err
                ));
            }
        }

        Ok(())
    }
}

// Public API
#[cfg(windows)]
pub use win32_service::*;

#[cfg(not(windows))]
pub fn install_service(_custom_exe_path: Option<&std::path::Path>) -> Result<(), String> {
    Err("Windows Service management is only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn uninstall_service() -> Result<(), String> {
    Err("Windows Service management is only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn start_service() -> Result<(), String> {
    Err("Windows Service management is only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn stop_service() -> Result<(), String> {
    Err("Windows Service management is only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn query_service_status() -> Result<ServiceState, String> {
    Err("Windows Service management is only supported on Windows".to_string())
}

#[cfg(not(windows))]
pub fn run_service_dispatcher() -> Result<(), String> {
    Err("Windows Service dispatcher is only supported on Windows".to_string())
}

/// Đăng ký tiến trình service vào Ring-0 Shield (FSE-1 / FIX C2).
/// Kết quả phải được ghi log TRUNG THỰC: driver vắng mặt hay IOCTL lỗi
/// là thông tin an ninh quan trọng, không được nuốt im lặng.
#[cfg(windows)]
fn attempt_kernel_shield_registration() {
    use crate::defense::kernel::registration::ProtectedProcessRegistration;
    use crate::kernel::client::WindowsKernelClient;

    let reg = ProtectedProcessRegistration::current("cyberv-service-boot", 1);

    // Suy 64 byte nonce từ chuỗi đăng ký (driver hiện lưu nhưng chưa dùng —
    // trường giữ chỗ cho giao thức xác thực phiên driver trong tương lai)
    let mut nonce = [0u8; 64];
    for (i, b) in reg.registration_nonce.as_bytes().iter().take(64).enumerate() {
        nonce[i] = *b;
    }

    let client = WindowsKernelClient::new();
    match client.register_protected_pid(reg.pid, reg.process_start_time, nonce) {
        Ok(()) => log_service_event(&format!(
            "Kernel Shield: registered PID {} (create FILETIME {}) for ObCallbacks protection.",
            reg.pid, reg.process_start_time
        )),
        Err(e) => log_service_event(&format!(
            "Kernel Shield: registration UNAVAILABLE (fail-open for agent process, no shield): {}",
            e
        )),
    }
}

#[cfg(not(windows))]
pub fn log_service_event(_msg: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_constants() {
        assert_eq!(SERVICE_NAME, "CyberVAgent");
        assert!(SERVICE_DISPLAY_NAME.contains("CyberV"));
        assert!(SERVICE_DESCRIPTION.contains("root-of-trust"));
    }

    #[test]
    fn test_service_state_display() {
        assert_eq!(format!("{}", ServiceState::NotInstalled), "NOT_INSTALLED");
        assert_eq!(format!("{}", ServiceState::Stopped), "STOPPED");
        assert_eq!(format!("{}", ServiceState::StartPending), "START_PENDING");
        assert_eq!(format!("{}", ServiceState::StopPending), "STOP_PENDING");
        assert_eq!(format!("{}", ServiceState::Running), "RUNNING");
        assert_eq!(format!("{}", ServiceState::ContinuePending), "CONTINUE_PENDING");
        assert_eq!(format!("{}", ServiceState::PausePending), "PAUSE_PENDING");
        assert_eq!(format!("{}", ServiceState::Paused), "PAUSED");
        assert_eq!(format!("{}", ServiceState::Unknown(99)), "UNKNOWN (99)");
    }

    #[cfg(windows)]
    #[test]
    fn test_current_exe_path_resolution() {
        let exe = get_current_exe_path().expect("Must resolve current exe path");
        assert!(exe.exists());
        assert!(exe.to_string_lossy().ends_with(".exe"));
    }

    #[cfg(windows)]
    #[test]
    fn test_to_wide_null() {
        let wide = win32_service::to_wide_null("Test");
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(wide.len(), 5); // T, e, s, t, 0
    }
}

