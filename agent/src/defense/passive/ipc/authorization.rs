//! IPC Client Authorization & Token Validation (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! "Authenticated IPC: Xác thực Client PID & Token SID trước khi xử lý thông điệp."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcClientIdentity {
    pub client_pid: u32,
    pub client_sid: String,
    pub executable_name: String,
    pub is_authenticated: bool,
}

pub struct IpcAuthorizer;

impl IpcAuthorizer {
    /// Kiểm tra xem client kết nối vào pipe có phải là thành phần CyberV được ủy quyền hay không
    pub fn authorize_client(
        client_pid: u32,
        client_sid: &str,
        executable_name: &str,
        expected_sid: &str,
    ) -> IpcClientIdentity {
        let is_sid_valid = client_sid == expected_sid;
        let is_known_component = executable_name == "CyberVAgent.exe"
            || executable_name == "CyberVWatchdog.exe"
            || executable_name == "CyberVUpdater.exe"
            || executable_name == "CyberVUi.exe";

        let is_authenticated = is_sid_valid && is_known_component && client_pid > 0;

        IpcClientIdentity {
            client_pid,
            client_sid: client_sid.to_string(),
            executable_name: executable_name.to_string(),
            is_authenticated,
        }
    }
}
