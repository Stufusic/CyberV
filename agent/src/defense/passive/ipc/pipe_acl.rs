//! Hardened Named Pipe DACL Security (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! "Only expected principals (SYSTEM + Current User SID) + Deny Everyone/Network."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeSecurityDescriptor {
    pub pipe_name: String,
    pub allows_system: bool,
    pub allows_current_user: bool,
    pub denies_everyone: bool,
    pub denies_network_logon: bool,
    pub is_hardened: bool,
}

pub struct PipeAclManager;

impl PipeAclManager {
    /// Tạo cấu hình bảo mật DACL cho Named Pipe
    pub fn create_hardened_pipe_descriptor(pipe_name: impl Into<String>) -> PipeSecurityDescriptor {
        PipeSecurityDescriptor {
            pipe_name: pipe_name.into(),
            allows_system: true,
            allows_current_user: true,
            denies_everyone: true,
            denies_network_logon: true,
            is_hardened: true,
        }
    }
}
