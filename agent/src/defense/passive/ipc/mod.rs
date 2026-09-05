//! Hardened Authenticated IPC Subsystem (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! Pipe ACLs, Client Token Authorization, Strict Schema & Size Bounds.

pub mod authorization;
pub mod pipe_acl;
pub mod protocol;

pub use authorization::{IpcAuthorizer, IpcClientIdentity};
pub use pipe_acl::{PipeAclManager, PipeSecurityDescriptor};
pub use protocol::{
    IpcCommand, IpcMessageEnvelope, IpcProtocolError, IpcProtocolValidator, MAX_IPC_MESSAGE_SIZE,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcSecurityReport {
    pub pipe_descriptor: PipeSecurityDescriptor,
    pub is_acl_hardened: bool,
    pub is_protocol_bounded: bool,
    pub ipc_score: u32, // 0 - 10000
    pub summary: String,
}

impl IpcSecurityReport {
    pub fn standard_hardened(pipe_name: &str) -> Self {
        let desc = PipeAclManager::create_hardened_pipe_descriptor(pipe_name);
        Self {
            is_acl_hardened: desc.is_hardened,
            is_protocol_bounded: true,
            pipe_descriptor: desc,
            ipc_score: 10000,
            summary: format!(
                "Hardened IPC Pipe '{}' active (SYSTEM + User only, <=64KB)",
                pipe_name
            ),
        }
    }
}
