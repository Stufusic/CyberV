//! Shield Telemetry & Handle Operations (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Handle-operation telemetry: Đừng chỉ block. Phân biệt ALLOW, DENY, SUSPICIOUS, UNKNOWN
//! và đưa event vào Evidence Graph."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandleOperationResult {
    Allow,
    Deny,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldTelemetry {
    pub protected_pid: u32,
    pub blocked_terminations: u32,
    pub blocked_vm_reads: u32,
    pub blocked_vm_writes: u32,
    pub suspicious_attempts: u32,
    pub driver_unload_attempts: u32,
    pub is_shield_active: bool,
}

impl ShieldTelemetry {
    pub fn active(protected_pid: u32) -> Self {
        Self {
            protected_pid,
            blocked_terminations: 0,
            blocked_vm_reads: 0,
            blocked_vm_writes: 0,
            suspicious_attempts: 0,
            driver_unload_attempts: 0,
            is_shield_active: true,
        }
    }

    pub fn inactive() -> Self {
        Self {
            protected_pid: 0,
            blocked_terminations: 0,
            blocked_vm_reads: 0,
            blocked_vm_writes: 0,
            suspicious_attempts: 0,
            driver_unload_attempts: 0,
            is_shield_active: false,
        }
    }

    pub fn total_blocked(&self) -> u32 {
        self.blocked_terminations + self.blocked_vm_reads + self.blocked_vm_writes
    }

    pub fn has_tampering_attempts(&self) -> bool {
        self.total_blocked() > 0 || self.suspicious_attempts > 0 || self.driver_unload_attempts > 0
    }
}
