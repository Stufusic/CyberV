//! Startup Recovery & Crash Counter (P24.12)
//!
//! Ref: Docs/rv13.md Section 9:
//! Crash-loop detection and fallback configuration restoration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRecoveryStatus {
    pub crash_count: u32,
    pub is_fallback_needed: bool,
    pub last_known_good_version: u32,
}

pub struct StartupRecoveryTracker;

impl StartupRecoveryTracker {
    pub const CRASH_THRESHOLD_FOR_FALLBACK: u32 = 3;

    /// Kiểm tra xem có cần kích hoạt cấu hình fallback hay không
    pub fn check_recovery_state(crash_count: u32, last_good_ver: u32) -> StartupRecoveryStatus {
        let is_fallback_needed = crash_count >= Self::CRASH_THRESHOLD_FOR_FALLBACK;
        StartupRecoveryStatus {
            crash_count,
            is_fallback_needed,
            last_known_good_version: last_good_ver,
        }
    }
}
