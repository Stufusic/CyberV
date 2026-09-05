//! Safe Mode Machine for Passive Foundation (P24.12)
//!
//! Ref: Docs/rv13.md Section 9:
//! "NORMAL -> DEGRADED -> RECOVERY -> SAFE_MODE -> RESTORED.
//! Giữ vững tính khả dụng, không làm chết máy người dùng khi gặp lỗi tương thích."

use crate::security::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PassiveSystemState {
    Normal,
    Degraded,
    Recovery,
    SafeMode,
    Restored,
}

pub struct SafeModeManager;

impl SafeModeManager {
    /// Đánh giá trạng thái hệ thống dựa trên số lần crash khởi động
    pub fn evaluate_crash_recovery(
        consecutive_crashes: u32,
    ) -> (PassiveSystemState, AssuranceLevel) {
        match consecutive_crashes {
            0 => (PassiveSystemState::Normal, AssuranceLevel::Attested),
            1..=2 => (PassiveSystemState::Degraded, AssuranceLevel::OSProtected),
            3..=4 => (PassiveSystemState::Recovery, AssuranceLevel::OSProtected),
            _ => (PassiveSystemState::SafeMode, AssuranceLevel::Software),
        }
    }

    /// Khôi phục từ SafeMode về Restored sau khi hoàn tất sửa chữa cấu hình
    pub fn restore_from_safe_mode() -> PassiveSystemState {
        PassiveSystemState::Restored
    }
}
