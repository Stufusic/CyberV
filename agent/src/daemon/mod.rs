//! CyberV Agent Daemon Layer
//!
//! Ref: Plan.md Section 1, 15, 17, Rule.md Điều 1, 15, 17:
//! Tiến trình daemon chạy nền giám sát biến động phần cứng và thực hiện chứng thực định kỳ.

pub mod engine;

pub use engine::*;

use serde::{Deserialize, Serialize};

/// Trạng thái hoạt động của Agent Daemon
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Chưa đăng ký thiết bị với Server
    Unregistered,

    /// Đang hoạt động bình thường, phần cứng khớp 100%
    Active {
        graph_version: u32,
        state_hash: String,
        last_attested_at: u64,
    },

    /// Phát hiện thay đổi linh kiện, cần re-enroll
    HardwareMutated {
        previous_graph_version: u32,
        previous_state_hash: String,
        new_state_hash: String,
    },

    /// Yêu cầu Re-enrollment đang chờ người dùng duyệt trên Dashboard
    PendingApproval {
        request_id: Option<String>,
        submitted_at: u64,
    },

    /// Mất kết nối internet nhưng vẫn trong thời gian ân hạn an toàn
    OfflineGracePeriod {
        consecutive_failures: u32,
        last_success_at: u64,
    },

    /// Bị Server khóa/từ chối do vi phạm bảo mật
    SuspendedOrRejected { reason: String },
}

/// Cấu hình cho Agent Daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub attestation_interval_secs: u64,
    pub max_offline_grace_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            attestation_interval_secs: 300, // 5 phút
            max_offline_grace_secs: 86400,  // 24 giờ
        }
    }
}
