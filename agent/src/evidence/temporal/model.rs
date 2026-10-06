// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! Temporal Trajectory & Storage Health Telemetry Models (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5 Section 14, 16, 18:
//! "StorageTrajectory: PowerOnHours, PowerCycles, DataUnitsWritten.
//! Anomaly classes: NORMAL_PROGRESS, IMPOSSIBLE_DECREASE, COUNTER_RESET, etc."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTrajectory {
    pub storage_id: String,
    pub power_on_hours: Option<u64>,
    pub power_cycles: Option<u64>,
    pub data_units_written_tb: Option<u64>,
    pub unsafe_shutdowns: Option<u64>,
    pub media_errors: Option<u64>,
    pub observed_at: u64, // Epoch seconds
}

impl StorageTrajectory {
    pub fn new(storage_id: impl Into<String>, observed_at: u64) -> Self {
        Self {
            storage_id: storage_id.into(),
            power_on_hours: None,
            power_cycles: None,
            data_units_written_tb: None,
            unsafe_shutdowns: None,
            media_errors: None,
            observed_at,
        }
    }
}

/// Các lớp phân loại dị thường theo thời gian (HCE-5 Section 18)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemporalAnomaly {
    /// Tiến triển bình thường theo thời gian thực (Giờ chạy và dữ liệu ghi tăng hợp lý)
    NormalProgress,
    /// Chưa đủ dữ liệu lịch sử (Lần quan sát đầu tiên của thiết bị)
    InsufficientHistory,
    /// Bộ đếm bị reset (Ví dụ: Reset phần cứng/Controller)
    CounterReset,
    /// Giảm bất khả thi (Giờ chạy hoặc TBW bị giảm trên cùng 1 ổ đĩa -> Phát hiện Rollback / Snapshot Revert)
    ImpossibleDecrease {
        field: String,
        old_val: u64,
        new_val: u64,
    },
    /// Bước nhảy thời gian bất thường (Ví dụ: 1 giờ ngoài đời nhưng TBW nhảy vọt 500TB)
    AbnormalJump { field: String, delta: u64 },
    /// Thay thế thiết bị lưu trữ mới hợp lệ
    DeviceReplacement,
    /// Không hỗ trợ dữ liệu S.M.A.R.T (Fail-Safe: UNKNOWN, không quy kết là giả mạo)
    MissingSmartData,
}

/// Đánh giá độ nhất quán theo thời gian
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalEvaluation {
    pub storage_id: String,
    pub anomaly: TemporalAnomaly,
    pub penalty: u32,            // 0 - 10000
    pub consistency_score: u32,  // 0 - 10000
    pub commitment_hash: String, // SHA-512 hex
    pub description: String,
}
