//! Monotonic Counter Verification (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5 Section 14, 15:
//! "Normally non-decreasing counters.
//! Check for impossible decrease and plausible growth limits."

use super::model::TemporalAnomaly;

pub struct MonotonicCounterChecker;

impl MonotonicCounterChecker {
    /// Kiểm tra tính đơn điệu của số giờ hoạt động (Power-On Hours)
    pub fn check_power_on_hours(
        current: Option<u64>,
        previous: Option<u64>,
        elapsed_seconds: u64,
    ) -> Option<TemporalAnomaly> {
        match (current, previous) {
            (Some(curr), Some(prev)) => {
                if curr < prev {
                    // Giờ chạy giảm trên cùng 1 thiết bị -> Phát hiện Rollback!
                    return Some(TemporalAnomaly::ImpossibleDecrease {
                        field: "power_on_hours".to_string(),
                        old_val: prev,
                        new_val: curr,
                    });
                }

                // Kiểm tra bước nhảy bất thường: Số giờ tăng không thể vượt quá thời gian trôi qua thực tế (+ sai số 2 giờ)
                let elapsed_hours = elapsed_seconds / 3600;
                let delta_hours = curr - prev;
                if delta_hours > elapsed_hours + 2 {
                    return Some(TemporalAnomaly::AbnormalJump {
                        field: "power_on_hours".to_string(),
                        delta: delta_hours,
                    });
                }

                None
            }
            _ => None,
        }
    }

    /// Kiểm tra tính đơn điệu của lượng dữ liệu ghi (TBW - Data Units Written)
    pub fn check_data_written(
        current: Option<u64>,
        previous: Option<u64>,
        elapsed_seconds: u64,
    ) -> Option<TemporalAnomaly> {
        match (current, previous) {
            (Some(curr), Some(prev)) => {
                if curr < prev {
                    return Some(TemporalAnomaly::ImpossibleDecrease {
                        field: "data_units_written_tb".to_string(),
                        old_val: prev,
                        new_val: curr,
                    });
                }

                // Giới hạn ghi vật lý tối đa của PCIe Gen4/Gen5 NVMe (~20 TB/giờ)
                let elapsed_hours = (elapsed_seconds / 3600).max(1);
                let delta_tb = curr - prev;
                let max_plausible_tb = elapsed_hours * 25; // 25 TB/h cực hạn
                if delta_tb > max_plausible_tb {
                    return Some(TemporalAnomaly::AbnormalJump {
                        field: "data_units_written_tb".to_string(),
                        delta: delta_tb,
                    });
                }

                None
            }
            _ => None,
        }
    }
}
