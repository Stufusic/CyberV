//! Temporal Anomaly Detector & Evaluation Engine (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5 Section 16, 17, 18, 19:
//! "Detect rollback, implausible transitions, cloned/replaced storage."

use super::counters::MonotonicCounterChecker;
use super::model::{StorageTrajectory, TemporalAnomaly, TemporalEvaluation};
use crate::fingerprint::canonical::CanonicalEncoder;
use sha2::{Digest, Sha512};

pub const DOMAIN_TEMPORAL_DRIFT: &[u8] = b"CYBERV/DBS/TEMPORAL_DRIFT/v1\0";

pub struct TemporalAnomalyDetector;

impl TemporalAnomalyDetector {
    /// Phân tích quỹ đạo biến thiên thời gian giữa hai thời điểm quan sát
    pub fn evaluate_drift(
        current: &StorageTrajectory,
        previous: Option<&StorageTrajectory>,
    ) -> TemporalEvaluation {
        // 1. Trường hợp lần quan sát đầu tiên của thiết bị
        let prev = match previous {
            Some(p) => p,
            None => {
                let commitment =
                    compute_temporal_commitment(&current.storage_id, "INSUFFICIENT_HISTORY", 10000);
                return TemporalEvaluation {
                    storage_id: current.storage_id.clone(),
                    anomaly: TemporalAnomaly::InsufficientHistory,
                    penalty: 0,
                    consistency_score: 10000,
                    commitment_hash: commitment,
                    description: "Khởi tạo quan sát mốc thời gian đầu tiên (T0)".to_string(),
                };
            }
        };

        // 2. Trường hợp thay thế ổ đĩa mới (Serial khác biệt)
        if current.storage_id != prev.storage_id {
            let commitment =
                compute_temporal_commitment(&current.storage_id, "DEVICE_REPLACEMENT", 10000);
            return TemporalEvaluation {
                storage_id: current.storage_id.clone(),
                anomaly: TemporalAnomaly::DeviceReplacement,
                penalty: 0,
                consistency_score: 10000,
                commitment_hash: commitment,
                description: "Nhận diện thay thế ổ cứng lưu trữ mới".to_string(),
            };
        }

        // 3. Trường hợp ổ đĩa không hỗ trợ S.M.A.R.T (Fail-Safe: UNKNOWN != INVALID)
        if current.power_on_hours.is_none() && current.data_units_written_tb.is_none() {
            let commitment =
                compute_temporal_commitment(&current.storage_id, "MISSING_SMART", 10000);
            return TemporalEvaluation {
                storage_id: current.storage_id.clone(),
                anomaly: TemporalAnomaly::MissingSmartData,
                penalty: 0,
                consistency_score: 10000,
                commitment_hash: commitment,
                description:
                    "Không có thông số S.M.A.R.T từ ổ đĩa (Fail-safe giữ nguyên độ tin cậy)"
                        .to_string(),
            };
        }

        let elapsed_seconds = current.observed_at.saturating_sub(prev.observed_at);

        // 4. Kiểm tra số giờ hoạt động (Power-On Hours)
        if let Some(anomaly) = MonotonicCounterChecker::check_power_on_hours(
            current.power_on_hours,
            prev.power_on_hours,
            elapsed_seconds,
        ) {
            let (penalty, score, desc) = match &anomaly {
                TemporalAnomaly::ImpossibleDecrease { old_val, new_val, .. } => (
                    8000,
                    2000,
                    format!("Phát hiện nghịch lý thời gian: Giờ hoạt động giảm từ {}h xuống {}h (Nghi ngờ khôi phục snapshot)", old_val, new_val),
                ),
                TemporalAnomaly::AbnormalJump { delta, .. } => (
                    3500,
                    6500,
                    format!("Số giờ hoạt động tăng đột biến bất thường (+{}h) so với thời gian thực", delta),
                ),
                _ => (0, 10000, "Bình thường".to_string()),
            };

            let commitment =
                compute_temporal_commitment(&current.storage_id, "HOURS_ANOMALY", score);
            return TemporalEvaluation {
                storage_id: current.storage_id.clone(),
                anomaly,
                penalty,
                consistency_score: score,
                commitment_hash: commitment,
                description: desc,
            };
        }

        // 5. Kiểm tra lượng dữ liệu ghi (TBW)
        if let Some(anomaly) = MonotonicCounterChecker::check_data_written(
            current.data_units_written_tb,
            prev.data_units_written_tb,
            elapsed_seconds,
        ) {
            let (penalty, score, desc) = match &anomaly {
                TemporalAnomaly::ImpossibleDecrease {
                    old_val, new_val, ..
                } => (
                    7500,
                    2500,
                    format!(
                        "Phát hiện nghịch lý dữ liệu ghi: TBW giảm từ {}TB xuống {}TB",
                        old_val, new_val
                    ),
                ),
                TemporalAnomaly::AbnormalJump { delta, .. } => (
                    4000,
                    6000,
                    format!("Lượng dữ liệu ghi tăng vọt bất thường (+{}TB)", delta),
                ),
                _ => (0, 10000, "Bình thường".to_string()),
            };

            let commitment = compute_temporal_commitment(&current.storage_id, "TBW_ANOMALY", score);
            return TemporalEvaluation {
                storage_id: current.storage_id.clone(),
                anomaly,
                penalty,
                consistency_score: score,
                commitment_hash: commitment,
                description: desc,
            };
        }

        // 6. Mọi biến thiên hoàn toàn hợp lý (Normal Progress)
        let commitment = compute_temporal_commitment(&current.storage_id, "NORMAL_PROGRESS", 10000);
        TemporalEvaluation {
            storage_id: current.storage_id.clone(),
            anomaly: TemporalAnomaly::NormalProgress,
            penalty: 0,
            consistency_score: 10000,
            commitment_hash: commitment,
            description: "Quỹ đạo thời gian và độ hao mòn phần cứng hoàn toàn nhất quán"
                .to_string(),
        }
    }
}

fn compute_temporal_commitment(storage_id: &str, status: &str, score: u32) -> String {
    let mut encoder = CanonicalEncoder::new();
    encoder.add_field("score", &score.to_string());
    encoder.add_field("status", status);
    encoder.add_field("storage_id", storage_id);

    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_TEMPORAL_DRIFT);
    hasher.update(encoder.to_canonical_bytes());
    format!("{:x}", hasher.finalize())
}
