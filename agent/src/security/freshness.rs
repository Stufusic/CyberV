//! Evidence Freshness & Decay Model (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 8:
//! "Freshness: Evidence lấy 3 ngày trước thì giá trị khác hoàn toàn.
//! Fresh evidence -> High confidence; Stale evidence -> Confidence decay; Expired -> UNKNOWN."

use super::assurance::AssuranceLevel;
use crate::evidence::unified::EvidenceSource;
use serde::{Deserialize, Serialize};

/// Siêu dữ liệu thời gian và độ tin cậy của bằng chứng
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMetadata {
    pub observed_at: u64,
    pub expires_at: Option<u64>,
    pub source: EvidenceSource,
    /// Độ tin cậy ban đầu (0 - 10000)
    pub confidence: u16,
    pub assurance: AssuranceLevel,
    pub derivation_version: u32,
}

impl EvidenceMetadata {
    pub fn new(
        observed_at: u64,
        ttl_seconds: Option<u64>,
        source: EvidenceSource,
        confidence: u16,
        assurance: AssuranceLevel,
        derivation_version: u32,
    ) -> Self {
        let expires_at = ttl_seconds.map(|ttl| observed_at + ttl);
        Self {
            observed_at,
            expires_at,
            source,
            confidence: confidence.min(10000),
            assurance,
            derivation_version,
        }
    }

    /// Kiểm tra xem bằng chứng còn trong thời hạn hay đã hết hạn hoàn toàn
    pub fn is_fresh(&self, now: u64) -> bool {
        match self.expires_at {
            Some(exp) => now <= exp,
            None => true, // Bằng chứng vĩnh viễn
        }
    }

    /// Tính toán độ tin cậy thực tế tại thời điểm `now` (Toán học số nguyên 100%)
    /// Suy giảm tuyến tính / bậc thang theo thời gian trôi qua
    pub fn effective_confidence(&self, now: u64, half_life_secs: u64) -> u16 {
        if !self.is_fresh(now) {
            return 0; // Hết hạn -> UNKNOWN (0)
        }

        if now <= self.observed_at || half_life_secs == 0 {
            return self.confidence;
        }

        let elapsed = now - self.observed_at;

        // Mô hình suy giảm số nguyên (Integer Half-Life Decay):
        // Sau mỗi half_life_secs, độ tin cậy giảm một nửa:
        // effective = confidence * (10000 / (10000 + 10000 * elapsed / half_life_secs))
        let factor = 10000u64;
        let penalty_ratio = (factor * elapsed) / half_life_secs;
        let divisor = factor + penalty_ratio;

        let effective = ((self.confidence as u64) * factor) / divisor;
        (effective as u16).min(10000)
    }
}
