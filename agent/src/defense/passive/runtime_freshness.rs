//! Evidence Freshness & Time-To-Live Subsystem (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 10:
//! "Evidence đó không nên có giá trị bằng checked 500ms ago.
//! Thêm EvidenceFreshness: observed_at, ttl_ms, fresh, stale, expired."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessState {
    Fresh,
    Stale,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFreshness {
    pub observed_at: u64,
    pub ttl_ms: u64,
}

impl EvidenceFreshness {
    pub const DEFAULT_RUNTIME_TTL_MS: u64 = 60_000; // 1 phút mặc định

    pub fn new(observed_at: u64, ttl_ms: u64) -> Self {
        Self {
            observed_at,
            ttl_ms,
        }
    }

    pub fn standard(observed_at: u64) -> Self {
        Self::new(observed_at, Self::DEFAULT_RUNTIME_TTL_MS)
    }

    pub fn evaluate_state(&self, current_time_ms: u64) -> FreshnessState {
        if current_time_ms < self.observed_at {
            // Trường hợp đồng hồ lùi lại: coi như Fresh nhưng cảnh báo
            return FreshnessState::Fresh;
        }

        let elapsed = current_time_ms - self.observed_at;
        if elapsed <= self.ttl_ms {
            FreshnessState::Fresh
        } else if elapsed <= self.ttl_ms * 2 {
            // Quá hạn 1x-2x TTL -> Stale
            FreshnessState::Stale
        } else {
            // Quá hạn > 2x TTL -> Expired
            FreshnessState::Expired
        }
    }

    pub fn is_fresh(&self, current_time_ms: u64) -> bool {
        self.evaluate_state(current_time_ms) == FreshnessState::Fresh
    }

    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        self.evaluate_state(current_time_ms) == FreshnessState::Expired
    }
}
