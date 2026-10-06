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
    /// Đồng hồ lùi lại so với thời điểm quan sát: không thể quyết định độ tươi
    /// (TTL/half-life bị vô hiệu) — phải được coi là không tin cậy, không phải Fresh.
    Unknown,
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
            // Trường hợp đồng hồ lùi lại (NTP chỉnh, VM resume, giả mạo):
            // mọi bằng chứng quan sát được "tương lai" là không đáng tin —
            // trả Unknown (fail-closed) thay vì Fresh (cũ) để TTL/decay có nghĩa.
            return FreshnessState::Unknown;
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
