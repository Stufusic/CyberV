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
