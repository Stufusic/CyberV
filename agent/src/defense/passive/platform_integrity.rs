// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
//! Platform & Boot Chain Integrity (P24.9)
//!
//! Ref: Docs/rv13.md Section 3:
//! "Platform Integrity: secure_boot, measured_boot, boot_configuration, platform_state.
//! Tích hợp trạng thái Secure Boot DBX Precedence và TPM Measured Boot vào Passive Foundation."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformIntegrityReport {
    pub is_secure_boot_active: bool,
    pub is_measured_boot_active: bool,
    pub is_dbx_precedence_enforced: bool,
    pub pcr0_firmware_sha512: String,
    pub pcr7_secure_boot_sha512: String,
    pub confidence: u16,
    pub freshness: u16,
    pub platform_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct PlatformIntegrityChecker;

impl PlatformIntegrityChecker {
    /// Đánh giá trạng thái chuỗi khởi động nền tảng (Platform Boot Chain)
    pub fn evaluate(
        secure_boot_active: bool,
        measured_boot_active: bool,
        dbx_precedence_enforced: bool,
        pcr0_hex: &str,
        pcr7_hex: &str,
    ) -> PlatformIntegrityReport {
        let mut score: u32 = 0;
        if secure_boot_active {
            score += 3000;
        }
        if measured_boot_active {
            score += 3000;
        }
        if dbx_precedence_enforced {
            score += 2000;
        }
        if !pcr0_hex.is_empty() && !pcr7_hex.is_empty() {
            score += 2000;
        }

        let summary = format!(
            "Platform Integrity: SecureBoot={}, MeasuredBoot={}, DbxPrecedence={}, PCRs={}/{} (Score: {}/10000)",
            secure_boot_active,
            measured_boot_active,
            dbx_precedence_enforced,
            !pcr0_hex.is_empty(),
            !pcr7_hex.is_empty(),
            score
        );

        PlatformIntegrityReport {
            is_secure_boot_active: secure_boot_active,
            is_measured_boot_active: measured_boot_active,
            is_dbx_precedence_enforced: dbx_precedence_enforced,
            pcr0_firmware_sha512: pcr0_hex.to_string(),
            pcr7_secure_boot_sha512: pcr7_hex.to_string(),
            confidence: 10000,
            freshness: 10000,
            platform_score: score,
            summary,
        }
    }
}
