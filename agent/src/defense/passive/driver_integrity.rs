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
//! Kernel Driver Integrity Verification (P24.5)
//!
//! Ref: Docs/rv13.md Section 4:
//! "Driver Integrity còn thiếu — cybervprobe.sys phải được coi là security-critical binary.
//! Không chỉ 'driver đang chạy' mà: 'đúng driver + đúng signer + đúng version + đúng image'."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverIntegrityReport {
    pub driver_name: String,
    pub expected_publisher: String,
    pub actual_publisher: String,
    pub image_sha512: String,
    pub expected_sha512: String,
    pub driver_version: String,
    pub expected_version: String,
    pub is_loaded: bool,
    pub is_signer_valid: bool,
    pub is_hash_matched: bool,
    pub is_version_compliant: bool,
    pub driver_integrity_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct DriverIntegrityChecker;

impl DriverIntegrityChecker {
    pub const EXPECTED_DRIVER_NAME: &'static str = "cybervprobe.sys";
    pub const EXPECTED_PUBLISHER: &'static str = "CyberV Security Corporation (WHQL)";
    pub const EXPECTED_VERSION: &'static str = "1.0.0";

    /// Kiểm tra tính toàn vẹn đa lớp của driver CyberVProbe
    pub fn verify_driver(
        actual_publisher: &str,
        image_sha512: &str,
        expected_sha512: &str,
        actual_version: &str,
        is_loaded: bool,
    ) -> DriverIntegrityReport {
        let is_signer_valid = actual_publisher == Self::EXPECTED_PUBLISHER;
        let is_hash_matched = image_sha512 == expected_sha512 && !image_sha512.is_empty();
        let is_version_compliant = actual_version == Self::EXPECTED_VERSION;

        let mut score: u32 = 0;
        if is_loaded {
            score += 2000;
        }
        if is_signer_valid {
            score += 3000;
        }
        if is_hash_matched {
            score += 3000;
        }
        if is_version_compliant {
            score += 2000;
        }

        let summary = format!(
            "Driver Integrity ({}): Loaded={}, Signer={}, HashMatch={}, VersionMatch={} (Score: {}/10000)",
            Self::EXPECTED_DRIVER_NAME,
            is_loaded,
            is_signer_valid,
            is_hash_matched,
            is_version_compliant,
            score
        );

        DriverIntegrityReport {
            driver_name: Self::EXPECTED_DRIVER_NAME.to_string(),
            expected_publisher: Self::EXPECTED_PUBLISHER.to_string(),
            actual_publisher: actual_publisher.to_string(),
            image_sha512: image_sha512.to_string(),
            expected_sha512: expected_sha512.to_string(),
            driver_version: actual_version.to_string(),
            expected_version: Self::EXPECTED_VERSION.to_string(),
            is_loaded,
            is_signer_valid,
            is_hash_matched,
            is_version_compliant,
            driver_integrity_score: score,
            summary,
        }
    }
}
