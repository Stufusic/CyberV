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
//! System Code Integrity (CI/HVCI) Kernel Verifier (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 7, 8:
//! "CodeIntegrityVerifier: Truy vấn trạng thái Code Integrity qua NtQuerySystemInformation(SystemCodeIntegrityInformation)."
//!
//! P1-3: `query_kernel_ci()` giờ gọi NtQuerySystemInformation THẬT (ntdll).
//! Khi truy vấn thất bại → fail-closed (CI=off, testsign/debug coi như bật,
//! score 0) thay vì báo giá trị lành mạnh bịa.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemCodeIntegrityReport {
    pub is_ci_enabled: bool,
    pub is_hvci_kmci_enabled: bool,
    pub is_testsigning_active: bool,
    pub is_debugmode_active: bool,
    pub integrity_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct CodeIntegrityVerifier;

/// SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation = 103
#[cfg(windows)]
const SYSTEM_CODEINTEGRITY_INFORMATION: u32 = 103;

/// SYSTEM_CODEINTEGRITY_INFORMATION.CodeIntegrityOptions bit flags (Windows SDK)
#[cfg(windows)]
mod ci_flags {
    pub const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x1;
    pub const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x2;
    pub const CODEINTEGRITY_OPTION_DEBUGMODE: u32 = 0x4;
    pub const CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED: u32 = 0x400;
}

#[cfg(windows)]
#[repr(C)]
struct SystemCodeIntegrityInformation {
    length: u32,
    code_integrity_options: u32,
}

#[cfg(windows)]
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut u8,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32; // NTSTATUS
}

impl CodeIntegrityVerifier {
    /// Đánh giá trạng thái Code Integrity từ các cờ đã truy vấn (pure function)
    pub fn evaluate_status(
        is_ci_enabled: bool,
        is_hvci_kmci_enabled: bool,
        is_testsigning_active: bool,
        is_debugmode_active: bool,
    ) -> SystemCodeIntegrityReport {
        let mut score: u32 = 10000;

        if !is_ci_enabled {
            score = score.saturating_sub(5000);
        }
        if !is_hvci_kmci_enabled {
            score = score.saturating_sub(2000);
        }
        if is_testsigning_active {
            score = score.saturating_sub(4000); // Nguy cơ nạp driver tự ký
        }
        if is_debugmode_active {
            score = score.saturating_sub(2000); // Nguy cơ kernel debugging
        }

        let summary = format!(
            "System Code Integrity: CI={}, HVCI/KMCI={}, TestSigning={}, DebugMode={}, Score={}/10000",
            is_ci_enabled, is_hvci_kmci_enabled, is_testsigning_active, is_debugmode_active, score
        );

        SystemCodeIntegrityReport {
            is_ci_enabled,
            is_hvci_kmci_enabled,
            is_testsigning_active,
            is_debugmode_active,
            integrity_score: score,
            summary,
        }
    }

    /// P1-3: truy vấn CI/HVCI THẬT qua ntdll trên Windows x64.
    /// Truy vấn thất bại → fail-closed: coi như CI tắt + testsign/debug bật
    /// (score 0, phần tệ nhất) — tuyệt đối không báo lành mạnh giả.
    pub fn query_kernel_ci() -> SystemCodeIntegrityReport {
        #[cfg(windows)]
        {
            let mut info = SystemCodeIntegrityInformation {
                length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                code_integrity_options: 0,
            };
            let mut return_length: u32 = 0;

            // SAFETY: buffer 8 byte hợp lệ cho struct {u32, u32}; return_length hợp lệ
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_CODEINTEGRITY_INFORMATION,
                    &mut info as *mut _ as *mut u8,
                    std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                    &mut return_length,
                )
            };

            if status == 0 {
                // NTSTATUS_SUCCESS
                let o = info.code_integrity_options;
                let report = Self::evaluate_status(
                    o & ci_flags::CODEINTEGRITY_OPTION_ENABLED != 0,
                    o & ci_flags::CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED != 0,
                    o & ci_flags::CODEINTEGRITY_OPTION_TESTSIGN != 0,
                    o & ci_flags::CODEINTEGRITY_OPTION_DEBUGMODE != 0,
                );
                return SystemCodeIntegrityReport {
                    summary: format!("[queried via NtQuerySystemInformation] {}", report.summary),
                    ..report
                };
            }

            // Truy vấn thất bại: fail-closed (phần tệ nhất)
            let mut report = Self::evaluate_status(false, false, true, true);
            report.summary = format!(
                "[UNVERIFIED — NtQuerySystemInformation failed, NTSTATUS 0x{:08X}; fail-closed worst case] {}",
                status as u32, report.summary
            );
            report
        }
        #[cfg(not(windows))]
        {
            let mut report = Self::evaluate_status(false, false, true, true);
            report.summary = format!(
                "[UNVERIFIED — non-Windows platform; fail-closed worst case] {}",
                report.summary
            );
            report
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_status_scoring_is_pure() {
        let full = CodeIntegrityVerifier::evaluate_status(true, true, false, false);
        assert_eq!(full.integrity_score, 10000);

        let no_ci = CodeIntegrityVerifier::evaluate_status(false, true, false, false);
        assert_eq!(no_ci.integrity_score, 5000);

        let testsign = CodeIntegrityVerifier::evaluate_status(true, true, true, false);
        assert_eq!(testsign.integrity_score, 6000);
    }

    /// P1-3: trên Windows thật, query phải thực sự gọi API — summary ghi rõ
    /// nguồn; nếu query thất bại thì phải fail-closed (score 0).
    #[test]
    fn query_kernel_ci_reports_honest_source() {
        let report = CodeIntegrityVerifier::query_kernel_ci();
        if report.summary.contains("UNVERIFIED") {
            assert_eq!(report.integrity_score, 0, "query fail = score tệ nhất");
        } else {
            assert!(report.summary.contains("queried"), "{}", report.summary);
        }
    }
}
