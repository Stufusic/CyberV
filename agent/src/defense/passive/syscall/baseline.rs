//! NTDLL & Syscall Baseline Lifecycle Management (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 11:
//! "Phải có OS Build, Architecture, Module Version, Module Path, Image Identity, Baseline Version.
//! Nếu Windows Update thay ntdll.dll hợp lệ: old baseline -> new OS build -> baseline refresh -> NOT TAMPERING."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtdllBaseline {
    pub os_build: u32,
    pub architecture: String,
    pub module_sha512: String,
    pub baseline_version: u32,
    pub approved_preambles: Vec<Vec<u8>>,
}

impl NtdllBaseline {
    /// Baseline tiêu chuẩn cho Windows 10/11 x64 hiện đại
    pub fn standard_windows_x64(os_build: u32, sha512: &str) -> Self {
        // Các biến thể preamble hợp lệ của Windows x64:
        // 1. mov r10, rcx; mov eax, <ssn> (4c 8b d1 b8)
        // 2. mov eax, <ssn>; mov r10, rcx (b8 ... 4c 8b d1)
        Self {
            os_build,
            architecture: "x86_64".to_string(),
            module_sha512: sha512.to_string(),
            baseline_version: 1,
            approved_preambles: vec![
                vec![0x4C, 0x8B, 0xD1, 0xB8], // mov r10, rcx; mov eax, ...
                vec![0xB8, 0x00, 0x00, 0x00], // mov eax, ...
            ],
        }
    }
}

pub struct BaselineLifecycleManager {
    current_baseline: NtdllBaseline,
    history: Vec<NtdllBaseline>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaselineRefreshResult {
    UpdatedLegitimateOsUpgrade {
        old_build: u32,
        new_build: u32,
    },
    ReplacedSameBuildMaintenance {
        build: u32,
    },
    RejectedUnapprovedDowngrade {
        current_build: u32,
        target_build: u32,
    },
}

impl BaselineLifecycleManager {
    pub fn new(initial: NtdllBaseline) -> Self {
        Self {
            current_baseline: initial,
            history: Vec::new(),
        }
    }

    pub fn current(&self) -> &NtdllBaseline {
        &self.current_baseline
    }

    /// Đánh giá và cập nhật baseline khi có Windows Update hoặc bảo trì hệ thống
    pub fn evaluate_and_refresh(&mut self, candidate: NtdllBaseline) -> BaselineRefreshResult {
        if candidate.os_build < self.current_baseline.os_build {
            return BaselineRefreshResult::RejectedUnapprovedDowngrade {
                current_build: self.current_baseline.os_build,
                target_build: candidate.os_build,
            };
        }

        let old = std::mem::replace(&mut self.current_baseline, candidate);
        let result = if self.current_baseline.os_build > old.os_build {
            BaselineRefreshResult::UpdatedLegitimateOsUpgrade {
                old_build: old.os_build,
                new_build: self.current_baseline.os_build,
            }
        } else {
            BaselineRefreshResult::ReplacedSameBuildMaintenance {
                build: self.current_baseline.os_build,
            }
        };

        self.history.push(old);
        result
    }

    pub fn history_count(&self) -> usize {
        self.history.len()
    }
}
