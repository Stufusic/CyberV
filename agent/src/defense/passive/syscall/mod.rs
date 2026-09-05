//! Syscall & NTDLL Integrity Analyzer Subsystem (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 2 & Section 19:
//! "Syscall / NTDLL Integrity Analyzer - phát hiện và ghi nhận khách quan,
//! không tự chuyển sang đường thực thi bí mật (DirectSyscall) để bypass security product."

pub mod baseline;
pub mod hook_detector;
pub mod stub_integrity;

pub use baseline::{BaselineLifecycleManager, BaselineRefreshResult, NtdllBaseline};
pub use hook_detector::{FunctionIntegrityObservation, HookAssessment, NtdllIntegrityAnalyzer};
pub use stub_integrity::{StubIntegrityChecker, StubVariantAssessment};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtdllObservationReport {
    pub baseline_build: u32,
    pub total_analyzed_functions: usize,
    pub clean_functions_count: usize,
    pub suspected_functions_count: usize,
    pub edr_instrumented_count: usize,
    pub observations: Vec<FunctionIntegrityObservation>,
    pub summary: String,
}

impl NtdllObservationReport {
    pub fn new(baseline_build: u32, observations: Vec<FunctionIntegrityObservation>) -> Self {
        let total_analyzed_functions = observations.len();
        let clean_functions_count = observations
            .iter()
            .filter(|o| matches!(o.hook_assessment, HookAssessment::Clean))
            .count();
        let suspected_functions_count = observations
            .iter()
            .filter(|o| matches!(o.hook_assessment, HookAssessment::Suspected { .. }))
            .count();
        let edr_instrumented_count = observations
            .iter()
            .filter(|o| {
                matches!(
                    o.hook_assessment,
                    HookAssessment::KnownSecuritySoftwareInstrumentation { .. }
                )
            })
            .count();

        let summary = format!(
            "NTDLL Observation (Build {}): Total={}, Clean={}, Suspected={}, EDRInstrumented={}",
            baseline_build,
            total_analyzed_functions,
            clean_functions_count,
            suspected_functions_count,
            edr_instrumented_count
        );

        Self {
            baseline_build,
            total_analyzed_functions,
            clean_functions_count,
            suspected_functions_count,
            edr_instrumented_count,
            observations,
            summary,
        }
    }
}
