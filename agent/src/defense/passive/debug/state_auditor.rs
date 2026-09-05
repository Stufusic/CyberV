//! Execution Instrumentation & Debug State Auditor (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 7, 8, 9:
//! "Debug State Auditor: Phân biệt rõ ràng giữa tín hiệu:
//! - PEB signal = LOW confidence
//! - DRx evidence = MEDIUM confidence
//! - Process Mitigation = HIGH confidence
//!
//! Debug registers gắn với thread execution context; kiểm tra đáng tin cậy phải xét context của các threads."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugSignalConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugStateAssessment {
    NoEvidence,
    PossibleInstrumentation,
    DebugStateDetected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadDebugContext {
    pub thread_id: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub has_hardware_breakpoint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugInstrumentationReport {
    pub is_peb_being_debugged: bool,
    pub peb_signal_confidence: DebugSignalConfidence,
    pub is_nt_global_flag_active: bool,
    pub total_threads_audited: usize,
    pub threads_with_hardware_breakpoints: usize,
    pub overall_assessment: DebugStateAssessment,
    pub thread_contexts: Vec<ThreadDebugContext>,
    pub summary: String,
}

pub struct DebugStateAuditor;

impl DebugStateAuditor {
    /// Đánh giá ngữ cảnh gỡ lỗi của một luồng thực thi cụ thể
    pub fn assess_thread_context(
        thread_id: u32,
        dr0: u64,
        dr1: u64,
        dr2: u64,
        dr3: u64,
        dr6: u64,
        dr7: u64,
    ) -> ThreadDebugContext {
        // DR7: Cờ kích hoạt breakpoint cục bộ hoặc toàn cục cho DR0..DR3
        // Các bit lẻ/chẵn 0..7 trong DR7 điều khiển kích hoạt L0..L3 và G0..G3
        let is_dr0_active = (dr7 & 0x03) != 0 && dr0 != 0;
        let is_dr1_active = (dr7 & 0x0C) != 0 && dr1 != 0;
        let is_dr2_active = (dr7 & 0x30) != 0 && dr2 != 0;
        let is_dr3_active = (dr7 & 0xC0) != 0 && dr3 != 0;

        let has_hardware_breakpoint =
            is_dr0_active || is_dr1_active || is_dr2_active || is_dr3_active;

        ThreadDebugContext {
            thread_id,
            dr0,
            dr1,
            dr2,
            dr3,
            dr6,
            dr7,
            has_hardware_breakpoint,
        }
    }

    /// Đánh giá tổng thể trạng thái gỡ lỗi trên tiến trình
    pub fn audit_process_debug_state(
        peb_being_debugged: bool,
        nt_global_flag: u32,
        thread_raw_contexts: &[(u32, u64, u64, u64, u64, u64, u64)],
    ) -> DebugInstrumentationReport {
        let is_nt_global_flag_active = (nt_global_flag & 0x70) != 0; // FLG_HEAP_* validation flags

        let thread_contexts: Vec<ThreadDebugContext> = thread_raw_contexts
            .iter()
            .map(|&(tid, dr0, dr1, dr2, dr3, dr6, dr7)| {
                Self::assess_thread_context(tid, dr0, dr1, dr2, dr3, dr6, dr7)
            })
            .collect();

        let threads_with_hardware_breakpoints = thread_contexts
            .iter()
            .filter(|tc| tc.has_hardware_breakpoint)
            .count();

        // Đánh giá trạng thái tổng thể dựa trên phân tầng trọng số
        let overall_assessment = if threads_with_hardware_breakpoints > 0 {
            // Tín hiệu phần cứng (DRx) có độ tin cậy Medium/High
            DebugStateAssessment::DebugStateDetected
        } else if peb_being_debugged || is_nt_global_flag_active {
            // Chỉ có cờ PEB (dễ bị phần mềm hook/test tool bật) -> PossibleInstrumentation
            DebugStateAssessment::PossibleInstrumentation
        } else {
            DebugStateAssessment::NoEvidence
        };

        let summary = format!(
            "Debug State: Assessment={:?}, PEB_Debugged={}, NtGlobalFlag={}, Threads={}/{} WithHardwareBP",
            overall_assessment,
            peb_being_debugged,
            is_nt_global_flag_active,
            threads_with_hardware_breakpoints,
            thread_contexts.len()
        );

        DebugInstrumentationReport {
            is_peb_being_debugged: peb_being_debugged,
            peb_signal_confidence: DebugSignalConfidence::Low,
            is_nt_global_flag_active,
            total_threads_audited: thread_contexts.len(),
            threads_with_hardware_breakpoints,
            overall_assessment,
            thread_contexts,
            summary,
        }
    }
}
