//! Runtime Integrity Observer & Evidence Coordinator (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 1, 15, 17, 19:
//! "Runtime Integrity Guard không phải một anti-debug tool;
//! nó là một observation layer về trạng thái thực thi của chính CyberV.
//! Không bao giờ tự tiện kill, wipe, block mạng hoặc hủy vault.
//! Observation != Response."

use super::debug::DebugInstrumentationReport;
use super::memory::MemoryObservationReport;
use super::runtime_freshness::EvidenceFreshness;
use super::syscall::NtdllObservationReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObservationReport {
    pub ntdll: NtdllObservationReport,
    pub memory: MemoryObservationReport,
    pub debug: DebugInstrumentationReport,
    pub freshness: EvidenceFreshness,
    pub confidence: u16, // 0 - 10000
    pub summary: String,
}

pub struct RuntimeIntegrityObserver;

impl RuntimeIntegrityObserver {
    /// Tổng hợp các quan sát runtime từ các cảm biến thành một báo cáo chuẩn hóa
    pub fn observe(
        ntdll: NtdllObservationReport,
        memory: MemoryObservationReport,
        debug: DebugInstrumentationReport,
        current_time_ms: u64,
    ) -> RuntimeObservationReport {
        let freshness = EvidenceFreshness::standard(current_time_ms);

        // Đánh giá độ tin cậy của tập bằng chứng tổng hợp (Confidence)
        let mut confidence: u16 = 10000;

        // Nếu có dấu hiệu can thiệp, độ tin cậy bị suy giảm có tính toán
        if ntdll.suspected_functions_count > 0 {
            confidence = confidence.saturating_sub(3000);
        }
        if memory.rwx_anomaly_count > 0 {
            confidence = confidence.saturating_sub(4000);
        }
        if debug.threads_with_hardware_breakpoints > 0 {
            confidence = confidence.saturating_sub(3000);
        }

        let summary = format!(
            "Runtime Observation: NTDLL_Clean={}/{}, RWX_Violations={}, HW_Breakpoints={}, Confidence={}/10000",
            ntdll.clean_functions_count,
            ntdll.total_analyzed_functions,
            memory.rwx_anomaly_count,
            debug.threads_with_hardware_breakpoints,
            confidence
        );

        RuntimeObservationReport {
            ntdll,
            memory,
            debug,
            freshness,
            confidence,
            summary,
        }
    }
}
