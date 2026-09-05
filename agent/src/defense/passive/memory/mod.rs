//! Dynamic Memory State & W^X Observation Subsystem (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 5 & Section 6:
//! Quan sát khách quan hiện trạng không gian bộ nhớ ảo.

pub mod state_auditor;

pub use state_auditor::{
    AnomalySignalStrength, MemoryAnomalyClass, MemoryObservation, MemoryStateAuditor, MEM_COMMIT,
    MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryObservationReport {
    pub total_scanned_regions: usize,
    pub rwx_anomaly_count: usize,
    pub executable_private_count: usize,
    pub observations: Vec<MemoryObservation>,
    pub summary: String,
}

impl MemoryObservationReport {
    pub fn from_observations(observations: Vec<MemoryObservation>) -> Self {
        let total_scanned_regions = observations.len();
        let rwx_anomaly_count = observations
            .iter()
            .filter(|o| matches!(o.anomaly_class, Some(MemoryAnomalyClass::RwxRegion)))
            .count();
        let executable_private_count = observations
            .iter()
            .filter(|o| {
                matches!(
                    o.anomaly_class,
                    Some(MemoryAnomalyClass::ExecutablePrivateRegion)
                )
            })
            .count();

        let summary = format!(
            "Memory Observation: Scanned={}, RWX_Violations={}, Private_Executable={}",
            total_scanned_regions, rwx_anomaly_count, executable_private_count
        );

        Self {
            total_scanned_regions,
            rwx_anomaly_count,
            executable_private_count,
            observations,
            summary,
        }
    }
}
