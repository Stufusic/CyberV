//! Security Event Bus (P24.10)
//!
//! Ref: Docs/rv13.md Section 11:
//! "Decoupled Event Bus: Các subsystem không gọi trực tiếp nhau mà đưa sự kiện vào Event Bus.
//! Bus chuyển sự kiện thành EvidenceItem đưa vào Evidence Fusion, tránh architecture thành spaghetti."

use crate::evidence::unified::{EvidenceClass, EvidenceItem, EvidenceSource};
use crate::hardware::models::Confidence;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityEvent {
    BinaryTamperDetected {
        detail: String,
    },
    DriverUnexpected {
        reason: String,
    },
    MitigationDisabled {
        capability: String,
    },
    PrivilegePresent {
        privilege: String,
    },
    UpdateRollbackAttempt {
        current: u32,
        target: u32,
    },
    IpcAuthFailed {
        client_pid: u32,
        reason: String,
    },
    AclViolationDetected {
        path: String,
    },
    // Runtime Integrity Observation Events (Phase 24.1 - Ref: Docs/rv14.md)
    NtdllDiscrepancyObserved {
        function_name: String,
        assessment: String,
        severity: EventSeverity,
    },
    MemoryAnomalyObserved {
        anomaly_class: String,
        size: usize,
        severity: EventSeverity,
    },
    DebugInstrumentationObserved {
        assessment: String,
        severity: EventSeverity,
    },
}

impl SecurityEvent {
    /// Chuyển đổi sự kiện an ninh thành một thực thể bằng chứng chuẩn (EvidenceItem)
    pub fn to_evidence_item(&self, event_id: &str) -> EvidenceItem {
        match self {
            SecurityEvent::BinaryTamperDetected { detail } => EvidenceItem::new(
                event_id,
                "EVENT_BINARY_TAMPER",
                EvidenceClass::Structural,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                detail,
                Confidence::High,
                0, // Vi phạm tính toàn vẹn nhị phân -> 0 điểm
            ),
            SecurityEvent::DriverUnexpected { reason } => EvidenceItem::new(
                event_id,
                "EVENT_DRIVER_UNEXPECTED",
                EvidenceClass::Platform,
                1,
                1,
                EvidenceSource::KernelTamperResistance,
                reason,
                Confidence::High,
                1000,
            ),
            SecurityEvent::MitigationDisabled { capability } => EvidenceItem::new(
                event_id,
                "EVENT_MITIGATION_DISABLED",
                EvidenceClass::Platform,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                capability,
                Confidence::High,
                3000,
            ),
            SecurityEvent::PrivilegePresent { privilege } => EvidenceItem::new(
                event_id,
                "EVENT_PRIVILEGE_PRESENT",
                EvidenceClass::Behavioral,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                privilege,
                Confidence::High,
                4000,
            ),
            SecurityEvent::UpdateRollbackAttempt { current, target } => EvidenceItem::new(
                event_id,
                "EVENT_UPDATE_ROLLBACK",
                EvidenceClass::Temporal,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                format!("Rollback from {} to {}", current, target),
                Confidence::High,
                0,
            ),
            SecurityEvent::IpcAuthFailed { client_pid, reason } => EvidenceItem::new(
                event_id,
                "EVENT_IPC_AUTH_FAILED",
                EvidenceClass::Behavioral,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                format!("PID {}: {}", client_pid, reason),
                Confidence::High,
                2000,
            ),
            SecurityEvent::AclViolationDetected { path } => EvidenceItem::new(
                event_id,
                "EVENT_ACL_VIOLATION",
                EvidenceClass::Structural,
                1,
                1,
                EvidenceSource::PassiveProcessMitigation,
                path,
                Confidence::High,
                2500,
            ),
            SecurityEvent::NtdllDiscrepancyObserved {
                function_name,
                assessment,
                severity,
            } => {
                let score = match severity {
                    EventSeverity::Critical => 0,
                    EventSeverity::High => 2000,
                    EventSeverity::Medium => 4000,
                    EventSeverity::Low => 6000,
                    EventSeverity::Info => 8000,
                };
                EvidenceItem::new(
                    event_id,
                    "EVENT_NTDLL_DISCREPANCY",
                    EvidenceClass::Structural,
                    1,
                    1,
                    EvidenceSource::PassiveProcessMitigation,
                    format!("{}: {} [{:?}]", function_name, assessment, severity),
                    Confidence::High,
                    score,
                )
            }
            SecurityEvent::MemoryAnomalyObserved {
                anomaly_class,
                size,
                severity,
            } => {
                let score = match severity {
                    EventSeverity::Critical => 0,
                    EventSeverity::High => 1000,
                    EventSeverity::Medium => 3000,
                    EventSeverity::Low => 5000,
                    EventSeverity::Info => 7000,
                };
                EvidenceItem::new(
                    event_id,
                    "EVENT_MEMORY_ANOMALY",
                    EvidenceClass::Structural,
                    1,
                    1,
                    EvidenceSource::PassiveProcessMitigation,
                    format!("{}: size={}B [{:?}]", anomaly_class, size, severity),
                    Confidence::High,
                    score,
                )
            }
            SecurityEvent::DebugInstrumentationObserved {
                assessment,
                severity,
            } => {
                let score = match severity {
                    EventSeverity::Critical => 0,
                    EventSeverity::High => 2000,
                    EventSeverity::Medium => 4000,
                    EventSeverity::Low => 6000,
                    EventSeverity::Info => 8000,
                };
                EvidenceItem::new(
                    event_id,
                    "EVENT_DEBUG_INSTRUMENTATION",
                    EvidenceClass::Behavioral,
                    1,
                    1,
                    EvidenceSource::PassiveProcessMitigation,
                    format!("{} [{:?}]", assessment, severity),
                    Confidence::High,
                    score,
                )
            }
        }
    }
}

pub struct SecurityEventBus {
    events: Mutex<Vec<SecurityEvent>>,
}

impl Default for SecurityEventBus {
    fn default() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}

impl SecurityEventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Đưa một sự kiện an ninh mới vào bus
    pub fn publish(&self, event: SecurityEvent) {
        if let Ok(mut lock) = self.events.lock() {
            lock.push(event);
        }
    }

    /// Lấy toàn bộ sự kiện hiện có và xóa hàng đợi
    pub fn drain_events(&self) -> Vec<SecurityEvent> {
        if let Ok(mut lock) = self.events.lock() {
            std::mem::take(&mut *lock)
        } else {
            Vec::new()
        }
    }

    /// Chuyển đổi toàn bộ sự kiện thành danh sách EvidenceItem
    pub fn drain_as_evidence_items(&self) -> Vec<EvidenceItem> {
        let events = self.drain_events();
        events
            .into_iter()
            .enumerate()
            .map(|(idx, ev)| ev.to_evidence_item(&format!("ev_bus_{}", idx)))
            .collect()
    }
}
