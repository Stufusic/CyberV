//! Execution Instrumentation & Debug State Auditor Subsystem (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 7, 8, 9:
//! Quan sát khách quan hiện trạng Debugger & Hardware Breakpoint.

pub mod state_auditor;

pub use state_auditor::{
    DebugInstrumentationReport, DebugSignalConfidence, DebugStateAssessment, DebugStateAuditor,
    ThreadDebugContext,
};
