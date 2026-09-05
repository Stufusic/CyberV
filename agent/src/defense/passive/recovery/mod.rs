//! Safe Recovery & Safe Mode Subsystem (P24.12)
//!
//! Ref: Docs/rv13.md Section 9:
//! Crash-loop detection, state degradation, safe mode and configuration restoration.

pub mod safe_mode;
pub mod startup_recovery;

pub use safe_mode::{PassiveSystemState, SafeModeManager};
pub use startup_recovery::{StartupRecoveryStatus, StartupRecoveryTracker};
