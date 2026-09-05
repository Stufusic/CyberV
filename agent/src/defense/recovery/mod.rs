//! Recovery & Re-Attestation Lifecycle (Phase 22)
//!
//! Ref: Docs/rv11.md Section 10:
//! Safe recovery pipelines avoiding device bricking on BIOS/Windows updates.

pub mod re_attestation;
pub mod transition;

pub use re_attestation::{DeviceLifecycleState, RecoveryChallenge, RecoveryManager, RecoveryProof};
pub use transition::{PlatformUpdateType, TransitionDetector};
