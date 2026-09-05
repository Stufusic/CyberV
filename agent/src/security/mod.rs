//! Foundational Security Capability & Assurance Layer (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 7 & 8:
//! Capabilities, Assurance Levels, Evidence Freshness and Decay.

pub mod assurance;
pub mod capabilities;
pub mod freshness;

pub use assurance::AssuranceLevel;
pub use capabilities::PlatformSecurityCapabilities;
pub use freshness::EvidenceMetadata;
