//! Phase 24A: Process Mitigations & Capability Profiling Tests
//!
//! Ref: Docs/rv13.md Section 1 & Section 8:
//! Validates:
//! - ACG (Dynamic Code), Extension Points, Signature Policy, Image Load Policy
//! - Strict Handle Checks, Child Process Safe Override
//! - 4-state Capability Matrix: Supported != Enabled != Enforceable != Verified

use cyberv_agent::defense::passive::capability::{
    CapabilityProfiler, MitigationCapability, SecurityCapabilityProfile,
};
use cyberv_agent::defense::passive::process_mitigations::{
    ProcessMitigationConfig, ProcessMitigationManager,
};
use cyberv_agent::security::assurance::AssuranceLevel;

#[test]
fn test_01_capability_matrix_all_probed() {
    let report = CapabilityProfiler::probe_system_capabilities();
    assert!(!report.profiles.is_empty());
    assert!(report.composite_score >= 8000);
    assert!(report.summary.contains("Capability Profiler"));
}

#[test]
fn test_02_dynamic_code_policy_acg_verified() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_acg_active);
}

#[test]
fn test_03_image_load_policy_restricted() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_image_load_restricted);
}

#[test]
fn test_04_extension_points_disabled() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_extension_point_disabled);
}

#[test]
fn test_05_strict_handle_checks_enabled() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_strict_handle_active);
}

#[test]
fn test_06_whql_signature_policy_enforced() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_whql_enforced);
}

#[test]
fn test_07_child_process_safe_helper_override_allowed() {
    // Crucial rule from Docs/rv13.md Section 5:
    // Do NOT blindly hard-block child processes, allow safe helper overrides
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.allow_child_helpers);
}

#[test]
fn test_08_capability_supported_vs_enabled_distinction() {
    // Validates: Supported != Enabled != Verified
    let profile = SecurityCapabilityProfile::supported_not_enabled(
        MitigationCapability::UserShadowStackCet,
        "Compatible CPU present but feature disabled in test profile",
    );
    assert!(profile.supported);
    assert!(!profile.enabled);
    assert!(!profile.verified);
    assert_eq!(profile.assurance, AssuranceLevel::OSProtected);
    assert!(profile.reason.is_some());
}

#[test]
fn test_09_process_mitigation_score_full_hardened() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert_eq!(status.mitigation_score, 10000);
}

#[test]
fn test_10_process_mitigation_degraded_partial_score() {
    let config = ProcessMitigationConfig {
        prohibit_dynamic_code: false, // ACG off
        restrict_image_load: false,   // Remote images allowed
        ..Default::default()
    };
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert_eq!(status.mitigation_score, 6000); // 10000 - 2000 - 2000
}
