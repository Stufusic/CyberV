//! Phase 24E: Secure Update & Safe Recovery Tests
//!
//! Ref: Docs/rv13.md Section 7 & Section 9:
//! Validates:
//! - Update manifest signature & package hash
//! - Anti-Rollback version enforcement (V_target >= V_current + 1)
//! - Staging state machine: CURRENT -> STAGED -> VERIFIED -> ACTIVE / ROLLEDBACK
//! - Safe Mode & Crash loop detection state machine

use cyberv_agent::defense::passive::recovery::{
    PassiveSystemState, SafeModeManager, StartupRecoveryTracker,
};
use cyberv_agent::defense::passive::update::{
    UpdatePackageManifest, UpdateStagingManager, UpdateStagingState, VersionPolicyDecision,
    VersionPolicyValidator,
};
use cyberv_agent::security::assurance::AssuranceLevel;

#[test]
fn test_01_update_manifest_signature_verification_success() {
    let manifest = UpdatePackageManifest {
        version: 2,
        package_sha512: "sha512_package_digest".to_string(),
        release_key_id: "release_key_2026_primary".to_string(),
        manifest_signature_hex: "valid_ecdsa_sig".to_string(),
        target_arch: "x86_64".to_string(),
    };
    assert!(manifest.verify_signature("release_key_2026_primary"));
}

#[test]
fn test_02_update_manifest_wrong_release_key_fails() {
    let manifest = UpdatePackageManifest {
        version: 2,
        package_sha512: "sha512_package_digest".to_string(),
        release_key_id: "rogue_attacker_key".to_string(),
        manifest_signature_hex: "fake_sig".to_string(),
        target_arch: "x86_64".to_string(),
    };
    assert!(!manifest.verify_signature("release_key_2026_primary"));
}

#[test]
fn test_03_version_policy_allowed_upgrade() {
    let res = VersionPolicyValidator::evaluate(1, 2);
    assert_eq!(res, VersionPolicyDecision::AllowedUpgrade { increment: 1 });
}

#[test]
fn test_04_version_policy_rejected_downgrade_anti_rollback() {
    let res = VersionPolicyValidator::evaluate(3, 1);
    assert_eq!(
        res,
        VersionPolicyDecision::RejectedDowngrade {
            current: 3,
            target: 1
        }
    );
}

#[test]
fn test_05_version_policy_rejected_same_version_replay() {
    let res = VersionPolicyValidator::evaluate(2, 2);
    assert_eq!(
        res,
        VersionPolicyDecision::RejectedReplaySameVersion { version: 2 }
    );
}

#[test]
fn test_06_staging_lifecycle_current_to_staged() {
    let state = UpdateStagingManager::advance_state(UpdateStagingState::Current, true).unwrap();
    assert_eq!(state, UpdateStagingState::Staged);
}

#[test]
fn test_07_staging_lifecycle_staged_to_verified_to_active() {
    let staged = UpdateStagingState::Staged;
    let verified = UpdateStagingManager::advance_state(staged, true).unwrap();
    assert_eq!(verified, UpdateStagingState::Verified);

    let active = UpdateStagingManager::advance_state(verified, true).unwrap();
    assert_eq!(active, UpdateStagingState::Active);
}

#[test]
fn test_08_staging_lifecycle_verification_failure_triggers_rollback() {
    let staged = UpdateStagingState::Staged;
    let rolled_back = UpdateStagingManager::advance_state(staged, false).unwrap();
    assert_eq!(rolled_back, UpdateStagingState::RolledBack);
}

#[test]
fn test_09_safe_mode_machine_crash_escalation() {
    let (s0, a0) = SafeModeManager::evaluate_crash_recovery(0);
    assert_eq!(s0, PassiveSystemState::Normal);
    assert_eq!(a0, AssuranceLevel::Attested);

    let (s1, a1) = SafeModeManager::evaluate_crash_recovery(1);
    assert_eq!(s1, PassiveSystemState::Degraded);
    assert_eq!(a1, AssuranceLevel::OSProtected);

    let (s3, a3) = SafeModeManager::evaluate_crash_recovery(3);
    assert_eq!(s3, PassiveSystemState::Recovery);
    assert_eq!(a3, AssuranceLevel::OSProtected);

    let (s5, a5) = SafeModeManager::evaluate_crash_recovery(5);
    assert_eq!(s5, PassiveSystemState::SafeMode);
    assert_eq!(a5, AssuranceLevel::Software);

    let tracker = StartupRecoveryTracker::check_recovery_state(4, 1);
    assert!(tracker.is_fallback_needed);
}

#[test]
fn test_10_safe_mode_machine_restore() {
    let restored = SafeModeManager::restore_from_safe_mode();
    assert_eq!(restored, PassiveSystemState::Restored);
}
