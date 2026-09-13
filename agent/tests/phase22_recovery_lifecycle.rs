//! Phase 22: Recovery & Re-Attestation Lifecycle Tests
//!
//! Ref: Docs/rv11.md Section 10:
//! Validates:
//! - Distinction between expected OEM/OS updates and unexpected tampering
//! - Transition to RECOVERY_PENDING without bricking user systems
//! - Recovery challenge generation and verification
//! - Golden baseline re-attestation and restoration to ActiveAttested

use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::recovery::{
    DeviceLifecycleState, PlatformUpdateType, RecoveryChallenge, RecoveryManager, RecoveryProof,
    TransitionDetector,
};
use cyberv_agent::security::assurance::AssuranceLevel;
use sha2::{Digest, Sha512};
use std::fmt::Write;

fn helper_admin_signature(challenge_id: &str, new_pcr_sha512: &str, admin_pubkey: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update(new_pcr_sha512.as_bytes());
    hasher.update(admin_pubkey);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[test]
fn test_01_transition_detector_unchanged() {
    let baseline = FirmwareConfigReport::standard_asus();
    let current = FirmwareConfigReport::standard_asus();
    let update_type = TransitionDetector::detect(&baseline, &current, false);
    assert_eq!(update_type, PlatformUpdateType::Unchanged);
}

#[test]
fn test_02_transition_detector_expected_oem_bios_update() {
    let baseline = FirmwareConfigReport::standard_asus();
    let mut current = FirmwareConfigReport::standard_asus();
    current.bios_version = "2201".to_string(); // New version from OEM
    let update_type = TransitionDetector::detect(&baseline, &current, true);
    assert_eq!(update_type, PlatformUpdateType::ExpectedOemUpdate);
}

#[test]
fn test_03_transition_detector_expected_os_windows_update() {
    let baseline = FirmwareConfigReport::standard_asus();
    let current = FirmwareConfigReport::standard_asus();
    // Same BIOS version, but PCR changed due to legitimate OS bootloader update
    let update_type = TransitionDetector::detect(&baseline, &current, true);
    assert_eq!(update_type, PlatformUpdateType::ExpectedOsUpdate);
}

#[test]
fn test_04_transition_detector_unexpected_tampering_unsigned() {
    let baseline = FirmwareConfigReport::standard_asus();
    let unverified = FirmwareConfigReport::unverified_vendor();
    let update_type = TransitionDetector::detect(&baseline, &unverified, true);
    assert_eq!(update_type, PlatformUpdateType::UnexpectedTampering);
}

#[test]
fn test_05_transition_detector_unexpected_pcr_tampering() {
    let baseline = FirmwareConfigReport::standard_asus();
    let mut current = FirmwareConfigReport::standard_asus();
    current.is_oem_signed = false; // Signature missing/corrupted
    let update_type = TransitionDetector::detect(&baseline, &current, true);
    assert_eq!(update_type, PlatformUpdateType::UnexpectedTampering);
}

#[test]
fn test_06_handle_transition_unchanged_keeps_active_attested() {
    let (state, assurance) = RecoveryManager::handle_transition(
        DeviceLifecycleState::ActiveAttested,
        PlatformUpdateType::Unchanged,
    );
    assert_eq!(state, DeviceLifecycleState::ActiveAttested);
    assert_eq!(assurance, AssuranceLevel::Attested);
}

#[test]
fn test_07_handle_transition_oem_update_enters_recovery_pending() {
    // Non-bricking rule: Device is NOT bricked, but enters RECOVERY_PENDING with OSProtected
    let (state, assurance) = RecoveryManager::handle_transition(
        DeviceLifecycleState::ActiveAttested,
        PlatformUpdateType::ExpectedOemUpdate,
    );
    assert_eq!(state, DeviceLifecycleState::RecoveryPending);
    assert_eq!(assurance, AssuranceLevel::OSProtected);
}

#[test]
fn test_08_handle_transition_os_update_enters_recovery_pending() {
    let (state, assurance) = RecoveryManager::handle_transition(
        DeviceLifecycleState::ActiveAttested,
        PlatformUpdateType::ExpectedOsUpdate,
    );
    assert_eq!(state, DeviceLifecycleState::RecoveryPending);
    assert_eq!(assurance, AssuranceLevel::OSProtected);
}

#[test]
fn test_09_handle_transition_unexpected_tampering_quarantined() {
    let (state, assurance) = RecoveryManager::handle_transition(
        DeviceLifecycleState::ActiveAttested,
        PlatformUpdateType::UnexpectedTampering,
    );
    assert_eq!(state, DeviceLifecycleState::Quarantined);
    assert_eq!(assurance, AssuranceLevel::Unknown);
}

#[test]
fn test_10_recovery_challenge_generation() {
    let nonce = [0x42u8; 32];
    let prev_pcr = b"OLD_PCR_STATE_0_7";
    let new_pcr = b"NEW_PCR_STATE_0_7";
    let now = 1700000000;

    let challenge = RecoveryManager::create_challenge("dev-pc-001", nonce, prev_pcr, new_pcr, now);
    assert!(challenge.challenge_id.starts_with("rc_"));
    assert_eq!(challenge.device_id, "dev-pc-001");
    assert_eq!(challenge.previous_pcr_sha512.len(), 128); // 64 bytes in hex
    assert_eq!(challenge.new_pcr_sha512.len(), 128);
    assert_eq!(challenge.created_at, now);
}

#[test]
fn test_11_verify_and_re_attest_success() {
    let nonce = [0x42u8; 32];
    let prev_pcr = b"OLD_PCR_STATE";
    let new_pcr = b"NEW_PCR_STATE";
    let admin_pub = b"CENTRAL_ADMIN_ED25519_KEY";
    let oem_cert_hash = "asus_oem_bios_cert_hash_sha512";

    let challenge = RecoveryManager::create_challenge("dev-pc-001", nonce, prev_pcr, new_pcr, 1000);
    let admin_sig = helper_admin_signature(
        &challenge.challenge_id,
        &challenge.new_pcr_sha512,
        admin_pub,
    );

    let proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: admin_sig,
        oem_update_cert_hash: oem_cert_hash.to_string(),
    };

    let result =
        RecoveryManager::verify_and_re_attest(&challenge, &proof, admin_pub, oem_cert_hash);
    assert_eq!(result.unwrap(), DeviceLifecycleState::ActiveAttested);
}

#[test]
fn test_12_verify_and_re_attest_challenge_id_mismatch_fails() {
    let nonce = [0x42u8; 32];
    let challenge = RecoveryManager::create_challenge("dev-pc-001", nonce, b"P1", b"P2", 1000);
    let admin_pub = b"ADMIN_KEY";
    let oem_cert_hash = "oem_hash";

    let proof = RecoveryProof {
        challenge_id: "rc_mismatched_id".to_string(),
        admin_signature_sha512: "sig".to_string(),
        oem_update_cert_hash: oem_cert_hash.to_string(),
    };

    let result =
        RecoveryManager::verify_and_re_attest(&challenge, &proof, admin_pub, oem_cert_hash);
    assert_eq!(result.unwrap_err(), "Challenge ID mismatch");
}

#[test]
fn test_13_verify_and_re_attest_oem_cert_mismatch_fails() {
    let nonce = [0x42u8; 32];
    let challenge = RecoveryManager::create_challenge("dev-pc-001", nonce, b"P1", b"P2", 1000);
    let admin_pub = b"ADMIN_KEY";

    let proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: "sig".to_string(),
        oem_update_cert_hash: "invalid_untrusted_cert".to_string(),
    };

    let result =
        RecoveryManager::verify_and_re_attest(&challenge, &proof, admin_pub, "expected_valid_cert");
    assert_eq!(result.unwrap_err(), "OEM update certificate hash mismatch");
}

#[test]
fn test_14_verify_and_re_attest_invalid_admin_signature_fails() {
    let nonce = [0x42u8; 32];
    let challenge = RecoveryManager::create_challenge("dev-pc-001", nonce, b"P1", b"P2", 1000);
    let admin_pub = b"ADMIN_KEY";
    let oem_cert_hash = "oem_hash";

    let proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: "bad_signature_hex".to_string(),
        oem_update_cert_hash: oem_cert_hash.to_string(),
    };

    let result =
        RecoveryManager::verify_and_re_attest(&challenge, &proof, admin_pub, oem_cert_hash);
    assert_eq!(result.unwrap_err(), "Invalid admin authorization signature");
}

#[test]
fn test_15_device_lifecycle_serialization() {
    let challenge = RecoveryChallenge {
        challenge_id: "rc_123".to_string(),
        device_id: "dev-01".to_string(),
        nonce: [0u8; 32],
        previous_pcr_sha512: "prev".to_string(),
        new_pcr_sha512: "new".to_string(),
        created_at: 500,
    };

    let json = serde_json::to_string(&challenge).unwrap();
    let deserialized: RecoveryChallenge = serde_json::from_str(&json).unwrap();
    assert_eq!(challenge, deserialized);
}
