//! Phase 24D: Binary & Driver Integrity Tests
//!
//! Ref: Docs/rv13.md Section 2 & Section 4:
//! Validates:
//! - Driver cybervprobe.sys signer, cert chain, version, and image hash
//! - 3-Tier PE-aware self-integrity (Disk, Loaded Image, Runtime Config)
//! - Detection of IAT hooking or writable .text without naive byte-matching

use cyberv_agent::defense::passive::binary_integrity::BinaryIntegrityChecker;
use cyberv_agent::defense::passive::driver_integrity::DriverIntegrityChecker;

#[test]
fn test_01_driver_integrity_verified_perfect_match() {
    let report = DriverIntegrityChecker::verify_driver(
        DriverIntegrityChecker::EXPECTED_PUBLISHER,
        "sha512_hash_driver_valid",
        "sha512_hash_driver_valid",
        DriverIntegrityChecker::EXPECTED_VERSION,
        true,
    );
    assert!(report.is_loaded);
    assert!(report.is_signer_valid);
    assert!(report.is_hash_matched);
    assert!(report.is_version_compliant);
    assert_eq!(report.driver_integrity_score, 10000);
}

#[test]
fn test_02_driver_integrity_wrong_publisher_fails() {
    let report = DriverIntegrityChecker::verify_driver(
        "Untrusted Third Party Publisher",
        "sha512_hash",
        "sha512_hash",
        DriverIntegrityChecker::EXPECTED_VERSION,
        true,
    );
    assert!(!report.is_signer_valid);
    assert_eq!(report.driver_integrity_score, 7000);
}

#[test]
fn test_03_driver_integrity_image_hash_mismatch_fails() {
    let report = DriverIntegrityChecker::verify_driver(
        DriverIntegrityChecker::EXPECTED_PUBLISHER,
        "corrupted_driver_hash",
        "expected_driver_hash",
        DriverIntegrityChecker::EXPECTED_VERSION,
        true,
    );
    assert!(!report.is_hash_matched);
    assert_eq!(report.driver_integrity_score, 7000);
}

#[test]
fn test_04_driver_integrity_unloaded_penalized() {
    let report = DriverIntegrityChecker::verify_driver(
        DriverIntegrityChecker::EXPECTED_PUBLISHER,
        "sha512_hash",
        "sha512_hash",
        DriverIntegrityChecker::EXPECTED_VERSION,
        false, // Driver stopped/unloaded
    );
    assert!(!report.is_loaded);
    assert_eq!(report.driver_integrity_score, 8000);
}

#[test]
fn test_05_binary_integrity_disk_authenticode_valid() {
    let report = BinaryIntegrityChecker::evaluate(
        true,
        "valid_hash",
        "valid_hash",
        true,
        true,
        true,
        true,
        true,
    );
    assert!(report.disk.is_disk_intact);
    assert_eq!(report.binary_integrity_score, 10000);
}

#[test]
fn test_06_binary_integrity_disk_hash_mismatch_fails() {
    let report = BinaryIntegrityChecker::evaluate(
        true,
        "tampered_hash",
        "expected_hash",
        true,
        true,
        true,
        true,
        true,
    );
    assert!(!report.disk.is_disk_intact);
    assert_eq!(report.binary_integrity_score, 6000); // 10000 - 4000
}

#[test]
fn test_07_binary_integrity_loaded_image_pe_aware_valid() {
    let report = BinaryIntegrityChecker::evaluate(
        true, "hash", "hash", true, // PE sections match headers
        true, // IAT unhooked
        true, // .text is R-X only
        true, true,
    );
    assert!(report.loaded_image.is_loaded_image_intact);
}

#[test]
fn test_08_binary_integrity_loaded_image_iat_hooked_fails() {
    let report = BinaryIntegrityChecker::evaluate(
        true, "hash", "hash", true, false, // IAT was hooked by inline detour
        true, true, true,
    );
    assert!(!report.loaded_image.is_loaded_image_intact);
    assert_eq!(report.binary_integrity_score, 6000);
}

#[test]
fn test_09_binary_integrity_loaded_image_writable_text_fails() {
    let report = BinaryIntegrityChecker::evaluate(
        true, "hash", "hash", true, true,
        false, // .text was flipped to PAGE_EXECUTE_READWRITE
        true, true,
    );
    assert!(!report.loaded_image.is_loaded_image_intact);
}

#[test]
fn test_10_binary_integrity_runtime_config_acg_intact() {
    let report = BinaryIntegrityChecker::evaluate(
        true, "hash", "hash", true, true, true, true, // ACG active
        true, // Driver connected
    );
    assert!(report.runtime_config.is_runtime_config_intact);
}
