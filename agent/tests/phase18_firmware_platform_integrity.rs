//! Phase 18: FSE-3 Firmware & Platform Integrity Tests
//!
//! Ref: Docs/rv11.md Section 4:
//! Validates decoupled firmware evidence domains:
//! - Secure Boot DB and DBX Revocation Precedence
//! - Intel Boot Guard / AMD PSB Hardware Root of Trust
//! - SMM Core Lockdown & Non-alarmist SMI anomaly scoring
//! - OEM Signed Firmware Configuration
//! - Integer-only Evidence Fusion Engine (0 - 10000)

use cyberv_agent::defense::firmware::boot_guard::{BootGuardReport, HardwareBootTechnology};
use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::firmware::fusion::FirmwareEvidenceFusionEngine;
use cyberv_agent::defense::firmware::secure_boot::{ImageValidationResult, SecureBootDbReport};
use cyberv_agent::defense::firmware::smm::SmmSecurityReport;

#[test]
fn test_01_secure_boot_hardened_score() {
    let sb = SecureBootDbReport::standard_hardened();
    assert_eq!(sb.security_score(), 10000);
}

#[test]
fn test_02_secure_boot_unconfigured_score() {
    let sb = SecureBootDbReport::unconfigured();
    assert_eq!(sb.security_score(), 1000);
}

#[test]
fn test_03_secure_boot_partial_scores() {
    let mut sb = SecureBootDbReport::standard_hardened();
    sb.dbx_count = 10; // Below threshold 100
    assert_eq!(sb.security_score(), 9000);

    sb.pk_present = false;
    assert_eq!(sb.security_score(), 7000);
}

#[test]
fn test_04_dbx_revocation_precedence_allowed() {
    let sb = SecureBootDbReport::standard_hardened();
    let res = sb.validate_image_precedence(true, false);
    assert_eq!(res, ImageValidationResult::AllowedByDb);
}

#[test]
fn test_05_dbx_revocation_precedence_overrides_db() {
    // Critical Microsoft UEFI rule: If an image is in BOTH db and dbx,
    // dbx takes absolute precedence and revokes it.
    let sb = SecureBootDbReport::standard_hardened();
    let res = sb.validate_image_precedence(true, true);
    assert_eq!(res, ImageValidationResult::RevokedByDbxPrecedence);
}

#[test]
fn test_06_dbx_revocation_precedence_not_found() {
    let sb = SecureBootDbReport::standard_hardened();
    let res = sb.validate_image_precedence(false, false);
    assert_eq!(res, ImageValidationResult::UntrustedNotFound);
}

#[test]
fn test_07_boot_guard_intel_profile5() {
    let bg = BootGuardReport::intel_boot_guard_profile5();
    assert_eq!(bg.technology, HardwareBootTechnology::IntelBootGuard);
    assert!(bg.is_fused);
    assert!(bg.verified_boot_enabled);
    assert!(bg.measured_boot_enabled);
    assert_eq!(bg.security_score(), 10000);
}

#[test]
fn test_08_boot_guard_amd_psb() {
    let bg = BootGuardReport::amd_psb_active();
    assert_eq!(bg.technology, HardwareBootTechnology::AmdPlatformSecureBoot);
    assert!(bg.is_fused);
    assert_eq!(bg.security_score(), 10000);
}

#[test]
fn test_09_boot_guard_unconfigured() {
    let bg = BootGuardReport::unconfigured();
    assert_eq!(bg.technology, HardwareBootTechnology::UnknownOrNone);
    assert_eq!(bg.security_score(), 2000);
}

#[test]
fn test_10_boot_guard_unfused_partial() {
    let mut bg = BootGuardReport::intel_boot_guard_profile5();
    bg.is_fused = false; // Not permanently fused
    assert_eq!(bg.security_score(), 8000);
}

#[test]
fn test_11_smm_security_hardened() {
    let smm = SmmSecurityReport::hardened();
    assert!(smm.smm_core_lockdown);
    assert!(smm.smm_driver_verification);
    assert!(smm.smm_mitigation_active);
    assert_eq!(smm.security_score(), 10000);
}

#[test]
fn test_12_smm_security_smi_anomaly_non_alarmist() {
    // Non-alarmist rule: SMI frequency variations are noisy, reducing score slightly
    // rather than falsely claiming firmware compromise.
    let mut smm = SmmSecurityReport::hardened();
    smm.has_smi_frequency_anomaly = true;
    assert_eq!(smm.security_score(), 9000);
}

#[test]
fn test_13_firmware_config_oem_signed_vs_unverified() {
    let signed = FirmwareConfigReport::standard_asus();
    assert_eq!(signed.security_score(), 10000);

    let unverified = FirmwareConfigReport::unverified_vendor();
    assert_eq!(unverified.security_score(), 3000);
}

#[test]
fn test_14_firmware_fusion_engine_trusted() {
    let sb = SecureBootDbReport::standard_hardened();
    let bg = BootGuardReport::intel_boot_guard_profile5();
    let smm = SmmSecurityReport::hardened();
    let cfg = FirmwareConfigReport::standard_asus();

    let report = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);
    assert_eq!(report.composite_score, 10000);
    assert!(report.is_firmware_trusted);
    assert_eq!(report.virtual_points.len(), 5);
    assert_eq!(report.virtual_nodes.len(), 3);
    assert!(report
        .summary
        .contains("Firmware Security Score: 10000/10000"));
}

#[test]
fn test_15_firmware_fusion_engine_untrusted() {
    let sb = SecureBootDbReport::unconfigured(); // 1000 (30% -> 300)
    let bg = BootGuardReport::unconfigured(); // 2000 (30% -> 600)
    let smm = SmmSecurityReport::unconstrained(); // 0 (20% -> 0)
    let cfg = FirmwareConfigReport::unverified_vendor(); // 3000 (20% -> 600)

    let report = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);
    // 300 + 600 + 0 + 600 = 1500
    assert_eq!(report.composite_score, 1500);
    assert!(!report.is_firmware_trusted);
    assert!(report
        .summary
        .contains("Firmware Security Score: 1500/10000"));
}
