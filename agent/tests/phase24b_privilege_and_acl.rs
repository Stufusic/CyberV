//! Phase 24B: Token Privilege & Filesystem ACL Hardening Tests
//!
//! Ref: Docs/rv13.md Section 6:
//! Validates:
//! - Privilege Dropping (SeDebug, SeLoadDriver, SeTcb)
//! - Critical Asset ACLs (Vault, Config, Driver, Logs)
//! - Prevention of unauthorized write access before tampering occurs

use cyberv_agent::defense::passive::filesystem_acl::FilesystemAclManager;
use cyberv_agent::defense::passive::privilege::PrivilegeManager;

#[test]
fn test_01_privilege_dropping_sedebug_removed() {
    let report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    assert!(!report.is_debug_privilege_held);
}

#[test]
fn test_02_privilege_dropping_seloaddriver_removed() {
    let report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    assert!(!report.is_driver_privilege_held);
}

#[test]
fn test_03_privilege_least_privilege_score_10000() {
    let report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    assert!(report.is_least_privilege_active);
    assert_eq!(report.privilege_score, 10000);
}

#[test]
fn test_04_filesystem_acl_vault_hardened() {
    let result = FilesystemAclManager::audit_path("C:\\ProgramData\\CyberV\\identity.vault", false);
    assert!(result.is_owner_trusted);
    assert!(result.is_secure);
}

#[test]
fn test_05_filesystem_acl_everyone_write_denied() {
    let result = FilesystemAclManager::audit_path("C:\\ProgramData\\CyberV\\identity.vault", false);
    assert!(result.is_everyone_denied_write);
    assert!(result.is_users_denied_write);
}

#[test]
fn test_06_filesystem_acl_inheritance_restricted() {
    let result = FilesystemAclManager::audit_path("C:\\ProgramData\\CyberV\\config.json", false);
    assert!(result.is_inheritance_restricted);
}

#[test]
fn test_07_filesystem_acl_tampering_detected() {
    let paths = [
        "C:\\ProgramData\\CyberV\\identity.vault",
        "C:\\ProgramData\\CyberV\\config.json",
        "C:\\Windows\\System32\\drivers\\cybervprobe.sys",
    ];

    // Tamper asset at index 1
    let report = FilesystemAclManager::audit_critical_assets(&paths, Some(1));
    assert!(!report.is_all_secured);
    assert!(report.acl_score < 10000);
    assert!(!report.audits[1].is_secure);
}

#[test]
fn test_08_filesystem_acl_audit_summary_accurate() {
    let paths = [
        "C:\\ProgramData\\CyberV\\identity.vault",
        "C:\\ProgramData\\CyberV\\config.json",
    ];
    let report = FilesystemAclManager::audit_critical_assets(&paths, None);
    assert!(report.is_all_secured);
    assert_eq!(report.acl_score, 10000);
    assert!(report.summary.contains("2/2 assets secured"));
}
