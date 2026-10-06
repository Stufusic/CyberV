// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
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

/// Tạo file tạm cho audit DACL thật
fn make_temp_file(tag: &str) -> String {
    let p = std::env::temp_dir().join(format!(
        "cyberv_acl_{}_{}.dat",
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&p, b"cyberv-acl-test").unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn test_04_filesystem_acl_real_dacl_reads_clean_file() {
    let path = make_temp_file("clean");
    let result = FilesystemAclManager::audit_path(&path);
    // DACL mặc định của file user: owner = user, không có ACE ghi cho Everyone/Users
    assert!(result.is_verified, "{}", result.note);
    assert!(result.is_owner_trusted);
    assert!(result.is_everyone_denied_write);
    assert!(result.is_users_denied_write);
    assert!(result.is_secure);
    std::fs::remove_file(&path).ok();
}

/// Test đối kháng THẬT: cấp quyền ghi cho Everyone bằng SDDL qua
/// SetNamedSecurityInfoW rồi audit PHẢI phát hiện (không còn secure).
#[cfg(windows)]
#[test]
fn test_05_filesystem_acl_real_tamper_detected() {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    
    let path = make_temp_file("tampered");
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // DACL mới: chỉ Everyone full (mô phỏng kẻ tấn công mở quyền)
    let sddl: Vec<u16> = "D:(A;OICI;FA;;;WD)".encode_utf16().chain(std::iter::once(0)).collect();

    // ConvertStringSecurityDescriptorToSecurityDescriptor
    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut sd_size: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr(),
        1, // SDDL_REVISION_1
            &mut psd,
            &mut sd_size,
        )
    };
    assert!(ok != 0, "ConvertSDDL thất bại");

    // SetNamedSecurityInfoW nhận SECURITY_INFORMATION (u32) — OWNER giữ nguyên
    // (chỉ đổi DACL): dùng DACL_SECURITY_INFORMATION
    let dacl_info: u32 = 0x4;
    // Trích con trỏ DACL bên trong security descriptor (SetNamedSecurityInfoW
    // cần *mut ACL chứ không phải con trỏ SD)
    let mut has_dacl: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut pacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let got = unsafe {
        windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            psd,
            &mut has_dacl,
            &mut pacl,
            &mut dacl_defaulted,
        )
    };
    assert!(got != 0 && has_dacl != 0 && !pacl.is_null(), "SD thiếu DACL");

    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            dacl_info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            pacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(psd as *mut _) };
    assert_eq!(rc, 0, "SetNamedSecurityInfoW thất bại");

    let result = FilesystemAclManager::audit_path(&path);
    assert!(result.is_verified);
    assert!(
        !result.is_everyone_denied_write,
        "ACE Everyone-ghi phải bị phát hiện: {:?}",
        result
    );
    assert!(!result.is_secure, "file bị mở quyền cho Everyone KHÔNG được phép secure");
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_06_missing_asset_is_unverified_fail_closed() {
    let result = FilesystemAclManager::audit_path("C:\\cyberv-khong-ton-tai-xyz.dat");
    assert!(!result.is_verified, "file không tồn tại không được verify");
    assert!(!result.is_secure);
}

#[test]
fn test_07_filesystem_acl_scoring_reflects_findings() {
    let clean = make_temp_file("score_clean");
    let missing = "C:\\cyberv-khong-ton-tai-xyz.dat";
    let report = FilesystemAclManager::audit_critical_assets(&[&clean, missing]);
    assert!(!report.is_all_secured);
    assert_eq!(report.acl_score, 5000); // 1/2 secured
    assert!(report.audits[0].is_secure);
    assert!(!report.audits[1].is_secure);
    std::fs::remove_file(&clean).ok();
}

#[test]
fn test_08_filesystem_acl_audit_summary_accurate() {
    let f1 = make_temp_file("sum1");
    let f2 = make_temp_file("sum2");
    let report = FilesystemAclManager::audit_critical_assets(&[&f1, &f2]);
    assert!(report.is_all_secured);
    assert_eq!(report.acl_score, 10000);
    assert!(report.summary.contains("2/2 assets secured"));
    std::fs::remove_file(&f1).ok();
    std::fs::remove_file(&f2).ok();
}
