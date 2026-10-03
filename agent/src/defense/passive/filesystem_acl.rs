//! Filesystem & Critical Asset ACL Hardening (P24.3)
//!
//! Ref: Docs/rv13.md Section 6:
//! "Hash phát hiện file bị sửa SAU KHI bị sửa. ACL có thể ngăn một số thao tác NGAY TỪ ĐẦU.
//! Kiểm tra identity.vault, config, logs, update dir, driver files:
//! Owner = expected account, NO Everyone write, NO Users write, restricted inheritance."
//!
//! P1-3: audit_path gọi GetNamedSecurityInfoW THẬT và phân tích DACL/ACE:
//! - owner phải là SYSTEM / Administrators / user hiện tại
//! - KHÔNG có ACE allowed cho Everyone (S-1-1-0) hoặc Users (S-1-5-32-545)
//!   với quyền ghi (write/append/delete/WriteDAC/WriteOwner/generic-write)
//! - inheritance không được rò rỉ quyền ghi cho nhóm rộng (inherited ACE check)
//!
//! File không tồn tại / không đọc được DACL → `is_verified: false`, `is_secure: false`
//! (fail-closed) — không bao giờ báo "secure" không có bằng chứng.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclAuditResult {
    pub path: String,
    pub is_owner_trusted: bool,
    pub is_everyone_denied_write: bool,
    pub is_users_denied_write: bool,
    pub is_inheritance_restricted: bool,
    pub is_secure: bool,
    /// P1-3: DACL/owner đã được ĐO THẬT chưa (file tồn tại + đọc security descriptor OK)
    #[serde(default)]
    pub is_verified: bool,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemSecurityReport {
    pub audits: Vec<AclAuditResult>,
    pub is_all_secured: bool,
    pub acl_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct FilesystemAclManager;

#[cfg(windows)]
const FILE_WRITE_BITS: u32 = 0x2 // FILE_WRITE_DATA
    | 0x4 // FILE_APPEND_DATA
    | 0x1_0000 // DELETE
    | 0x4_0000 // WRITE_DAC
    | 0x8_0000 // WRITE_OWNER
    | 0x4000_0000; // GENERIC_WRITE

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, PSID};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, ACL,
        ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
        WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub const SE_DACL_PROTECTED: SECURITY_DESCRIPTOR_CONTROL = 0x1000;

    pub const WIN_LOCAL_SYSTEM_SID: WELL_KNOWN_SID_TYPE = 22; // WinLocalSystemSid
    pub const WIN_BUILTIN_ADMINS_SID: WELL_KNOWN_SID_TYPE = 23; // WinBuiltinAdministratorsSid

    pub const TOKEN_USER_CLASS: TOKEN_INFORMATION_CLASS = 1;

    /// Đọc security descriptor (owner + DACL) của file.
    /// Caller phải LocalFree con trỏ trả về.
    pub unsafe fn read_security(
        path_utf16: &[u16],
    ) -> Result<(PSID, PSECURITY_DESCRIPTOR), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = GetNamedSecurityInfoW(
            path_utf16.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut psd,
        );
        if ok != 0 || psd.is_null() {
            return Err(format!("GetNamedSecurityInfoW failed (win32 error {})", ok));
        }
        Ok((owner, psd))
    }

    /// Owner SID có tin cậy được không: SYSTEM / Administrators / user hiện tại
    pub unsafe fn is_owner_trusted(owner: PSID) -> bool {
        if owner.is_null() {
            return false;
        }
        if IsWellKnownSid(owner, WIN_LOCAL_SYSTEM_SID) != 0
            || IsWellKnownSid(owner, WIN_BUILTIN_ADMINS_SID) != 0
        {
            return true;
        }
        // So với SID user hiện tại
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY as _, &mut token) == 0 {
            return false;
        }
        let mut user_buf = [0u8; 68]; // đủ cho SID chuẩn (max 28 byte + offset)
        let mut retlen: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            user_buf.as_mut_ptr() as *mut _,
            user_buf.len() as u32,
            &mut retlen,
        );
        CloseHandle(token);
        if ok == 0 {
            return false;
        }
        // TOKEN_USER = { SID_AND_ATTRIBUTES { PSID Sid, u32 Attributes } } —
        // trường Sid là CON TRỎ tới SID nằm sau trong buffer, không phải inline.
        let sid_ptr = *(user_buf.as_ptr() as *const PSID);
        if sid_ptr.is_null() {
            return false;
        }
        sid_to_string(sid_ptr) == sid_to_string(owner)
    }

    /// Convert SID → chuỗi "S-1-x-y..." (debuggable; caller LocalFree chuỗi)
    pub unsafe fn sid_to_string(sid: PSID) -> String {
        let mut pstr: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut pstr) == 0 || pstr.is_null() {
            return "<sid-convert-failed>".to_string();
        }
        let mut len = 0usize;
        while *pstr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(pstr, len);
        let out = String::from_utf16_lossy(slice);
        windows_sys::Win32::Foundation::LocalFree(pstr as *mut _);
        out
    }

    /// Duyệt DACL: trả (everyone_write, users_write, inherited_broad_write, dacl_protected)
    pub unsafe fn scan_dacl(psd: PSECURITY_DESCRIPTOR) -> Result<(bool, bool, bool, bool), String> {
        let mut has_dacl: i32 = 0;
        let mut dacl_defaulted: i32 = 0;
        let mut pacl: *mut ACL = std::ptr::null_mut();
        if GetSecurityDescriptorDacl(psd, &mut has_dacl, &mut pacl, &mut dacl_defaulted) == 0 {
            return Err("GetSecurityDescriptorDacl failed".to_string());
        }
        if has_dacl == 0 || pacl.is_null() {
            // Không DACL = mọi truy cập được phép (mức tệ nhất cho tài sản)
            return Ok((true, true, true, false));
        }

        let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
        let mut revision: u32 = 0;
        let dacl_protected = GetSecurityDescriptorControl(psd, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0;

        // SID danh sách rộng so bằng chuỗi (debuggable, không phụ thuộc EqualSid)
        const EVERYONE_SID_STR: &str = "S-1-1-0";
        const USERS_SID_STR: &str = "S-1-5-32-545";

        let ace_count = (*pacl).AceCount as usize;
        let mut everyone_write = false;
        let mut users_write = false;
        let mut inherited_broad_write = false;

        for i in 0..ace_count {
            let mut p_ace: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(pacl, i as u32, &mut p_ace) == 0 || p_ace.is_null() {
                continue;
            }
            // ACCESS_ALLOWED_ACE: Header(AceType u8, AceFlags u8, AceSize u16) + Mask u32 + SidStart
            let base = p_ace as *const u8;
            let ace_type = *base;
            let ace_flags = *base.add(1);
            if ace_type != 0 {
                continue; // chỉ xét ACCESS_ALLOWED (0)
            }
            let allowed_ace = p_ace as *const ACCESS_ALLOWED_ACE;
            let mask = (*allowed_ace).Mask;
            if mask & super::FILE_WRITE_BITS == 0 {
                continue;
            }
            let ace_sid: PSID = (&(*allowed_ace).SidStart) as *const u32 as PSID;
            let sid_str = sid_to_string(ace_sid);
            if sid_str == EVERYONE_SID_STR {
                everyone_write = true;
                if ace_flags as u32 & INHERITED_ACE != 0 {
                    inherited_broad_write = true;
                }
            }
            if sid_str == USERS_SID_STR {
                users_write = true;
                if ace_flags as u32 & INHERITED_ACE != 0 {
                    inherited_broad_write = true;
                }
            }
        }
        Ok((everyone_write, users_write, inherited_broad_write, dacl_protected))
    }
}

impl FilesystemAclManager {
    /// P1-3: kiểm tra DACL THẬT của một đường dẫn (Windows).
    /// is_verified = đọc được security descriptor; thất bại → fail-closed.
    pub fn audit_path(path: &str) -> AclAuditResult {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let (owner, psd) = match unsafe { win::read_security(&wide_path) } {
                Ok(v) => v,
                Err(e) => {
                    return AclAuditResult {
                        path: path.to_string(),
                        is_owner_trusted: false,
                        is_everyone_denied_write: false,
                        is_users_denied_write: false,
                        is_inheritance_restricted: false,
                        is_secure: false,
                        is_verified: false,
                        note: format!("[UNVERIFIED — {}]", e),
                    };
                }
            };

            let result = unsafe {
                let owner_trusted = win::is_owner_trusted(owner);
                let scan = win::scan_dacl(psd);
                windows_sys::Win32::Foundation::LocalFree(psd as *mut _);
                match scan {
                    Ok((everyone_write, users_write, inherited_broad_write, _dacl_protected)) => {
                        let everyone_denied = !everyone_write;
                        let users_denied = !users_write;
                        let inheritance_restricted = !inherited_broad_write;
                        AclAuditResult {
                            path: path.to_string(),
                            is_owner_trusted: owner_trusted,
                            is_everyone_denied_write: everyone_denied,
                            is_users_denied_write: users_denied,
                            is_inheritance_restricted: inheritance_restricted,
                            is_secure: owner_trusted
                                && everyone_denied
                                && users_denied
                                && inheritance_restricted,
                            is_verified: true,
                            note: "[queried via GetNamedSecurityInfoW]".to_string(),
                        }
                    }
                    Err(e) => AclAuditResult {
                        path: path.to_string(),
                        is_owner_trusted: false,
                        is_everyone_denied_write: false,
                        is_users_denied_write: false,
                        is_inheritance_restricted: false,
                        is_secure: false,
                        is_verified: false,
                        note: format!("[UNVERIFIED — {}]", e),
                    },
                }
            };
            result
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            AclAuditResult {
                path: path.to_string(),
                is_owner_trusted: false,
                is_everyone_denied_write: false,
                is_users_denied_write: false,
                is_inheritance_restricted: false,
                is_secure: false,
                is_verified: false,
                note: "[UNVERIFIED — non-Windows platform; fail-closed]".to_string(),
            }
        }
    }

    /// Đánh giá toàn bộ các đường dẫn tài sản nhạy cảm (DACL thật, không mock)
    pub fn audit_critical_assets(paths: &[&str]) -> FilesystemSecurityReport {
        let mut audits = Vec::new();

        for path in paths {
            audits.push(Self::audit_path(path));
        }

        let secure_count = audits.iter().filter(|a| a.is_secure).count();
        let total = audits.len();
        let acl_score = if total > 0 {
            ((secure_count as u64 * 10000) / total as u64) as u32
        } else {
            10000
        };

        let is_all_secured = secure_count == total;
        let summary = format!(
            "Filesystem ACL Audit: {}/{} assets secured (Score: {}/10000)",
            secure_count, total, acl_score
        );

        FilesystemSecurityReport {
            audits,
            is_all_secured,
            acl_score,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_temp_file(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let p = dir.join(format!(
            "cyberv_acl_{}_{}.dat",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"cyberv-acl-test").unwrap();
        p
    }

    /// P1-3: file user tạo mới — DACL phải được ĐO THẬT và is_secure phải là
    /// hội của đúng 4 điều kiện (self-consistency). Các cờ riêng phụ thuộc
    /// cấu hình máy (vd: một số máy grant Users write trên %TEMP%).
    #[cfg(windows)]
    #[test]
    fn audit_path_reads_real_dacl_of_temp_file() {
        let p = make_temp_file("clean");
        let path = p.to_string_lossy().into_owned();
        let result = FilesystemAclManager::audit_path(&path);
        assert!(result.is_verified, "{}", result.note);
        assert!(result.is_owner_trusted, "{}", result.note);
        let expected_secure = result.is_owner_trusted
            && result.is_everyone_denied_write
            && result.is_users_denied_write
            && result.is_inheritance_restricted;
        assert_eq!(
            result.is_secure, expected_secure,
            "is_secure phải là hội của 4 điều kiện: {}",
            result.note
        );
        std::fs::remove_file(&p).ok();
    }

    #[cfg(not(windows))]
    #[test]
    fn audit_path_fail_closed_on_non_windows() {
        let result = FilesystemAclManager::audit_path("C:\\nonexistent.dat");
        assert!(!result.is_verified);
        assert!(!result.is_secure);
    }

    /// File không tồn tại → UNVERIFIED + fail-closed (không bao giờ "secure")
    #[test]
    fn missing_file_is_unverified_not_secure() {
        let result = FilesystemAclManager::audit_path("C:\\cyberv-khong-ton-tai-xyz.dat");
        assert!(!result.is_verified);
        assert!(!result.is_secure);
    }
}
