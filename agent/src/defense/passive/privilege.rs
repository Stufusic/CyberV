//! Token Privilege Hardening & Least Privilege Dropper (P24.2)
//!
//! Ref: Docs/rv13.md & Docs/rv12.md:
//! Tước bỏ các đặc quyền nguy hiểm (SeDebug, SeLoadDriver, SeTcb)
//! ngay sau giai đoạn bootstrap driver hoàn tất, đảm bảo Least Privilege.
//!
//! P1-3: gọi OpenProcessToken/GetTokenInformation/AdjustTokenPrivileges THẬT.
//! `is_verified` = cờ cho biết token đã được ĐO THẬT (query thành công),
//! không phải cờ "kết quả tốt" — query thất bại → fail-closed score 0.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegeIsolationReport {
    pub is_debug_privilege_held: bool,
    pub is_driver_privilege_held: bool,
    pub is_tcb_privilege_held: bool,
    pub is_least_privilege_active: bool,
    #[serde(default)]
    pub is_verified: bool,
    pub privilege_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct PrivilegeManager;

/// LUID cố định của các đặc quyền nguy hiểm (định nghĩa bởi Windows, ổn định
/// qua mọi phiên bản): SeTcbPrivilege=7, SeLoadDriverPrivilege=10, SeDebugPrivilege=20.
const SE_TCB_LUID: u64 = 7;
const SE_LOAD_DRIVER_LUID: u64 = 10;
const SE_DEBUG_LUID: u64 = 20;

#[cfg(windows)]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(windows)]
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
#[cfg(windows)]
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
#[cfg(windows)]
const SE_PRIVILEGE_REMOVED: u32 = 0x4;
#[cfg(windows)]
const TOKEN_PRIVILEGES_INFO_CLASS: u32 = 3; // TokenPrivileges

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAndAttrs {
    luid: u64,
    attributes: u32,
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(
        process_handle: isize,
        desired_access: u32,
        token_handle: *mut isize,
    ) -> i32;
    fn GetTokenInformation(
        token_handle: isize,
        information_class: u32,
        token_information: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn AdjustTokenPrivileges(
        token_handle: isize,
        disable_all_privileges: i32,
        new_state: *const u8,
        buffer_length: u32,
        previous_state: *mut u8,
        return_length: *mut u32,
    ) -> i32;
}

fn fail_report(reason: &str) -> PrivilegeIsolationReport {
    PrivilegeIsolationReport {
        is_debug_privilege_held: false,
        is_driver_privilege_held: false,
        is_tcb_privilege_held: false,
        is_least_privilege_active: false,
        is_verified: false,
        privilege_score: 0,
        summary: format!(
            "[UNVERIFIED — {}; fail-closed] Privilege state unknown: cannot claim least-privilege.",
            reason
        ),
    }
}

/// Gọi chuẩn hóa: parse buffer TOKEN_PRIVILEGES (count u32 + count * {u64 luid, u32 attrs})
#[cfg(windows)]
fn parse_privileges(buf: &[u8]) -> Vec<LuidAndAttrs> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut out = Vec::with_capacity(count.min(64));
    for i in 0..count {
        let off = 4 + i * 12;
        if off + 12 > buf.len() {
            break;
        }
        let luid = u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
        let attributes = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
        out.push(LuidAndAttrs { luid, attributes });
    }
    out
}

#[cfg(windows)]
fn held_flags(privs: &[LuidAndAttrs]) -> (bool, bool, bool) {
    let held = |target: u64| {
        privs
            .iter()
            .any(|p| p.luid == target && p.attributes & SE_PRIVILEGE_ENABLED != 0)
    };
    (
        held(SE_DEBUG_LUID),
        held(SE_LOAD_DRIVER_LUID),
        held(SE_TCB_LUID),
    )
}

impl PrivilegeManager {
    /// P1-3: Kiểm tra THẬT token của tiến trình và tước các đặc quyền nguy hiểm
    /// (SeDebug/SeLoadDriver/SeTcb) nếu đang enabled, rồi re-query trạng thái
    /// sau khi drop. is_verified = token API thành công (đo được thật).
    pub fn inspect_and_drop_dangerous_privileges() -> PrivilegeIsolationReport {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Threading::GetCurrentProcess;

            let mut token: isize = 0;
            // SAFETY: handle/token pointer hợp lệ; buffer tĩnh đủ lớn
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            ) == 0
            {
                return fail_report("OpenProcessToken failed");
            }

            let mut buf = [0u8; 1024];
            let mut retlen: u32 = 0;
            if GetTokenInformation(token, TOKEN_PRIVILEGES_INFO_CLASS, buf.as_mut_ptr(), buf.len() as u32, &mut retlen) == 0 {
                let _ = CloseToken(token);
                return fail_report("GetTokenInformation(TokenPrivileges) failed");
            }

            let before = parse_privileges(&buf);
            let (dbg, drv, tcb) = held_flags(&before);

            // Tước các đặc quyền đang enabled (SE_PRIVILEGE_REMOVED)
            let to_remove: Vec<u64> = [SE_DEBUG_LUID, SE_LOAD_DRIVER_LUID, SE_TCB_LUID]
                .into_iter()
                .filter(|l| {
                    before
                        .iter()
                        .any(|p| p.luid == *l && p.attributes & SE_PRIVILEGE_ENABLED != 0)
                })
                .collect();

            for luid in to_remove {
                let mut new_state: [u8; 16] = [0; 16];
                new_state[0..4].copy_from_slice(&1u32.to_ne_bytes());
                new_state[4..12].copy_from_slice(&luid.to_ne_bytes());
                new_state[12..16].copy_from_slice(&SE_PRIVILEGE_REMOVED.to_ne_bytes());
                // ReturnLength ở đây là yêu cầu kiểu NTSTATUS; với advapi32 là
                // ERROR_NOT_ALL_ASSIGNED khi một phần không được cấp — vẫn ok.
                let mut prev_len: u32 = 0;
                let _ = AdjustTokenPrivileges(token, 0, new_state.as_ptr(), 0, std::ptr::null_mut(), &mut prev_len);
            }

            // Re-query trạng thái SAU khi drop
            let mut buf2 = [0u8; 1024];
            let mut retlen2: u32 = 0;
            if GetTokenInformation(token, TOKEN_PRIVILEGES_INFO_CLASS, buf2.as_mut_ptr(), buf2.len() as u32, &mut retlen2) == 0 {
                let _ = CloseToken(token);
                return fail_report("Re-query after drop failed");
            }
            let after = parse_privileges(&buf2);
            let (dbg_after, drv_after, tcb_after) = held_flags(&after);
            let _ = CloseToken(token);

            let least = !dbg_after && !drv_after && !tcb_after;
            let score = if least { 10000 } else { 3000 };
            PrivilegeIsolationReport {
                is_debug_privilege_held: dbg_after,
                is_driver_privilege_held: drv_after,
                is_tcb_privilege_held: tcb_after,
                is_least_privilege_active: least,
                is_verified: true,
                privilege_score: score,
                summary: format!(
                    "[queried via OpenProcessToken] Privilege Dropper: before(Debug={},LoadDriver={},Tcb={}) -> after(Debug={},LoadDriver={},Tcb={}); LeastPrivilege={} (Score: {}/10000)",
                    dbg, drv, tcb, dbg_after, drv_after, tcb_after, least, score
                ),
            }
        }
        #[cfg(not(windows))]
        {
            fail_report("non-Windows platform")
        }
    }
}

// CloseHandle cho token handle (OpenProcessToken trả handle cần đóng)
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "CloseHandle"]
    fn CloseToken(handle: isize) -> i32;
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// P1-3: token phải được đo THẬT (is_verified=true) và sau khi drop,
    /// SeDebug phải không còn enabled — trên mọi môi trường Windows.
    #[test]
    fn real_token_query_and_drop() {
        let report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
        assert!(report.is_verified, "token query phải thành công: {}", report.summary);
        assert!(
            !report.is_debug_privilege_held,
            "sau drop, SeDebug không được còn enabled: {}",
            report.summary
        );
        assert!(report.summary.contains("queried"), "{}", report.summary);
    }
}
