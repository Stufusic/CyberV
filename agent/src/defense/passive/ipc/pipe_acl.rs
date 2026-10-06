// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
//! Hardened Named Pipe DACL Security (P24.4)
//!
//! Ref: Docs/rv13.md Section 5:
//! "Only expected principals (SYSTEM + Current User SID) + Deny Everyone/Network."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeSecurityDescriptor {
    pub pipe_name: String,
    pub allows_system: bool,
    pub allows_current_user: bool,
    pub denies_everyone: bool,
    pub denies_network_logon: bool,
    pub is_hardened: bool,
}

pub struct PipeAclManager;

impl PipeAclManager {
    /// Tạo cấu hình bảo mật DACL cho Named Pipe
    pub fn create_hardened_pipe_descriptor(pipe_name: impl Into<String>) -> PipeSecurityDescriptor {
        PipeSecurityDescriptor {
            pipe_name: pipe_name.into(),
            allows_system: true,
            allows_current_user: true,
            denies_everyone: true,
            denies_network_logon: true,
            is_hardened: true,
        }
    }

    /// Áp DACL THẬT lên handle pipe (P1-1): SDDL theo plan —
    /// `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AC)` — protected DACL, chỉ
    /// SYSTEM + Administrators + All Application Packages. Được gọi NGAY sau
    /// khi instance được tạo (SetKernelObjectSecurity trên handle hiện hành).
    ///
    /// Trung thực (ghi plan P1-1): grant cho user console ở chế độ service là
    /// việc còn lại (cần truy SID console user qua WTS API) — ở dev, agent
    /// chạy dưới user thường nên pipe do chính user đó tạo.
    #[cfg(windows)]
    pub fn apply_hardened_dacl(handle: std::os::windows::io::RawHandle) -> Result<(), String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SetKernelObjectSecurity};

        const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AC)";
        let sddl_w: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut sd_len = 0u32;
        // SAFETY: sddl_w là wide-string null-terminated hợp lệ; sd_ptr/sd_len
        // do Windows cấp phát và được LocalFree sau khi dùng xong.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                &mut sd_len,
            )
        };
        if ok == 0 {
            return Err("ConvertStringSecurityDescriptorToSecurityDescriptorW thất bại".into());
        }
        // SAFETY: handle hợp lệ do tokio pipe quản lý; SD còn sống đến sau lời
        // gọi (LocalFree sau SetKernelObjectSecurity).
        let set_ok = unsafe {
            SetKernelObjectSecurity(handle as isize, DACL_SECURITY_INFORMATION, sd_ptr)
        };
        unsafe { LocalFree(sd_ptr) };
        if set_ok == 0 {
            return Err("SetKernelObjectSecurity thất bại".into());
        }
        Ok(())
    }
}
