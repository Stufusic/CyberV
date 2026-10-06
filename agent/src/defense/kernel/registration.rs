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
//! Protected Process Registration (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Driver registration integrity: Không chỉ PID register:
//! ProtectedProcessRegistration { pid, process_start_time, registration_nonce, driver_instance_id }
//! Không dùng PID đơn độc vì PID có thể recycle."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedProcessRegistration {
    pub pid: u32,
    pub process_start_time: u64,
    pub registration_nonce: String,
    pub driver_instance_id: u32,
}

impl ProtectedProcessRegistration {
    pub fn current(nonce: impl Into<String>, driver_instance_id: u32) -> Self {
        let pid = std::process::id();
        // FIX C1: gửi thời điểm TẠO TIẾN TRÌNH dạng FILETIME (100ns từ 1601) —
        // cùng đơn vị, epoch và ngữ nghĩa với PsGetProcessCreateTimeQuadPart
        // phía kernel. Giá trị cũ ("giây Unix hiện tại") sai cả ba thứ khiến
        // phép so sánh PID-reuse trong driver luôn kết luận "foreign process"
        // và shield không bao giờ tước quyền handle.
        Self {
            pid,
            process_start_time: current_process_create_time_filetime(),
            registration_nonce: nonce.into(),
            driver_instance_id,
        }
    }

    pub fn new(
        pid: u32,
        process_start_time: u64,
        registration_nonce: impl Into<String>,
        driver_instance_id: u32,
    ) -> Self {
        Self {
            pid,
            process_start_time,
            registration_nonce: registration_nonce.into(),
            driver_instance_id,
        }
    }
}

/// Thời điểm tạo tiến trình hiện tại dạng FILETIME (100ns kể từ 1601-01-01 UTC) —
/// cùng hệ quy chiếu với `PsGetProcessCreateTimeQuadPart` của kernel.
/// Trả về 0 nếu không lấy được (kernel sẽ tự tra cứu thực tế — xem driver fix).
pub fn current_process_create_time_filetime() -> u64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

        unsafe {
            let mut create_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut exit_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut kernel_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut user_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };

            // GetCurrentProcess trả pseudo-handle, không cần CloseHandle
            let ok = GetProcessTimes(
                GetCurrentProcess(),
                &mut create_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            );
            if ok != 0 {
                ((create_time.dwHighDateTime as u64) << 32) | create_time.dwLowDateTime as u64
            } else {
                0
            }
        }
    }
    #[cfg(not(windows))]
    {
        0
    }
}
