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
//! FFI bindings tới WinRT shim C++ (M-3 WiFi Direct / M-4 BLE).
//!
//! Ref: `agent/shim/cyberv_shim.h` (ABI contract) + HYBRID §1.1. Rust giữ
//! TOÀN BỘ logic — module này chỉ gọi qua biên giới và map mã lỗi thành
//! `ShimResult` trung thực. Non-Windows: mọi hàm trả `Unsupported` mà không
//! đụng FFI (shim stub cũng vậy — hai lớp phòng thủ nhất quán).
//!
//! Handles là singleton per-process (atomic) — registry phía C++ vốn global,
//! start/stop là cặp operations của node (một publisher/watcher mỗi loại).

use crate::mesh::MeshError;

/// Mã trạng thái của shim — đối chiếu 1-1 với `CybervShimStatus` trong C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ShimStatus {
    Ok = 0,
    Unsupported = 1,
    NotInitialized = 2,
    InvalidArg = 3,
    Busy = 4,
    OsError = 5,
    Timeout = 6,
    NotFound = 7,
    RadioOff = 8,
}

impl ShimStatus {
    pub const fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(ShimStatus::Ok),
            1 => Some(ShimStatus::Unsupported),
            2 => Some(ShimStatus::NotInitialized),
            3 => Some(ShimStatus::InvalidArg),
            4 => Some(ShimStatus::Busy),
            5 => Some(ShimStatus::OsError),
            6 => Some(ShimStatus::Timeout),
            7 => Some(ShimStatus::NotFound),
            8 => Some(ShimStatus::RadioOff),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ShimStatus::Ok => "OK",
            ShimStatus::Unsupported => "UNSUPPORTED",
            ShimStatus::NotInitialized => "NOT_INITIALIZED",
            ShimStatus::InvalidArg => "INVALID_ARG",
            ShimStatus::Busy => "BUSY",
            ShimStatus::OsError => "OS_ERROR",
            ShimStatus::Timeout => "TIMEOUT",
            ShimStatus::NotFound => "NOT_FOUND",
            ShimStatus::RadioOff => "RADIO_OFF",
        }
    }
}

/// Sample BLE watcher trả về: (MAC 6 byte, payload).
pub type WatchSample = ([u8; 6], Vec<u8>);

/// Kết quả gọi shim: mã trạng thái + mã lỗi WinRT gốc (khi có).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimResult {
    pub status: ShimStatus,
    pub os_error: u32,
}

impl ShimResult {
    pub fn to_mesh_error(self, what: &str) -> MeshError {
        MeshError::TransportIo(format!(
            "shim {what}: {} (os_error=0x{:08X})",
            self.status.as_str(),
            self.os_error
        ))
    }
}

/// Handle shim per-process — 0 = chưa start (registry C++ vốn global).
static WFD_ADV_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BLE_ADV_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BLE_WATCH_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(windows)]
mod imp {
    use super::{ShimResult, ShimStatus, WatchSample, WFD_ADV_HANDLE, BLE_ADV_HANDLE, BLE_WATCH_HANDLE};
    use std::os::raw::{c_int, c_uchar, c_uint, c_ushort, c_ulonglong};
    use std::sync::atomic::Ordering;

    extern "C" {
        fn cyberv_wfd_advertise_start(handle_out: *mut c_ulonglong, os_error_out: *mut c_uint) -> c_int;
        fn cyberv_wfd_advertise_stop(handle: c_ulonglong, os_error_out: *mut c_uint) -> c_int;
        fn cyberv_wfd_requests_next(
            handle: c_ulonglong,
            device_id_out: *mut c_ushort,
            device_id_cap_wchars: c_uint,
            device_id_len_out: *mut c_uint,
            os_error_out: *mut c_uint,
        ) -> c_int;
        fn cyberv_wfd_requests_dropped(handle: c_ulonglong, dropped_out: *mut c_ulonglong) -> c_int;
        fn cyberv_wfd_connect(
            device_id_utf16: *const c_ushort,
            device_id_len_wchars: c_uint,
            timeout_ms: c_uint,
            remote_ip16_out: *mut c_uchar,
            remote_port_out: *mut c_ushort,
            os_error_out: *mut c_uint,
        ) -> c_int;
        fn cyberv_ble_adv_start(
            payload: *const c_uchar,
            len: c_uint,
            handle_out: *mut c_ulonglong,
            os_error_out: *mut c_uint,
        ) -> c_int;
        fn cyberv_ble_adv_stop(handle: c_ulonglong, os_error_out: *mut c_uint) -> c_int;
        fn cyberv_ble_watch_start(handle_out: *mut c_ulonglong, os_error_out: *mut c_uint) -> c_int;
        fn cyberv_ble_watch_stop(handle: c_ulonglong, os_error_out: *mut c_uint) -> c_int;
        fn cyberv_ble_watch_next(
            handle: c_ulonglong,
            addr6_out: *mut c_uchar,
            payload_out: *mut c_uchar,
            payload_cap: c_uint,
            payload_len_out: *mut c_uint,
            os_error_out: *mut c_uint,
        ) -> c_int;
    }

    fn map(rc: c_int, os_error: u32) -> ShimResult {
        // Mã lạ → OsError (fail-closed, không map nửa vời).
        ShimResult { status: ShimStatus::from_i32(rc).unwrap_or(ShimStatus::OsError), os_error }
    }

    pub fn wfd_advertise_start() -> ShimResult {
        let (mut h, mut os) = (0u64, 0u32);
        let rc = unsafe { cyberv_wfd_advertise_start(&mut h, &mut os) };
        if rc == 0 {
            WFD_ADV_HANDLE.store(h, Ordering::SeqCst);
        }
        map(rc, os)
    }

    pub fn wfd_advertise_stop() -> ShimResult {
        let handle = WFD_ADV_HANDLE.swap(0, Ordering::SeqCst);
        if handle == 0 {
            return ShimResult { status: ShimStatus::NotInitialized, os_error: 0 };
        }
        let mut os = 0u32;
        map(unsafe { cyberv_wfd_advertise_stop(handle, &mut os) }, os)
    }

    /// Popped một ConnectionRequested — device_id UTF-16 → String (lossy).
    /// `Ok(None)` = hết hàng đợi (E_NOT_FOUND — chuyện bình thường).
    pub fn wfd_requests_next() -> Result<Option<String>, ShimResult> {
        let handle = WFD_ADV_HANDLE.load(Ordering::SeqCst);
        if handle == 0 {
            return Err(ShimResult { status: ShimStatus::NotInitialized, os_error: 0 });
        }
        let (mut id_buf, mut id_len, mut os) = ([0u16; 256], 0u32, 0u32);
        let rc = unsafe {
            cyberv_wfd_requests_next(handle, id_buf.as_mut_ptr(), 256, &mut id_len, &mut os)
        };
        if rc == 7 {
            return Ok(None);
        }
        let res = map(rc, os);
        if res.status != ShimStatus::Ok {
            return Err(res);
        }
        let len = (id_len as usize).min(256);
        Ok(Some(String::from_utf16_lossy(&id_buf[..len])))
    }

    pub fn wfd_requests_dropped() -> Result<u64, ShimResult> {
        let handle = WFD_ADV_HANDLE.load(Ordering::SeqCst);
        if handle == 0 {
            return Err(ShimResult { status: ShimStatus::NotInitialized, os_error: 0 });
        }
        let (mut dropped, os) = (0u64, 0u32);
        let rc = unsafe { cyberv_wfd_requests_dropped(handle, &mut dropped) };
        if rc != 0 {
            return Err(map(rc, os));
        }
        Ok(dropped)
    }

    pub fn wfd_connect(device_id_utf16: &[u16], timeout_ms: u32) -> Result<([u8; 17], u16), ShimResult> {
        let (mut ip17, mut port, mut os) = ([0u8; 17], 0u16, 0u32);
        let rc = unsafe {
            cyberv_wfd_connect(
                device_id_utf16.as_ptr(),
                device_id_utf16.len() as c_uint,
                timeout_ms,
                ip17.as_mut_ptr(),
                &mut port,
                &mut os,
            )
        };
        let res = map(rc, os);
        if res.status != ShimStatus::Ok {
            return Err(res);
        }
        Ok((ip17, port))
    }

    pub fn ble_adv_start(payload: &[u8]) -> ShimResult {
        let (mut h, mut os) = (0u64, 0u32);
        let rc = unsafe { cyberv_ble_adv_start(payload.as_ptr(), payload.len() as c_uint, &mut h, &mut os) };
        if rc == 0 {
            BLE_ADV_HANDLE.store(h, Ordering::SeqCst);
        }
        map(rc, os)
    }

    pub fn ble_adv_stop() -> ShimResult {
        let handle = BLE_ADV_HANDLE.swap(0, Ordering::SeqCst);
        if handle == 0 {
            return ShimResult { status: ShimStatus::NotInitialized, os_error: 0 };
        }
        let mut os = 0u32;
        map(unsafe { cyberv_ble_adv_stop(handle, &mut os) }, os)
    }

    pub fn ble_watch_start() -> ShimResult {
        let (mut h, mut os) = (0u64, 0u32);
        let rc = unsafe { cyberv_ble_watch_start(&mut h, &mut os) };
        if rc == 0 {
            BLE_WATCH_HANDLE.store(h, Ordering::SeqCst);
        }
        map(rc, os)
    }

    pub fn ble_watch_stop() -> ShimResult {
        let handle = BLE_WATCH_HANDLE.swap(0, Ordering::SeqCst);
        if handle == 0 {
            return ShimResult { status: ShimStatus::NotInitialized, os_error: 0 };
        }
        let mut os = 0u32;
        map(unsafe { cyberv_ble_watch_stop(handle, &mut os) }, os)
    }

    /// `Ok(None)` = chưa có quảng bá mới (E_NOT_FOUND — bình thường).
    pub fn ble_watch_next() -> Result<Option<WatchSample>, ShimResult> {
        let handle = BLE_WATCH_HANDLE.load(Ordering::SeqCst);
        if handle == 0 {
            return Err(ShimResult { status: ShimStatus::NotInitialized, os_error: 0 });
        }
        let (mut addr6, mut payload_buf, mut payload_len, mut os) =
            ([0u8; 6], [0u8; 32], 0u32, 0u32);
        let rc = unsafe {
            cyberv_ble_watch_next(handle, addr6.as_mut_ptr(), payload_buf.as_mut_ptr(), 32, &mut payload_len, &mut os)
        };
        if rc == 7 {
            return Ok(None);
        }
        let res = map(rc, os);
        if res.status != ShimStatus::Ok {
            return Err(res);
        }
        let len = (payload_len as usize).min(32);
        Ok(Some((addr6, payload_buf[..len].to_vec())))
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{ShimResult, ShimStatus, WatchSample};

    fn unsupported() -> ShimResult {
        ShimResult { status: ShimStatus::Unsupported, os_error: 0 }
    }

    pub fn wfd_advertise_start() -> ShimResult {
        unsupported()
    }
    pub fn wfd_advertise_stop() -> ShimResult {
        unsupported()
    }
    pub fn wfd_requests_next() -> Result<Option<String>, ShimResult> {
        Err(unsupported())
    }
    pub fn wfd_requests_dropped() -> Result<u64, ShimResult> {
        Err(unsupported())
    }
    pub fn wfd_connect(_device_id_utf16: &[u16], _timeout_ms: u32) -> Result<([u8; 17], u16), ShimResult> {
        Err(unsupported())
    }
    pub fn ble_adv_start(_payload: &[u8]) -> ShimResult {
        unsupported()
    }
    pub fn ble_adv_stop() -> ShimResult {
        unsupported()
    }
    pub fn ble_watch_start() -> ShimResult {
        unsupported()
    }
    pub fn ble_watch_stop() -> ShimResult {
        unsupported()
    }
    pub fn ble_watch_next() -> Result<Option<WatchSample>, ShimResult> {
        Err(unsupported())
    }
}

pub use imp::*;
