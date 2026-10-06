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
//! M-PLAN M-3/M-4 — test biên giới shim C++ (HYBRID §1.1: MỖI hàm shim có
//! 1 test biên giới). Shim WinRT thật nếu máy có SDK; stub trả UNSUPPORTED
//! nếu không — CẢ HAI phải hành xử trung thực (không bao giờ OK giả).
//!
//! Handles shim là singleton per-process ⇒ mọi test đụng radio phải giữ
//! SHIM_LOCK để không giẫm chân nhau khi cargo chạy song song.

use std::sync::{Mutex, MutexGuard, OnceLock};

use cyberv_agent::mesh::transport::shim::{self, ShimStatus};

fn shim_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Hợp lệ cho start khi radio có/không: OK (đã bật thật) hoặc lỗi trung thực.
/// UNSUPPORTED chỉ hợp lệ khi shim là stub (build không có SDK).
fn honest_start_verdict(res: shim::ShimResult) -> bool {
    matches!(
        res.status,
        ShimStatus::Ok | ShimStatus::RadioOff | ShimStatus::OsError
    )
}

#[test]
fn boundary_wfd_advertise_start_stop_roundtrip() {
    let _guard = shim_lock();
    let start = shim::wfd_advertise_start();
    assert!(honest_start_verdict(start), "start phải trung thực: {:?}", start);
    let stop = shim::wfd_advertise_stop();
    assert_eq!(stop.status, ShimStatus::Ok, "stop sau start thành công phải OK");
}

#[test]
fn boundary_wfd_advertise_stop_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let stop = shim::wfd_advertise_stop();
    assert_eq!(stop.status, ShimStatus::NotInitialized);
}

#[test]
fn boundary_wfd_requests_next_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let res = shim::wfd_requests_next();
    assert!(matches!(res, Err(r) if r.status == ShimStatus::NotInitialized));
}

#[test]
fn boundary_wfd_requests_dropped_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let res = shim::wfd_requests_dropped();
    assert!(matches!(res, Err(r) if r.status == ShimStatus::NotInitialized));
}

#[test]
fn boundary_wfd_connect_empty_device_id_is_invalid_arg() {
    let _guard = shim_lock();
    // Deterministic trên cả shim thật lẫn stub — bounds nằm trước radio.
    let res = shim::wfd_connect(&[], 100);
    assert!(matches!(res, Err(r) if r.status == ShimStatus::InvalidArg));
}

#[test]
fn boundary_wfd_connect_unknown_device_times_out_or_not_found() {
    let _guard = shim_lock();
    // device_id không tồn tại: shim thật → NOT_FOUND/TIMEOUT/OS_ERROR;
    // stub → UNSUPPORTED. Không được OK (không thể connect thứ không có).
    let device_id: Vec<u16> = "\\\\?\\SWD#WiFiDirect#cyberv-nonexistent#".encode_utf16().collect();
    let res = shim::wfd_connect(&device_id, 250);
    match res {
        Err(r) => assert!(
            matches!(
                r.status,
                ShimStatus::NotFound
                    | ShimStatus::Timeout
                    | ShimStatus::OsError
                    | ShimStatus::Unsupported
            ),
            "connect peer không tồn tại phải từ chối trung thực: {r:?}"
        ),
        Ok(_) => panic!("connect peer không tồn tại không được OK"),
    }
}

#[test]
fn boundary_ble_adv_bounds_enforced_before_radio() {
    let _guard = shim_lock();
    // Payload rỗng / vượt 26 byte → INVALID_ARG (deterministic, không đụng radio).
    let res_empty = shim::ble_adv_start(&[]);
    assert_eq!(res_empty.status, ShimStatus::InvalidArg);
    let res_big = shim::ble_adv_start(&[0u8; 27]);
    assert_eq!(res_big.status, ShimStatus::InvalidArg);
}

#[test]
fn boundary_ble_adv_start_stop_roundtrip() {
    let _guard = shim_lock();
    let beacon = cyberv_agent::mesh::transport::ble::BleBeacon26::from_identity(&[7u8; 32], &[9u8; 32]);
    let start = shim::ble_adv_start(&beacon.encode());
    assert!(honest_start_verdict(start), "start phải trung thực: {:?}", start);
    let stop = shim::ble_adv_stop();
    assert_eq!(stop.status, ShimStatus::Ok);
}

#[test]
fn boundary_ble_adv_stop_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let stop = shim::ble_adv_stop();
    assert_eq!(stop.status, ShimStatus::NotInitialized);
}

#[test]
fn boundary_ble_watch_next_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let res = shim::ble_watch_next();
    assert!(matches!(res, Err(r) if r.status == ShimStatus::NotInitialized));
}

#[test]
fn boundary_ble_watch_start_next_stop_roundtrip() {
    let _guard = shim_lock();
    let start = shim::ble_watch_start();
    assert!(honest_start_verdict(start), "watch start phải trung thực: {:?}", start);
    if start.status == ShimStatus::Ok {
        let next = shim::ble_watch_next();
        match next {
            Ok(None) | Ok(Some(_)) => {}
            Err(r) => assert_eq!(r.status, ShimStatus::Ok, "next lỗi bất thường: {r:?}"),
        }
        let stop = shim::ble_watch_stop();
        assert_eq!(stop.status, ShimStatus::Ok);
    } else {
        let stop = shim::ble_watch_stop();
        assert_eq!(stop.status, ShimStatus::NotInitialized);
    }
}

#[test]
fn boundary_ble_watch_stop_without_start_is_not_initialized() {
    let _guard = shim_lock();
    let stop = shim::ble_watch_stop();
    assert_eq!(stop.status, ShimStatus::NotInitialized);
}
