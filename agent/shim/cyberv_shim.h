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
// CyberV WinRT Shim — ABI contract (extern "C" thuần)
//
// Ref: Docs/HYBRID_DISTRIBUTION_PLAN.md §1.1 (quy tắc biên giới FFI bắt buộc)
// + Docs/TRANSPORT_ISOLATION_PLAN.md M-3 (WiFi Direct) / M-4 (BLE beacon).
//
// RANH GIỚI TRUNG THỰC: shim chỉ transliterate WinRT API (WiFiDirect /
// BluetoothLEAdvertisement) — KHÔNG business logic; logic nằm Rust (test được).
// ABI extern "C" thuần: không C++ object/exception qua biên giới; lỗi trả mã
// enum + os_error gốc qua con trỏ out; bộ nhớ một chiều — RUST cấp buffer,
// shim chỉ ghi (bounds do Rust truyền).
//
// Mỗi hàm có 1 test biên giới ở agent/tests/mesh_shim_boundary_tests.rs.

#ifndef CYBERV_SHIM_H
#define CYBERV_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Mã trạng thái — mọi nhánh lỗi là NHÁN TỪ CHỐI trung thực.
enum CybervShimStatus {
    CYBERV_SHIM_OK = 0,
    CYBERV_SHIM_E_UNSUPPORTED = 1,   // build stub / nền không có WinRT API này
    CYBERV_SHIM_E_NOT_INITIALIZED = 2,
    CYBERV_SHIM_E_INVALID_ARG = 3,   // buffer/null/len sai
    CYBERV_SHIM_E_BUSY = 4,          // đã advertise/watch rồi
    CYBERV_SHIM_E_OS_ERROR = 5,      // WinRT lỗi — mã gốc trong *os_error_out
    CYBERV_SHIM_E_TIMEOUT = 6,       // connect/việc chờ vượt timeout_ms
    CYBERV_SHIM_E_NOT_FOUND = 7,     // endpoint/device không còn thấy
    CYBERV_SHIM_E_RADIO_OFF = 8,     // adapter không hỗ trợ / radio tắt
};

// ---- WiFi Direct (M-3, Tier B — flag tắt mặc định) -------------------------
// Mô hình: shim chỉ lo PHẦN WinRT (publish discoverability, nhận
// ConnectionRequested, thiết lập phiên WFD và ĐỌC endpoint pair). Data path
// là TCP thuần trên endpoint đó — Rust tự connect/handshake/AEAD (tái dụng
// TcpLink, path_class = TransportId::WiFiDirect).
//
// TRUNG THỰC (giới hạn metadata SDK): WiFiDirectAdvertisementWatcher không có
// trong Windows.winmd của SDK cài tại máy — KHÔNG có browse chủ động. Khởi
// tạo kết nối dùng device_id ĐÃ PIN qua enrollment (pin_wfd_device); phía
// accept nhận device_id từ ConnectionRequested. Bổ sung Watcher khi có
// contract winmd đầy đủ.

int cyberv_wfd_advertise_start(uint64_t* handle_out, uint32_t* os_error_out);
int cyberv_wfd_advertise_stop(uint64_t handle, uint32_t* os_error_out);

// Popped một ConnectionRequested (peer yêu cầu phiên tới mình): device_id
// UTF-16 ghi vào buffer Rust (cap wchar); trả độ dài đã ghi (không gồm NUL).
// Trả CYBERV_SHIM_E_NOT_FOUND khi hết hàng đợi. Queue cap 64 — drop-cũ-nhất
// đếm được qua cyberv_wfd_requests_dropped.
int cyberv_wfd_requests_next(uint64_t handle,
                             uint16_t* device_id_out, uint32_t device_id_cap_wchars,
                             uint32_t* device_id_len_out, uint32_t* os_error_out);
int cyberv_wfd_requests_dropped(uint64_t handle, uint64_t* dropped_out);

// Thiết lập phiên WFD theo device_id (initiator với id đã pin enrollment,
// hoặc accept request đã lấy từ requests_next): trả endpoint pair (IP +
// port) để RUST tự connect TCP + bắt tay mesh. remote_ip_out là buffer 17
// BYTE: byte 0 = family marker (4 = IPv4 + 4 octet; 6 = IPv6 + 16 octet).
int cyberv_wfd_connect(const uint16_t* device_id_utf16, uint32_t device_id_len_wchars,
                       uint32_t timeout_ms,
                       uint8_t* remote_ip_out, uint16_t* remote_port_out,
                       uint32_t* os_error_out);

// ---- BLE advertisement (M-4, Tier C — discovery only, zero trust) -----------

// Payload ≤ 26 byte (BLE legacy adv data), RUST tự nén/kiểm bounds.
int cyberv_ble_adv_start(const uint8_t* payload, uint32_t len,
                         uint64_t* handle_out, uint32_t* os_error_out);
int cyberv_ble_adv_stop(uint64_t handle, uint32_t* os_error_out);

int cyberv_ble_watch_start(uint64_t* handle_out, uint32_t* os_error_out);
int cyberv_ble_watch_stop(uint64_t handle, uint32_t* os_error_out);
// Nhận một quảng bá khớp filter: addr6 (6 byte MAC) + payload copy vào
// buffer Rust. Trả CYBERV_SHIM_E_NOT_FOUND khi chưa có gì mới.
int cyberv_ble_watch_next(uint64_t handle, uint8_t* addr6_out,
                          uint8_t* payload_out, uint32_t payload_cap,
                          uint32_t* payload_len_out, uint32_t* os_error_out);

#ifdef __cplusplus
}
#endif

#endif // CYBERV_SHIM_H
