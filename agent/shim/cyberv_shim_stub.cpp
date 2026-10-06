// CyberV Shim STUB — dùng khi build không có Windows SDK/WinRT (không phải
// Windows hoặc môi trường chỉ có rustup-msvc tối thiểu). Mọi hàm trả
// CYBERV_SHIM_E_UNSUPPORTED — TRUNG THỰC: shim không có ⇒ không thể quảng bá/
// quét WFD/BLE ⇒ tầng Rust phải báo không hỗ trợ, KHÔNG BAO GIỜ giả vờ thấy
// peer. Build thật (WinRT) là cyberv_shim_winrt.cpp cùng ABI.

#include "cyberv_shim.h"

#include <cstring>

int cyberv_wfd_advertise_start(uint64_t* handle_out, uint32_t* os_error_out) {
    if (handle_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *handle_out = 0;
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_wfd_advertise_stop(uint64_t, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_wfd_requests_next(uint64_t, uint16_t* device_id_out, uint32_t,
                             uint32_t* device_id_len_out, uint32_t* os_error_out) {
    if (device_id_out == nullptr || device_id_len_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *device_id_len_out = 0;
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_wfd_requests_dropped(uint64_t, uint64_t* dropped_out) {
    if (dropped_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *dropped_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_wfd_connect(const uint16_t*, uint32_t, uint32_t,
                       uint8_t* remote_ip_out, uint16_t* remote_port_out,
                       uint32_t* os_error_out) {
    if (remote_ip_out == nullptr || remote_port_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_ble_adv_start(const uint8_t*, uint32_t len,
                         uint64_t* handle_out, uint32_t* os_error_out) {
    if (handle_out == nullptr || os_error_out == nullptr || (len == 0)) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    if (len > 26) {
        return CYBERV_SHIM_E_INVALID_ARG; // bounds vẫn kiểm ở stub — nhất quán
    }
    *handle_out = 0;
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_ble_adv_stop(uint64_t, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_ble_watch_start(uint64_t* handle_out, uint32_t* os_error_out) {
    if (handle_out == nullptr || os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *handle_out = 0;
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_ble_watch_stop(uint64_t, uint32_t* os_error_out) {
    if (os_error_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}

int cyberv_ble_watch_next(uint64_t, uint8_t* addr6_out,
                          uint8_t* payload_out, uint32_t,
                          uint32_t* payload_len_out, uint32_t* os_error_out) {
    if (addr6_out == nullptr || payload_out == nullptr || payload_len_out == nullptr) {
        return CYBERV_SHIM_E_INVALID_ARG;
    }
    *payload_len_out = 0;
    *os_error_out = 0;
    return CYBERV_SHIM_E_UNSUPPORTED;
}
