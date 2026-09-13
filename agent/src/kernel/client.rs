//! Kernel Probe Driver Client (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6 Section 24, 27:
//! "Giao tiếp an toàn qua IOCTL với cơ chế fallback khi driver chưa cài đặt."

use super::protocol::{KernelObservationPayload, KernelPciDevice, KernelShieldTelemetry};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawCybervPciDevice {
    vendor_id: u16,
    device_id: u16,
    subsystem_vendor_id: u16,
    subsystem_device_id: u16,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    device_class: u8,
    serial_number: [u8; 64],
}

#[repr(C, packed)]
struct RawCybervKernelObservation {
    driver_version: u32,
    device_count: u32,
    observed_at: u64,
    devices: [RawCybervPciDevice; 32],
}

#[repr(C, packed)]
struct RawProtectedProcessRegistration {
    process_id: u32,
    process_start_time: u64,
    registration_nonce: [u8; 64],
    driver_instance_id: u32,
}

#[repr(C, packed)]
struct RawShieldTelemetry {
    protected_pid: u32,
    blocked_terminations: u32,
    blocked_vm_reads: u32,
    blocked_vm_writes: u32,
    suspicious_attempts: u32,
    driver_unload_attempts: u32,
    is_shield_active: u32,
}

pub trait KernelProbeProvider: Send + Sync {
    fn is_driver_available(&self) -> bool;
    fn query_kernel_observation(&self) -> Option<KernelObservationPayload>;
}

/// Client giao tiếp với Driver KMDF thực tế trên Windows qua DeviceIoControl
pub struct WindowsKernelClient {
    device_path: String,
}

impl WindowsKernelClient {
    pub fn new() -> Self {
        Self {
            device_path: r"\\.\CyberVProbe".to_string(),
        }
    }

    /// Đăng ký bảo vệ tiến trình (Ring-0 Object Manager ObRegisterCallbacks)
    pub fn register_protected_pid(
        &self,
        pid: u32,
        start_time: u64,
        nonce: [u8; 64],
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = self
                .device_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let handle = CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(format!(
                        "Không thể mở kết nối tới driver CyberVProbe (Error: {})",
                        GetLastError()
                    ));
                }

                let mut reg = RawProtectedProcessRegistration {
                    process_id: pid,
                    process_start_time: start_time,
                    registration_nonce: nonce,
                    driver_instance_id: 1,
                };
                let mut bytes_returned: u32 = 0;

                let success = DeviceIoControl(
                    handle,
                    super::protocol::IOCTL_CYBERV_REGISTER_PROTECTED_PID,
                    &mut reg as *mut _ as *mut _,
                    std::mem::size_of::<RawProtectedProcessRegistration>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                );

                CloseHandle(handle);

                if success == 0 {
                    return Err(format!(
                        "IOCTL_CYBERV_REGISTER_PROTECTED_PID thất bại (Win32 Error: {})",
                        GetLastError()
                    ));
                }

                Ok(())
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (pid, start_time, nonce);
            Err("Chỉ hỗ trợ môi trường Windows".to_string())
        }
    }

    /// Truy vấn số liệu thống kê phòng thủ từ Ring-0 Shield
    pub fn query_shield_telemetry(&self) -> Result<KernelShieldTelemetry, String> {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = self
                .device_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let handle = CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    return Err(format!(
                        "Không thể mở driver CyberVProbe (Error: {})",
                        GetLastError()
                    ));
                }

                let mut raw_telem: RawShieldTelemetry = std::mem::zeroed();
                let mut bytes_returned: u32 = 0;

                let success = DeviceIoControl(
                    handle,
                    super::protocol::IOCTL_CYBERV_GET_SHIELD_TELEMETRY,
                    std::ptr::null(),
                    0,
                    &mut raw_telem as *mut _ as *mut _,
                    std::mem::size_of::<RawShieldTelemetry>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                );

                CloseHandle(handle);

                if success == 0 {
                    return Err(format!(
                        "IOCTL_CYBERV_GET_SHIELD_TELEMETRY thất bại (Error: {})",
                        GetLastError()
                    ));
                }

                Ok(KernelShieldTelemetry {
                    protected_pid: raw_telem.protected_pid,
                    blocked_terminations: raw_telem.blocked_terminations,
                    blocked_vm_reads: raw_telem.blocked_vm_reads,
                    blocked_vm_writes: raw_telem.blocked_vm_writes,
                    suspicious_attempts: raw_telem.suspicious_attempts,
                    driver_unload_attempts: raw_telem.driver_unload_attempts,
                    is_shield_active: raw_telem.is_shield_active != 0,
                })
            }
        }
        #[cfg(not(windows))]
        {
            Err("Chỉ hỗ trợ môi trường Windows".to_string())
        }
    }
}

impl Default for WindowsKernelClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelProbeProvider for WindowsKernelClient {
    fn is_driver_available(&self) -> bool {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = self
                .device_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let handle = CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                );
                if handle != INVALID_HANDLE_VALUE {
                    CloseHandle(handle);
                    true
                } else {
                    let err = GetLastError();
                    // ERROR_ACCESS_DENIED (5) means driver probe is loaded and device exists,
                    // but calling process needs Administrator / SYSTEM privilege
                    err == ERROR_ACCESS_DENIED
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = &self.device_path;
            false
        }
    }

    fn query_kernel_observation(&self) -> Option<KernelObservationPayload> {
        #[cfg(windows)]
        {
            let wide_path: Vec<u16> = self
                .device_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let handle = CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    return None;
                }

                let mut raw_obs: RawCybervKernelObservation = std::mem::zeroed();
                let mut bytes_returned: u32 = 0;

                let success = DeviceIoControl(
                    handle,
                    super::protocol::IOCTL_CYBERV_GET_PCI_INFO,
                    std::ptr::null(),
                    0,
                    &mut raw_obs as *mut _ as *mut _,
                    std::mem::size_of::<RawCybervKernelObservation>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                );

                CloseHandle(handle);

                let header_size = std::mem::size_of::<u32>() * 2 + std::mem::size_of::<u64>();
                if success == 0 || (bytes_returned as usize) < header_size {
                    return None;
                }

                let count = (raw_obs.device_count as usize).min(32);
                let mut devices = Vec::with_capacity(count);
                for i in 0..count {
                    let dev = &raw_obs.devices[i];
                    let sn_bytes = &dev.serial_number;
                    let sn_len = sn_bytes.iter().position(|&b| b == 0).unwrap_or(sn_bytes.len());
                    let sn_str = std::str::from_utf8(&sn_bytes[..sn_len])
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());

                    devices.push(KernelPciDevice {
                        vendor_id: dev.vendor_id,
                        device_id: dev.device_id,
                        subsystem_vendor_id: dev.subsystem_vendor_id,
                        subsystem_device_id: dev.subsystem_device_id,
                        segment: dev.segment,
                        bus: dev.bus,
                        device: dev.device,
                        function: dev.function,
                        device_class: dev.device_class,
                        serial_number: sn_str,
                    });
                }

                Some(KernelObservationPayload::new(
                    raw_obs.driver_version,
                    devices,
                    raw_obs.observed_at,
                ))
            }
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

/// Client giả lập phục vụ kiểm thử ma trận an ninh Cross-Validation
pub struct MockKernelClient {
    available: bool,
    payload: Option<KernelObservationPayload>,
}

impl MockKernelClient {
    pub fn available(payload: KernelObservationPayload) -> Self {
        Self {
            available: true,
            payload: Some(payload),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            available: false,
            payload: None,
        }
    }
}

impl KernelProbeProvider for MockKernelClient {
    fn is_driver_available(&self) -> bool {
        self.available
    }

    fn query_kernel_observation(&self) -> Option<KernelObservationPayload> {
        if self.available {
            self.payload.clone()
        } else {
            None
        }
    }
}
