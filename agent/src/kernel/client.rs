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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawCybervAbiHeader {
    pub magic: u32,
    pub abi_version: u32,
    pub header_size: u32,
    pub total_payload_size: u32,
    pub flags: u32,
    pub reserved: [u32; 4],
}

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
    // Phải bằng CYBERV_ABI_VERSION — driver từ chối đăng ký nếu lệch
    // (anti ABI drift; đối xứng với `unsigned long long ClientAbiVersion` trong ioctl.h)
    client_abi_version: u64,
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
                    client_abi_version: super::protocol::CYBERV_ABI_VERSION as u64,
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

                if success == 0 {
                    return None;
                }

                // Parse qua pure function tren raw bytes (khong reinterpret struct)
                // de co the kiem thu/fuzz ma khong can driver.
                // (da nam trong unsafe block DeviceIoControl ben tren)
                let raw_bytes = std::slice::from_raw_parts(
                    &raw_obs as *const RawCybervKernelObservation as *const u8,
                    std::mem::size_of::<RawCybervKernelObservation>(),
                );
                parse_kernel_observation_bytes(raw_bytes, bytes_returned as usize)
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


/// Kích thước header `CYBERV_KERNEL_OBSERVATION`: u32 driver_version + u32 device_count + u64 observed_at
pub const KERNEL_OBSERVATION_HEADER_SIZE: usize = 16;
/// Kích thước một entry `CYBERV_PCI_DEVICE` (packed): 14 byte header + 64 byte serial
pub const KERNEL_PCI_DEVICE_SIZE: usize = 78;
/// Số thiết bị tối đa mà ABI cho phép trong một frame
pub const KERNEL_MAX_DEVICES: usize = 32;

/// Pure parser cho payload trả về bởi IOCTL_CYBERV_GET_PCI_INFO.
///
/// Tách khỏi DeviceIoControl để kiểm thử/fuzz trực tiếp mà không cần driver.
/// Fail-closed ở mọi điểm: frame ngắn, sai ABI version, device_count vượt giới
/// hạn, hay bytes_returned không đủ chứa toàn bộ devices đều trả `None`
/// (trước đây device_count bị clamp im lặng và partial frame vẫn được tin).
pub fn parse_kernel_observation_bytes(
    bytes: &[u8],
    bytes_returned: usize,
) -> Option<KernelObservationPayload> {
    if bytes.len() < KERNEL_OBSERVATION_HEADER_SIZE
        || bytes_returned < KERNEL_OBSERVATION_HEADER_SIZE
    {
        return None;
    }

    fn read_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }
    fn read_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }
    fn read_u64(b: &[u8], off: usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&b[off..off + 8]);
        u64::from_le_bytes(arr)
    }

    // Anti ABI drift: driver phải cùng version ABI với client
    let driver_version = read_u32(bytes, 0);
    if driver_version != super::protocol::CYBERV_ABI_VERSION {
        return None;
    }

    let device_count_raw = read_u32(bytes, 4) as usize;
    if device_count_raw > KERNEL_MAX_DEVICES {
        // Frame khai báo nhiều hơn giới hạn ABI -> dữ liệu hỏng/giả mạo
        return None;
    }
    let observed_at = read_u64(bytes, 8);

    // Không tin partial data: đủ byte cho TOÀN BỘ devices khai báo mới chấp nhận
    let needed = KERNEL_OBSERVATION_HEADER_SIZE + device_count_raw * KERNEL_PCI_DEVICE_SIZE;
    if bytes_returned < needed || bytes.len() < needed {
        return None;
    }

    let mut devices = Vec::with_capacity(device_count_raw);
    for i in 0..device_count_raw {
        let base = KERNEL_OBSERVATION_HEADER_SIZE + i * KERNEL_PCI_DEVICE_SIZE;
        let dev = &bytes[base..base + KERNEL_PCI_DEVICE_SIZE];

        let sn_bytes = &dev[14..78];
        let sn_len = sn_bytes.iter().position(|&b| b == 0).unwrap_or(sn_bytes.len());
        let serial_number = std::str::from_utf8(&sn_bytes[..sn_len])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        devices.push(KernelPciDevice {
            vendor_id: read_u16(dev, 0),
            device_id: read_u16(dev, 2),
            subsystem_vendor_id: read_u16(dev, 4),
            subsystem_device_id: read_u16(dev, 6),
            segment: read_u16(dev, 8),
            bus: dev[10],
            device: dev[11],
            function: dev[12],
            device_class: dev[13],
            serial_number,
        });
    }

    Some(KernelObservationPayload::new(
        driver_version,
        devices,
        observed_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dựng một frame observation hợp lệ theo ABI layout
    fn build_frame(device_count: u32, serial: Option<&str>) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&super::super::protocol::CYBERV_ABI_VERSION.to_le_bytes());
        frame.extend_from_slice(&device_count.to_le_bytes());
        frame.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
        for i in 0..device_count as usize {
            let mut dev = vec![0u8; KERNEL_PCI_DEVICE_SIZE];
            dev[0..2].copy_from_slice(&0x8086u16.to_le_bytes());
            dev[2..4].copy_from_slice(&(0x1000u16 + i as u16).to_le_bytes());
            dev[13] = 0x01; // DeviceClass
            if let Some(sn) = serial {
                let bytes = sn.as_bytes();
                let n = bytes.len().min(63);
                dev[14..14 + n].copy_from_slice(&bytes[..n]);
            }
            frame.extend_from_slice(&dev);
        }
        frame
    }

    #[test]
    fn parses_valid_frame() {
        let frame = build_frame(2, Some("SN12345678"));
        let payload = parse_kernel_observation_bytes(&frame, frame.len()).expect("valid frame");
        assert_eq!(payload.devices.len(), 2);
        assert_eq!(payload.devices[0].vendor_id, 0x8086);
        assert_eq!(payload.devices[1].device_id, 0x1001);
        assert_eq!(payload.devices[0].serial_number.as_deref(), Some("SN12345678"));
    }

    #[test]
    fn rejects_wrong_abi_version() {
        let mut frame = build_frame(1, None);
        frame[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_kernel_observation_bytes(&frame, frame.len()).is_none());
    }

    #[test]
    fn rejects_oversized_device_count() {
        let mut frame = build_frame(1, None);
        frame[4..8].copy_from_slice(&33u32.to_le_bytes());
        assert!(parse_kernel_observation_bytes(&frame, frame.len()).is_none());
    }

    #[test]
    fn rejects_truncated_frames() {
        let frame = build_frame(4, Some("SN"));
        // Cắt giữa chừng: bytes_returned nhỏ hơn cần thiết cho 4 devices
        assert!(parse_kernel_observation_bytes(&frame, 16 + 2 * KERNEL_PCI_DEVICE_SIZE).is_none());
        // Buffer tồn tại nhưng bytes_returned chủ đủ header
        assert!(parse_kernel_observation_bytes(&frame, 16).is_none());
        // Buffer ngắn hơn header
        assert!(parse_kernel_observation_bytes(&frame[..10], 10).is_none());
        assert!(parse_kernel_observation_bytes(&[], 0).is_none());
    }

    #[test]
    fn serial_parsing_handles_nul_utf8_and_empty() {
        // Serial có NUL terminator + trailing junk
        let mut frame = build_frame(1, Some("CLEAN_SN"));
        let dev_off = KERNEL_OBSERVATION_HEADER_SIZE;
        frame[dev_off + 14 + 8] = 0x00; // terminate sau 8 ký tự
        frame[dev_off + 14 + 9] = 0xAB; // junk sau NUL
        let payload = parse_kernel_observation_bytes(&frame, frame.len()).unwrap();
        assert_eq!(payload.devices[0].serial_number.as_deref(), Some("CLEAN_SN"));

        // Serial không phải UTF-8 -> None, không panic
        let mut frame2 = build_frame(1, None);
        frame2[dev_off + 14] = 0xFF;
        frame2[dev_off + 15] = 0xFE;
        let payload2 = parse_kernel_observation_bytes(&frame2, frame2.len()).unwrap();
        assert!(payload2.devices[0].serial_number.is_none());

        // Serial rỗng -> None
        let frame3 = build_frame(1, None);
        let payload3 = parse_kernel_observation_bytes(&frame3, frame3.len()).unwrap();
        assert!(payload3.devices[0].serial_number.is_none());
    }

    /// Fuzz-style: dữ liệu ngẫu nhiên deterministic KHÔNG ĐƯỢC panic
    /// (trước đây test tương đương là tautology `assert!(x.is_none() || x.is_some())`).
    #[test]
    fn fuzz_random_bytes_never_panic_and_never_accept_garbage() {
        // xorshift64* deterministic
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };

        for _round in 0..2000 {
            let len = (next() % 2600) as usize;
            let mut bytes = vec![0u8; len];
            for chunk in bytes.chunks_mut(8) {
                let v = next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            let bytes_returned = (next() % 2600) as usize;

            let result = parse_kernel_observation_bytes(&bytes, bytes_returned);
            if let Some(payload) = result {
                // Nếu chấp nhận thì bắt buộc là frame hợp lệ:
                // ABI khớp + devices trong giới hạn
                assert!(payload.devices.len() <= KERNEL_MAX_DEVICES);
            }
        }
    }

    #[test]
    fn parse_is_deterministic() {
        let frame = build_frame(3, Some("DET"));
        let a = parse_kernel_observation_bytes(&frame, frame.len()).unwrap();
        let b = parse_kernel_observation_bytes(&frame, frame.len()).unwrap();
        assert_eq!(a, b);
    }
}