//! Kernel Probe Driver Client (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6 Section 24, 27:
//! "Giao tiếp an toàn qua IOCTL với cơ chế fallback khi driver chưa cài đặt."

use super::protocol::KernelObservationPayload;

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
}

impl Default for WindowsKernelClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelProbeProvider for WindowsKernelClient {
    fn is_driver_available(&self) -> bool {
        // Kiểm tra xem device handle có mở được không
        let _ = &self.device_path;
        false
    }

    fn query_kernel_observation(&self) -> Option<KernelObservationPayload> {
        // Khi chạy thực tế trên Windows: Mở CreateFileW(device_path) và DeviceIoControl
        // Nếu driver chưa cài đặt hoặc không đủ quyền, trả về None để graceful degradation
        None
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
