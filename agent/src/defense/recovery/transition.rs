//! Platform Transition & Update Detection (Phase 22)
//!
//! Ref: Docs/rv11.md Section 10:
//! Distinguishes expected OEM/OS updates from unexpected platform tampering.
//! Prevents bricking user devices upon legitimate BIOS or Windows Updates.

use crate::defense::firmware::config::FirmwareConfigReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformUpdateType {
    /// Không có thay đổi nào về phần cứng hay firmware
    Unchanged,
    /// Cập nhật BIOS/UEFI hợp lệ từ nhà sản xuất OEM (có chữ ký số OEM)
    ExpectedOemUpdate,
    /// Cập nhật hệ điều hành Windows Update hợp lệ
    ExpectedOsUpdate,
    /// Thay đổi bất thường không rõ nguồn gốc (Nghi ngờ can thiệp phần cứng/firmware)
    UnexpectedTampering,
}

pub struct TransitionDetector;

impl TransitionDetector {
    /// So sánh cấu hình baseline cũ và cấu hình đo lường mới
    pub fn detect(
        baseline_cfg: &FirmwareConfigReport,
        current_cfg: &FirmwareConfigReport,
        pcr_mismatch: bool,
    ) -> PlatformUpdateType {
        if !pcr_mismatch && baseline_cfg.bios_version == current_cfg.bios_version {
            return PlatformUpdateType::Unchanged;
        }

        // Nếu BIOS thay đổi và có chữ ký OEM hợp lệ
        if current_cfg.is_oem_signed && baseline_cfg.bios_vendor == current_cfg.bios_vendor {
            if baseline_cfg.bios_version != current_cfg.bios_version {
                return PlatformUpdateType::ExpectedOemUpdate;
            }
            // Nếu version giống nhau nhưng PCR thay đổi mà vẫn có chữ ký OEM và vendor khớp (ví dụ Windows bootloader update)
            return PlatformUpdateType::ExpectedOsUpdate;
        }

        // Thay đổi cấu hình hoặc PCR mà không có chữ ký OEM hợp lệ
        PlatformUpdateType::UnexpectedTampering
    }
}
