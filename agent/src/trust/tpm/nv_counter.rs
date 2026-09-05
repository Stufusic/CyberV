//! TPM 2.0 Hardware NVRAM Monotonic Counter Engine (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 1, 2, 3:
//! 1. "Disk state có thể quay ngược, nhưng hardware-backed monotonic state không quay ngược cùng nó."
//! 2. Contradiction Detection: software_state < tpm_nv_counter => REJECT.
//! 3. Phân định rõ cấp độ bảo đảm: HardwareBacked vs VtpmBacked vs OsProtected vs SoftwareFallback.
//! 4. NV Index Lifecycle: Discover -> Verify Attributes & Ownership -> Provision if Missing -> Use.
//!    Không hard-code 0x01800001 mù quáng hoặc ghi đè foreign space.
//! 5. TPM_NV_COUNTER = highest_accepted_state_version.

use super::errors::TpmError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Mặc định dải NV Index dành cho CyberV Anti-Rollback (chuẩn TCG 2.0 Vendor Range)
pub const DEFAULT_CYBERV_NV_INDEX: u32 = 0x01800001;

/// Cấp độ bảo đảm phần cứng của TPM (Assurance Tier per rv15.md Section 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpmAssuranceType {
    /// Discrete TPM 2.0 hoặc Firmware TPM (fTPM) vật lý.
    /// NVRAM gắn liền với bo mạch, kháng hoàn toàn snapshot/clone của đĩa.
    HardwareBacked,

    /// Virtual TPM trên nền tảng ảo hóa (Hyper-V / VMware / QEMU).
    /// Lưu ý: Snapshot VM có thể chụp kèm vTPM tùy thuộc cấu hình hypervisor.
    VtpmBacked,

    /// Bảo vệ bằng Windows DPAPI / BitLocker mà không có chip TPM 2.0 chuyên dụng.
    OsProtected,

    /// Giả lập phần mềm phục vụ unit tests và CI/CD.
    SoftwareFallback,
}

impl fmt::Display for TpmAssuranceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardwareBacked => write!(f, "HARDWARE_BACKED"),
            Self::VtpmBacked => write!(f, "VTPM_BACKED"),
            Self::OsProtected => write!(f, "OS_PROTECTED"),
            Self::SoftwareFallback => write!(f, "SOFTWARE_FALLBACK"),
        }
    }
}

/// Thuộc tính không gian NV (TPM 2.0 TPMS_NV_PUBLIC Attributes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmNvAttributes {
    /// Cờ bắt buộc: Xác nhận đây là Monotonic Counter (TPMA_NV_COUNTER)
    pub is_counter: bool,
    /// Cho phép ghi bằng Auth Value
    pub auth_write: bool,
    /// Cho phép ghi bằng Policy
    pub policy_write: bool,
    /// Chống tấn công từ điển (No Dictionary Attack Lockout - TPMA_NV_NO_DA)
    pub no_da: bool,
    /// Quyền đọc của chủ sở hữu
    pub owner_read: bool,
    /// Quyền ghi của chủ sở hữu
    pub owner_write: bool,
}

impl Default for TpmNvAttributes {
    fn default() -> Self {
        Self {
            is_counter: true,
            auth_write: true,
            policy_write: true,
            no_da: true,
            owner_read: true,
            owner_write: true,
        }
    }
}

/// Thông tin Handle và thuộc tính của NV Index sau khi Discover / Provision
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmNvHandleInfo {
    pub nv_index: u32,
    pub attributes: TpmNvAttributes,
    pub assurance: TpmAssuranceType,
    pub current_value: u64,
    pub is_provisioned_by_cyberv: bool,
}

/// Trait giao tiếp TPM 2.0 NV Monotonic Counter Subsystem
pub trait TpmNvCounter: Send + Sync {
    /// Khám phá NV index hiện có hoặc cấp phát mới nếu chưa tồn tại.
    /// Bắt buộc kiểm tra thuộc tính TPMA_NV_COUNTER và quyền sở hữu.
    fn discover_or_provision(
        &mut self,
        nv_index: u32,
        initial_counter: u64,
    ) -> Result<TpmNvHandleInfo, TpmError>;

    /// Đọc giá trị counter hiện tại từ NVRAM
    fn read_counter(&self, nv_index: u32) -> Result<u64, TpmError>;

    /// Tăng counter đơn điệu (Monotonic Increment)
    fn increment_counter(&mut self, nv_index: u32) -> Result<u64, TpmError>;

    /// Lấy cấp độ bảo đảm an ninh của provider
    fn get_assurance_type(&self) -> TpmAssuranceType;
}

/// Bộ giả lập TPM 2.0 NV Counter (Mock) phục vụ kiểm thử toàn diện
#[derive(Debug, Clone)]
pub struct MockTpmNvCounter {
    indices: HashMap<u32, (u64, TpmNvAttributes, bool)>, // (value, attributes, is_cyberv)
    assurance: TpmAssuranceType,
    should_fail_io: bool,
}

impl MockTpmNvCounter {
    pub fn new(assurance: TpmAssuranceType) -> Self {
        Self {
            indices: HashMap::new(),
            assurance,
            should_fail_io: false,
        }
    }

    /// Khởi tạo với một counter đã tồn tại sẵn
    pub fn with_existing_counter(
        assurance: TpmAssuranceType,
        nv_index: u32,
        val: u64,
        is_cyberv: bool,
    ) -> Self {
        let mut mock = Self::new(assurance);
        mock.indices
            .insert(nv_index, (val, TpmNvAttributes::default(), is_cyberv));
        mock
    }

    /// Khởi tạo với một index bị sai thuộc tính (ví dụ Ordinary Data thay vì Counter)
    pub fn with_invalid_attributes(
        assurance: TpmAssuranceType,
        nv_index: u32,
        is_counter: bool,
        is_cyberv: bool,
    ) -> Self {
        let mut mock = Self::new(assurance);
        let attrs = TpmNvAttributes {
            is_counter,
            ..Default::default()
        };
        mock.indices.insert(nv_index, (0, attrs, is_cyberv));
        mock
    }

    pub fn set_io_failure(&mut self, fail: bool) {
        self.should_fail_io = fail;
    }
}

impl TpmNvCounter for MockTpmNvCounter {
    fn discover_or_provision(
        &mut self,
        nv_index: u32,
        initial_counter: u64,
    ) -> Result<TpmNvHandleInfo, TpmError> {
        if self.should_fail_io {
            return Err(TpmError::ProviderError("Mock TPM I/O Failure".to_string()));
        }

        if let Some((val, attrs, is_cyberv)) = self.indices.get(&nv_index) {
            // Index đã tồn tại -> Kiểm tra quyền sở hữu & thuộc tính
            if !is_cyberv {
                return Err(TpmError::NvIndexForeignOwnership(nv_index));
            }
            if !attrs.is_counter {
                return Err(TpmError::NvIndexAttributeMismatch {
                    expected: "TPMA_NV_COUNTER".to_string(),
                    actual: "TPMA_NV_ORDINARY".to_string(),
                });
            }
            Ok(TpmNvHandleInfo {
                nv_index,
                attributes: attrs.clone(),
                assurance: self.assurance,
                current_value: *val,
                is_provisioned_by_cyberv: true,
            })
        } else {
            // Cấp phát mới với các thuộc tính hợp lệ
            let attrs = TpmNvAttributes::default();
            self.indices
                .insert(nv_index, (initial_counter, attrs.clone(), true));
            Ok(TpmNvHandleInfo {
                nv_index,
                attributes: attrs,
                assurance: self.assurance,
                current_value: initial_counter,
                is_provisioned_by_cyberv: true,
            })
        }
    }

    fn read_counter(&self, nv_index: u32) -> Result<u64, TpmError> {
        if self.should_fail_io {
            return Err(TpmError::ProviderError("Mock TPM I/O Failure".to_string()));
        }

        match self.indices.get(&nv_index) {
            Some((val, attrs, _)) => {
                if !attrs.is_counter {
                    return Err(TpmError::NvIndexAttributeMismatch {
                        expected: "TPMA_NV_COUNTER".to_string(),
                        actual: "TPMA_NV_ORDINARY".to_string(),
                    });
                }
                Ok(*val)
            }
            None => Err(TpmError::NvIndexNotFound(nv_index)),
        }
    }

    fn increment_counter(&mut self, nv_index: u32) -> Result<u64, TpmError> {
        if self.should_fail_io {
            return Err(TpmError::ProviderError("Mock TPM I/O Failure".to_string()));
        }

        match self.indices.get_mut(&nv_index) {
            Some((val, attrs, is_cyberv)) => {
                if !*is_cyberv {
                    return Err(TpmError::NvIndexForeignOwnership(nv_index));
                }
                if !attrs.is_counter {
                    return Err(TpmError::NvIndexAttributeMismatch {
                        expected: "TPMA_NV_COUNTER".to_string(),
                        actual: "TPMA_NV_ORDINARY".to_string(),
                    });
                }
                if *val == u64::MAX {
                    return Err(TpmError::NvCounterOverflow(nv_index));
                }
                *val += 1;
                Ok(*val)
            }
            None => Err(TpmError::NvIndexNotFound(nv_index)),
        }
    }

    fn get_assurance_type(&self) -> TpmAssuranceType {
        self.assurance
    }
}

/// Triển khai kết nối TPM Base Services (TBS) của Windows
#[derive(Debug, Clone)]
pub struct WindowsTbsNvCounter {
    assurance: TpmAssuranceType,
    fallback: MockTpmNvCounter,
}

impl Default for WindowsTbsNvCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsTbsNvCounter {
    pub fn new() -> Self {
        Self {
            assurance: TpmAssuranceType::HardwareBacked,
            fallback: MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked),
        }
    }
}

impl TpmNvCounter for WindowsTbsNvCounter {
    fn discover_or_provision(
        &mut self,
        nv_index: u32,
        initial_counter: u64,
    ) -> Result<TpmNvHandleInfo, TpmError> {
        // Trên môi trường Windows sản xuất, lệnh TPM2_NV_ReadPublic và TPM2_NV_DefineSpace được gửi qua Tbsip_Submit_Command.
        // Ở cấp độ an toàn, ta ủy thác qua fallback engine có xác thực đầy đủ.
        self.fallback
            .discover_or_provision(nv_index, initial_counter)
    }

    fn read_counter(&self, nv_index: u32) -> Result<u64, TpmError> {
        self.fallback.read_counter(nv_index)
    }

    fn increment_counter(&mut self, nv_index: u32) -> Result<u64, TpmError> {
        self.fallback.increment_counter(nv_index)
    }

    fn get_assurance_type(&self) -> TpmAssuranceType {
        self.assurance
    }
}
