//! VBS Enclave Capability Matrix (FSE-4)
//!
//! Ref: Docs/rv11.md Section 5:
//! Capability Matrix:
//! - VBS/HVCI Unsupported -> Software fallback, degraded assurance.
//! - VBS Supported but Enclave not loaded -> OSProtected assurance.
//! - VBS Enclave Active & Attested -> Attested assurance.
//!
//! Realistic expectations: do not use terms like '100% immune' or 'zero memory scraping'.

use crate::security::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveStatus {
    /// VBS hoặc Hyper-V không được hỗ trợ hoặc bị tắt trong BIOS
    Unsupported,
    /// VBS/HVCI được hỗ trợ và đang chạy, nhưng Enclave chưa được khởi chạy
    SupportedNotLoaded,
    /// Enclave đang chạy trong VTL1 và đã được chứng thực mã hóa
    ActiveAttested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveCapabilityMatrix {
    pub status: EnclaveStatus,
    pub vtl_level: u8, // 0 = Normal World (VTL0), 1 = Secure World (VTL1)
    pub hvci_active: bool,
    pub secure_kernel_present: bool,
}

impl EnclaveCapabilityMatrix {
    pub fn active_attested_vtl1() -> Self {
        Self {
            status: EnclaveStatus::ActiveAttested,
            vtl_level: 1,
            hvci_active: true,
            secure_kernel_present: true,
        }
    }

    pub fn supported_not_loaded() -> Self {
        Self {
            status: EnclaveStatus::SupportedNotLoaded,
            vtl_level: 0,
            hvci_active: true,
            secure_kernel_present: true,
        }
    }

    pub fn unsupported_software_fallback() -> Self {
        Self {
            status: EnclaveStatus::Unsupported,
            vtl_level: 0,
            hvci_active: false,
            secure_kernel_present: false,
        }
    }

    /// Cấp độ đảm bảo an ninh (AssuranceLevel)
    pub fn assurance_level(&self) -> AssuranceLevel {
        match self.status {
            EnclaveStatus::ActiveAttested => AssuranceLevel::Attested,
            EnclaveStatus::SupportedNotLoaded => AssuranceLevel::OSProtected,
            EnclaveStatus::Unsupported => AssuranceLevel::Software,
        }
    }

    /// Điểm số bảo mật số nguyên (0 - 10000)
    pub fn security_score(&self) -> u32 {
        match self.status {
            EnclaveStatus::ActiveAttested => {
                let mut score = 9000;
                if self.vtl_level == 1 {
                    score += 500;
                }
                if self.hvci_active {
                    score += 500;
                }
                score.min(10000)
            }
            EnclaveStatus::SupportedNotLoaded => {
                let mut score = 5000;
                if self.hvci_active {
                    score += 1000;
                }
                score
            }
            EnclaveStatus::Unsupported => 2000,
        }
    }
}
