//! Pre-Boot DMA Protection Verification (FSE-2)
//!
//! Ref: Docs/rv11.md Section 3:
//! "Microsoft phân biệt bảo vệ DMA lúc runtime với bảo vệ trong quá trình boot.
//! Kernel DMA Protection không tự giải quyết toàn bộ pre-boot DMA threat."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThunderboltSecurityLevel {
    /// SL0: No security (DMA mở hoàn toàn trước khi boot)
    NoSecurity = 0,
    /// SL1: User Authorization (Yêu cầu phê duyệt thiết bị)
    UserAuth = 1,
    /// SL2: Secure Connect (Xác thực bằng khóa bí mật)
    SecureConnect = 2,
    /// SL3: DisplayPort only (Chặn hoàn toàn DMA qua Thunderbolt)
    DisplayPortOnly = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreBootDmaReport {
    pub is_pre_boot_protected: bool,
    pub thunderbolt_security_level: ThunderboltSecurityLevel,
    pub bme_dma_mitigation: bool, // Bus Master Enable mitigation
}

impl PreBootDmaReport {
    pub fn protected() -> Self {
        Self {
            is_pre_boot_protected: true,
            thunderbolt_security_level: ThunderboltSecurityLevel::SecureConnect,
            bme_dma_mitigation: true,
        }
    }

    pub fn display_port_only() -> Self {
        Self {
            is_pre_boot_protected: true,
            thunderbolt_security_level: ThunderboltSecurityLevel::DisplayPortOnly,
            bme_dma_mitigation: true,
        }
    }

    pub fn unconstrained() -> Self {
        Self {
            is_pre_boot_protected: false,
            thunderbolt_security_level: ThunderboltSecurityLevel::NoSecurity,
            bme_dma_mitigation: false,
        }
    }
}
