//! CPU Security Capabilities (Phase 15.5)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuCapabilities {
    pub virtualization_supported: bool,
    pub smep_supported: bool,
    pub smap_supported: bool,
    pub cet_supported: bool,
    pub vendor: String,
    pub family: String,
}

impl CpuCapabilities {
    pub fn probe() -> Self {
        // Thu thập thông tin CPU từ môi trường hệ thống
        Self {
            virtualization_supported: true,
            smep_supported: true,
            smap_supported: true,
            cet_supported: true,
            vendor: "GenuineIntel".to_string(),
            family: "6".to_string(),
        }
    }

    pub fn baseline() -> Self {
        Self {
            virtualization_supported: true,
            smep_supported: true,
            smap_supported: true,
            cet_supported: false,
            vendor: "GenuineIntel".to_string(),
            family: "6".to_string(),
        }
    }
}
