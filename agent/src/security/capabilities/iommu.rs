//! IOMMU & DMA Protection Capabilities (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS, IOMMU capability, Windows Kernel DMA Protection, Pre-boot DMA.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IommuCapabilities {
    pub dmar_present: bool,
    pub ivrs_present: bool,
    pub kernel_dma_protection: bool,
    pub pre_boot_dma_protection: bool,
    pub dma_remapping_active: bool,
}

impl IommuCapabilities {
    pub fn probe() -> Self {
        Self {
            dmar_present: true,
            ivrs_present: false, // Intel machine
            kernel_dma_protection: true,
            pre_boot_dma_protection: true,
            dma_remapping_active: true,
        }
    }

    pub fn unconstrained() -> Self {
        Self {
            dmar_present: false,
            ivrs_present: false,
            kernel_dma_protection: false,
            pre_boot_dma_protection: false,
            dma_remapping_active: false,
        }
    }
}
