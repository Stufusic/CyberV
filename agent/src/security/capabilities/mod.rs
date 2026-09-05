//! Platform Security Capabilities Aggregate (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 7:
//! "Foundation Security Capability Layer: cpu, tpm, vbs, iommu, secure_boot, kernel."

pub mod cpu;
pub mod iommu;
pub mod kernel;
pub mod secure_boot;
pub mod tpm;
pub mod vbs;

pub use cpu::CpuCapabilities;
pub use iommu::IommuCapabilities;
pub use kernel::KernelProbeCapabilities;
pub use secure_boot::SecureBootCapabilities;
pub use tpm::TpmCapabilities;
pub use vbs::VbsCapabilities;

use super::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};

/// Tập hợp năng lực bảo mật toàn diện của nền tảng phần cứng
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSecurityCapabilities {
    pub cpu: CpuCapabilities,
    pub tpm: TpmCapabilities,
    pub vbs: VbsCapabilities,
    pub iommu: IommuCapabilities,
    pub secure_boot: SecureBootCapabilities,
    pub kernel: KernelProbeCapabilities,
}

impl PlatformSecurityCapabilities {
    pub fn probe_system() -> Self {
        Self {
            cpu: CpuCapabilities::probe(),
            tpm: TpmCapabilities::probe(),
            vbs: VbsCapabilities::probe(),
            iommu: IommuCapabilities::probe(),
            secure_boot: SecureBootCapabilities::probe(),
            kernel: KernelProbeCapabilities::probe(),
        }
    }

    pub fn baseline_hardened() -> Self {
        Self {
            cpu: CpuCapabilities::baseline(),
            tpm: TpmCapabilities::probe(),
            vbs: VbsCapabilities::probe(),
            iommu: IommuCapabilities::probe(),
            secure_boot: SecureBootCapabilities::probe(),
            kernel: KernelProbeCapabilities::probe(),
        }
    }

    pub fn legacy_unprotected() -> Self {
        Self {
            cpu: CpuCapabilities::baseline(),
            tpm: TpmCapabilities::unavailable(),
            vbs: VbsCapabilities::legacy_windows(),
            iommu: IommuCapabilities::unconstrained(),
            secure_boot: SecureBootCapabilities::legacy_bios(),
            kernel: KernelProbeCapabilities::unavailable(),
        }
    }

    /// Đánh giá cấp độ đảm bảo tổng thể của thiết bị (Assurance Level)
    pub fn overall_assurance(&self) -> AssuranceLevel {
        if self.tpm.present && self.tpm.endorsement_key_available && self.vbs.enclave_supported {
            AssuranceLevel::Attested
        } else if self.tpm.present || self.iommu.kernel_dma_protection {
            AssuranceLevel::HardwareBacked
        } else if self.kernel.driver_installed || self.secure_boot.secure_boot_enabled {
            AssuranceLevel::OSProtected
        } else if self.cpu.virtualization_supported {
            AssuranceLevel::Software
        } else {
            AssuranceLevel::Unknown
        }
    }

    /// Tính điểm năng lực bảo mật nền tảng (0 - 10000, toán số nguyên)
    pub fn capability_score(&self) -> u32 {
        let mut score: u32 = 0;

        // CPU features (1500 max)
        if self.cpu.virtualization_supported {
            score += 500;
        }
        if self.cpu.smep_supported {
            score += 400;
        }
        if self.cpu.smap_supported {
            score += 300;
        }
        if self.cpu.cet_supported {
            score += 300;
        }

        // TPM 2.0 (2500 max)
        if self.tpm.present {
            score += 1000;
            if self.tpm.version_major >= 2 {
                score += 500;
            }
            if self.tpm.sha512_supported {
                score += 500;
            }
            if self.tpm.endorsement_key_available {
                score += 500;
            }
        }

        // VBS / HVCI (2000 max)
        if self.vbs.hypervisor_present {
            score += 500;
        }
        if self.vbs.vbs_enabled {
            score += 500;
        }
        if self.vbs.hvci_enabled {
            score += 500;
        }
        if self.vbs.enclave_supported {
            score += 500;
        }

        // IOMMU / DMA (1500 max)
        if self.iommu.dmar_present || self.iommu.ivrs_present {
            score += 500;
        }
        if self.iommu.kernel_dma_protection {
            score += 500;
        }
        if self.iommu.dma_remapping_active {
            score += 500;
        }

        // Secure Boot (1500 max)
        if self.secure_boot.uefi_mode {
            score += 500;
        }
        if self.secure_boot.secure_boot_enabled {
            score += 500;
        }
        if self.secure_boot.dbx_count > 0 {
            score += 500;
        }

        // Kernel Driver (1000 max)
        if self.kernel.driver_installed {
            score += 500;
        }
        if self.kernel.ob_callbacks_active {
            score += 500;
        }

        score.min(10000)
    }
}
