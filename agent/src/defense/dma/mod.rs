//! DMA & IOMMU Protection (FSE-2)
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS, Runtime vs Pre-boot DMA, Kernel DMA Protection, Multi-factor DMA Fusion.

pub mod fusion;
pub mod iommu;
pub mod preboot;

pub use fusion::{DmaEvidenceFusionEngine, DmaSecurityReport, DMA_DERIVATION_VERSION};
pub use iommu::{IommuReport, IommuStatus};
pub use preboot::{PreBootDmaReport, ThunderboltSecurityLevel};
