//! DMA Evidence Fusion Engine (FSE-2)
//!
//! Ref: Docs/rv11.md Section 3:
//! Firmware Evidence (DMAR/IVRS) + IOMMU capability + Windows Kernel DMA Protection
//! + DMA remapping state + device policy -> DMA Evidence Fusion -> vnode:iommu_protection.
//!
//! Points: point:dma_runtime, point:dma_preboot, point:dma_remapping, point:dma_policy
//! -> point:dma_security = weighted integer fusion.

use super::iommu::{IommuReport, IommuStatus};
use super::preboot::PreBootDmaReport;
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DMA_DERIVATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmaSecurityReport {
    pub dma_security_score: u32, // 0 - 10000
    pub is_fully_protected: bool,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub summary: String,
}

pub struct DmaEvidenceFusionEngine;

impl DmaEvidenceFusionEngine {
    /// Hợp nhất đa nhân tố bằng chứng DMA thành điểm số bảo mật thống nhất
    pub fn evaluate(
        iommu: &IommuReport,
        preboot: &PreBootDmaReport,
        kernel_dma_protection: bool,
        policy_strict: bool,
    ) -> DmaSecurityReport {
        // 1. Tính toán điểm Runtime DMA Protection (0 - 10000)
        let runtime_score: u32 = if kernel_dma_protection && iommu.status == IommuStatus::Active {
            10000
        } else if kernel_dma_protection || iommu.status == IommuStatus::Active {
            6000
        } else {
            1500
        };

        // 2. Tính toán điểm Pre-Boot DMA Protection (0 - 10000)
        let preboot_score: u32 = if preboot.is_pre_boot_protected && preboot.bme_dma_mitigation {
            10000
        } else if preboot.is_pre_boot_protected {
            6000
        } else {
            2000
        };

        // 3. Tính toán điểm Remapping Table (0 - 10000)
        let remapping_score: u32 =
            if iommu.is_remapping_enabled && (iommu.has_dmar_table || iommu.has_ivrs_table) {
                10000
            } else if iommu.has_dmar_table || iommu.has_ivrs_table {
                5000
            } else {
                1000
            };

        // 4. Tính toán điểm Policy Compliance (0 - 10000)
        let policy_score: u32 = if policy_strict {
            if runtime_score >= 8000 && preboot_score >= 6000 {
                10000
            } else {
                4000
            }
        } else {
            8000
        };

        // 5. Tổng hợp trọng số số nguyên (Weighted Integer Fusion)
        // runtime: 30%, preboot: 25%, remapping: 25%, policy: 20%
        let weighted_sum = (runtime_score as u64 * 3000)
            + (preboot_score as u64 * 2500)
            + (remapping_score as u64 * 2500)
            + (policy_score as u64 * 2000);
        let composite_score = (weighted_sum / 10000) as u32;

        let is_fully_protected = composite_score >= 8500;

        // 6. Xây dựng Virtual Points
        let p_runtime = VirtualPoint::new(
            "point:dma_runtime",
            runtime_score as i64,
            10000,
            DMA_DERIVATION_VERSION,
        );
        let p_preboot = VirtualPoint::new(
            "point:dma_preboot",
            preboot_score as i64,
            10000,
            DMA_DERIVATION_VERSION,
        );
        let p_remapping = VirtualPoint::new(
            "point:dma_remapping",
            remapping_score as i64,
            10000,
            DMA_DERIVATION_VERSION,
        );
        let p_policy = VirtualPoint::new(
            "point:dma_policy",
            policy_score as i64,
            10000,
            DMA_DERIVATION_VERSION,
        );
        let p_security = VirtualPoint::new(
            "point:dma_security",
            composite_score as i64,
            10000,
            DMA_DERIVATION_VERSION,
        );

        // 7. Xây dựng Virtual Nodes
        let mut iommu_attrs = BTreeMap::new();
        iommu_attrs.insert("iommu_vendor".to_string(), iommu.vendor_name.clone());
        iommu_attrs.insert(
            "remapping_active".to_string(),
            iommu.is_remapping_enabled.to_string(),
        );
        iommu_attrs.insert("composite_score".to_string(), composite_score.to_string());

        let vn_iommu = VirtualNode {
            id: "vnode:iommu_protection".to_string(),
            virtual_type: "IOMMU_PROTECTION".to_string(),
            derivation_version: DMA_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("iommu_vhash_{:04}", composite_score),
            attributes: iommu_attrs,
        };

        let mut guard_attrs = BTreeMap::new();
        guard_attrs.insert(
            "kernel_dma_protection".to_string(),
            kernel_dma_protection.to_string(),
        );
        guard_attrs.insert(
            "pre_boot_protected".to_string(),
            preboot.is_pre_boot_protected.to_string(),
        );

        let vn_guard = VirtualNode {
            id: "vnode:kernel_dma_guard".to_string(),
            virtual_type: "KERNEL_DMA_GUARD".to_string(),
            derivation_version: DMA_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("dma_guard_vhash_{:04}", composite_score),
            attributes: guard_attrs,
        };

        let summary = format!(
            "DMA Protection Score: {}/10000 (Runtime: {}, PreBoot: {}, Remap: {})",
            composite_score, runtime_score, preboot_score, remapping_score
        );

        DmaSecurityReport {
            dma_security_score: composite_score,
            is_fully_protected,
            virtual_nodes: vec![vn_iommu, vn_guard],
            virtual_points: vec![p_runtime, p_preboot, p_remapping, p_policy, p_security],
            summary,
        }
    }
}
