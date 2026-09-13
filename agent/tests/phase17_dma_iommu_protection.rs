//! CyberV Phase 17: FSE-2 DMA & IOMMU Protection Tests
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS, Runtime vs Pre-boot DMA, Kernel DMA Protection, Multi-factor DMA Fusion.

use cyberv_agent::defense::dma::{
    DmaEvidenceFusionEngine, IommuReport, IommuStatus, PreBootDmaReport, ThunderboltSecurityLevel,
    DMA_DERIVATION_VERSION,
};

#[test]
fn test_01_iommu_report_active_vt_d() {
    let report = IommuReport::probe();
    assert_eq!(report.status, IommuStatus::Active);
    assert!(report.has_dmar_table);
    assert!(!report.has_ivrs_table);
    assert!(report.is_remapping_enabled);
    assert_eq!(report.vendor_name, "Intel VT-d");
}

#[test]
fn test_02_iommu_report_active_amd_vi() {
    let report = IommuReport::amd_vi();
    assert_eq!(report.status, IommuStatus::Active);
    assert!(!report.has_dmar_table);
    assert!(report.has_ivrs_table);
    assert!(report.is_remapping_enabled);
    assert_eq!(report.vendor_name, "AMD-Vi");
}

#[test]
fn test_03_iommu_disabled_status() {
    let report = IommuReport::disabled();
    assert_eq!(report.status, IommuStatus::Disabled);
    assert!(report.has_dmar_table);
    assert!(!report.is_remapping_enabled);
}

#[test]
fn test_04_iommu_unsupported_hardware() {
    let report = IommuReport::unsupported();
    assert_eq!(report.status, IommuStatus::Unsupported);
    assert!(!report.has_dmar_table);
    assert!(!report.has_ivrs_table);
}

#[test]
fn test_05_preboot_dma_protection_levels() {
    let p_protected = PreBootDmaReport::protected();
    assert!(p_protected.is_pre_boot_protected);
    assert_eq!(
        p_protected.thunderbolt_security_level,
        ThunderboltSecurityLevel::SecureConnect
    );

    let p_dp = PreBootDmaReport::display_port_only();
    assert_eq!(
        p_dp.thunderbolt_security_level,
        ThunderboltSecurityLevel::DisplayPortOnly
    );

    let p_unconstrained = PreBootDmaReport::unconstrained();
    assert!(!p_unconstrained.is_pre_boot_protected);
    assert_eq!(
        p_unconstrained.thunderbolt_security_level,
        ThunderboltSecurityLevel::NoSecurity
    );
}

#[test]
fn test_06_dma_fusion_hardened_configuration_produces_high_score() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    assert!(rep.is_fully_protected);
    assert!(
        rep.dma_security_score >= 9000,
        "Cấu hình chuẩn phải đạt điểm rất cao (>= 9000), thực tế: {}",
        rep.dma_security_score
    );
}

#[test]
fn test_07_dma_fusion_unconstrained_configuration_penalized() {
    let iommu = IommuReport::unsupported();
    let preboot = PreBootDmaReport::unconstrained();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, true);

    assert!(!rep.is_fully_protected);
    assert!(
        rep.dma_security_score < 3000,
        "Máy không có DMA protection điểm phải thấp (< 3000), thực tế: {}",
        rep.dma_security_score
    );
}

#[test]
fn test_08_runtime_dma_protection_score() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::unconstrained();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, false);

    let p_runtime = rep
        .virtual_points
        .iter()
        .find(|p| p.id == "point:dma_runtime")
        .unwrap();
    assert_eq!(p_runtime.value, 10000);
}

#[test]
fn test_09_preboot_dma_protection_score() {
    let iommu = IommuReport::unsupported();
    let preboot = PreBootDmaReport::protected();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, false);

    let p_preboot = rep
        .virtual_points
        .iter()
        .find(|p| p.id == "point:dma_preboot")
        .unwrap();
    assert_eq!(p_preboot.value, 10000);
}

#[test]
fn test_10_dma_remapping_presence_evaluation() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, false);

    let p_remap = rep
        .virtual_points
        .iter()
        .find(|p| p.id == "point:dma_remapping")
        .unwrap();
    assert_eq!(p_remap.value, 10000);
}

#[test]
fn test_11_virtual_points_generated_for_dma_metrics() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    assert_eq!(rep.virtual_points.len(), 5);
    assert!(rep
        .virtual_points
        .iter()
        .any(|p| p.id == "point:dma_runtime"));
    assert!(rep
        .virtual_points
        .iter()
        .any(|p| p.id == "point:dma_preboot"));
    assert!(rep
        .virtual_points
        .iter()
        .any(|p| p.id == "point:dma_remapping"));
    assert!(rep
        .virtual_points
        .iter()
        .any(|p| p.id == "point:dma_policy"));
    assert!(rep
        .virtual_points
        .iter()
        .any(|p| p.id == "point:dma_security"));
}

#[test]
fn test_12_policy_strict_compliance_check() {
    let iommu = IommuReport::unsupported();
    let preboot = PreBootDmaReport::unconstrained();

    let rep_strict = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, true);
    let p_strict = rep_strict
        .virtual_points
        .iter()
        .find(|p| p.id == "point:dma_policy")
        .unwrap();
    assert_eq!(p_strict.value, 4000);

    let rep_relaxed = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, false);
    let p_relaxed = rep_relaxed
        .virtual_points
        .iter()
        .find(|p| p.id == "point:dma_policy")
        .unwrap();
    assert_eq!(p_relaxed.value, 8000);
}

#[test]
fn test_13_virtual_nodes_generated_for_iommu_and_guard() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let rep = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    assert_eq!(rep.virtual_nodes.len(), 2);
    let vn_iommu = &rep.virtual_nodes[0];
    assert_eq!(vn_iommu.id, "vnode:iommu_protection");
    assert_eq!(vn_iommu.virtual_type, "IOMMU_PROTECTION");
    assert_eq!(vn_iommu.derivation_version, DMA_DERIVATION_VERSION);

    let vn_guard = &rep.virtual_nodes[1];
    assert_eq!(vn_guard.id, "vnode:kernel_dma_guard");
    assert_eq!(vn_guard.virtual_type, "KERNEL_DMA_GUARD");
}

#[test]
fn test_14_integer_weighted_fusion_determinism() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let rep1 = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);
    let rep2 = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    assert_eq!(rep1.dma_security_score, rep2.dma_security_score);
    assert_eq!(
        rep1.virtual_nodes[0].virtual_hash,
        rep2.virtual_nodes[0].virtual_hash
    );
}

#[test]
fn test_15_end_to_end_dma_security_lifecycle() {
    // 1. Máy chuẩn doanh nghiệp bảo mật
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let report = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    assert!(report.is_fully_protected);
    assert_eq!(report.dma_security_score, 10000);
    assert!(report.summary.contains("Score: 10000/10000"));
}
