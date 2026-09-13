//! CyberV Phase 15.5: Foundational Capabilities, Assurance & Freshness Tests
//!
//! Ref: Docs/rv11.md Section 7 & 8:
//! Capabilities, Assurance Level, Evidence Freshness & Half-life Decay.

use cyberv_agent::evidence::unified::EvidenceSource;
use cyberv_agent::security::{AssuranceLevel, EvidenceMetadata, PlatformSecurityCapabilities};

#[test]
fn test_01_assurance_level_ordering_and_scores() {
    assert!(AssuranceLevel::Unknown < AssuranceLevel::Software);
    assert!(AssuranceLevel::Software < AssuranceLevel::OSProtected);
    assert!(AssuranceLevel::OSProtected < AssuranceLevel::HardwareBacked);
    assert!(AssuranceLevel::HardwareBacked < AssuranceLevel::Attested);

    assert_eq!(AssuranceLevel::Unknown.score(), 0);
    assert_eq!(AssuranceLevel::Software.score(), 2500);
    assert_eq!(AssuranceLevel::OSProtected.score(), 5000);
    assert_eq!(AssuranceLevel::HardwareBacked.score(), 8000);
    assert_eq!(AssuranceLevel::Attested.score(), 10000);
}

#[test]
fn test_02_evidence_metadata_creation_and_freshness() {
    let now = 1757077200;
    let meta = EvidenceMetadata::new(
        now,
        Some(3600), // 1 hour TTL
        EvidenceSource::TpmRootOfTrust,
        9500,
        AssuranceLevel::Attested,
        1,
    );

    assert!(meta.is_fresh(now));
    assert!(meta.is_fresh(now + 1800)); // 30 mins later: fresh
    assert!(meta.is_fresh(now + 3600)); // exactly 1 hour: fresh
    assert!(!meta.is_fresh(now + 3601)); // 1 hour 1 sec later: expired
}

#[test]
fn test_03_expired_evidence_evaluates_to_zero_confidence() {
    let now = 1757077200;
    let meta = EvidenceMetadata::new(
        now,
        Some(300), // 5 min TTL
        EvidenceSource::KernelObservation,
        10000,
        AssuranceLevel::OSProtected,
        1,
    );

    // Khi quá hạn, độ tin cậy tụt về 0 (UNKNOWN)
    let effective = meta.effective_confidence(now + 301, 60);
    assert_eq!(effective, 0, "Bằng chứng quá hạn phải có độ tin cậy = 0");
}

#[test]
fn test_04_integer_confidence_decay_half_life() {
    let now = 1757077200;
    let half_life = 3600; // 1 giờ
    let meta = EvidenceMetadata::new(
        now,
        Some(86400), // TTL 1 ngày
        EvidenceSource::TemporalDrift,
        10000,
        AssuranceLevel::HardwareBacked,
        1,
    );

    // Tại thời điểm thu thập: 10000
    assert_eq!(meta.effective_confidence(now, half_life), 10000);

    // Sau 1 chu kỳ bán rã (1 giờ = 3600s): giảm 50% -> 5000
    let conf_1h = meta.effective_confidence(now + 3600, half_life);
    assert_eq!(conf_1h, 5000);

    // Sau 2 chu kỳ bán rã (2 giờ = 7200s): giảm còn ~3333 theo công thức 10000 / (1 + 2)
    let conf_2h = meta.effective_confidence(now + 7200, half_life);
    assert_eq!(conf_2h, 3333);
}

#[test]
fn test_05_permanent_evidence_never_expires() {
    let now = 1757077200;
    let meta = EvidenceMetadata::new(
        now,
        None, // Vĩnh viễn (ví dụ: số serial vật lý không thay đổi)
        EvidenceSource::PhysicalConstraints,
        9000,
        AssuranceLevel::Software,
        1,
    );

    assert!(meta.is_fresh(now + 999_999_999));
}

#[test]
fn test_06_cpu_capabilities_probing() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.cpu.virtualization_supported);
    assert!(caps.cpu.smep_supported);
    assert!(caps.cpu.smap_supported);
    assert_eq!(caps.cpu.vendor, "GenuineIntel");
}

#[test]
fn test_07_tpm_capabilities_detection() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.tpm.present);
    assert_eq!(caps.tpm.version_major, 2);
    assert!(caps.tpm.sha512_supported);
    assert!(caps.tpm.endorsement_key_available);
}

#[test]
fn test_08_vbs_capabilities_evaluation() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.vbs.hypervisor_present);
    assert!(caps.vbs.vbs_enabled);
    assert!(caps.vbs.hvci_enabled);
    assert!(caps.vbs.enclave_supported);
    assert!(caps.vbs.build_number >= 26100);
}

#[test]
fn test_09_iommu_capabilities_remapping_check() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.iommu.dmar_present);
    assert!(caps.iommu.kernel_dma_protection);
    assert!(caps.iommu.pre_boot_dma_protection);
    assert!(caps.iommu.dma_remapping_active);
}

#[test]
fn test_10_secure_boot_capabilities_uefi_verification() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.secure_boot.uefi_mode);
    assert!(caps.secure_boot.secure_boot_enabled);
    assert!(caps.secure_boot.pk_enrolled);
    assert!(
        caps.secure_boot.dbx_count > 0,
        "Phải có danh sách thu hồi dbx"
    );
}

#[test]
fn test_11_kernel_probe_capabilities_driver_check() {
    let caps = PlatformSecurityCapabilities::probe_system();
    assert!(caps.kernel.driver_installed);
    assert_eq!(caps.kernel.driver_version, 1);
    assert!(caps.kernel.ioctl_responsive);
    assert!(caps.kernel.ob_callbacks_active);
}

#[test]
fn test_12_platform_security_capabilities_hardened_baseline() {
    let caps = PlatformSecurityCapabilities::baseline_hardened();
    let score = caps.capability_score();
    assert!(
        score >= 8000,
        "Hardened baseline phải đạt điểm cao (>= 8000), thực tế: {}",
        score
    );
    assert_eq!(caps.overall_assurance(), AssuranceLevel::Attested);
}

#[test]
fn test_13_platform_security_capabilities_legacy_unprotected() {
    let caps = PlatformSecurityCapabilities::legacy_unprotected();
    let score = caps.capability_score();
    assert!(
        score < 3000,
        "Máy cũ không bảo vệ điểm phải thấp (< 3000), thực tế: {}",
        score
    );
    assert_eq!(caps.overall_assurance(), AssuranceLevel::Software);
}

#[test]
fn test_14_assurance_level_derivation_from_capabilities() {
    let mut caps = PlatformSecurityCapabilities::baseline_hardened();
    assert_eq!(caps.overall_assurance(), AssuranceLevel::Attested);

    // Tắt enclave
    caps.vbs.enclave_supported = false;
    assert_eq!(caps.overall_assurance(), AssuranceLevel::HardwareBacked);

    // Tắt TPM & IOMMU
    caps.tpm.present = false;
    caps.iommu.kernel_dma_protection = false;
    assert_eq!(caps.overall_assurance(), AssuranceLevel::OSProtected);

    // Tắt driver & secure boot
    caps.kernel.driver_installed = false;
    caps.secure_boot.secure_boot_enabled = false;
    assert_eq!(caps.overall_assurance(), AssuranceLevel::Software);
}

#[test]
fn test_15_integer_capability_scoring_matrix() {
    let caps = PlatformSecurityCapabilities::probe_system();
    let score = caps.capability_score();
    assert!(score <= 10000);
    assert!(score > 0);
}
