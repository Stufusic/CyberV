//! Phase 20: Evidence Fusion & Policy Engine Integration Tests
//!
//! Ref: Docs/rv11.md Section 6, 7, 8:
//! Validates:
//! - Weighted Integer Multi-Domain Fusion (TPM, Kernel, DMA, Firmware, VBS)
//! - Policy Decisions: ALLOW, STEP-UP, ISOLATE
//! - Freshness & Half-life decay impact on decisions
//! - Minimum Assurance Level compliance

use cyberv_agent::defense::dma::fusion::DmaEvidenceFusionEngine;
use cyberv_agent::defense::dma::{IommuReport, PreBootDmaReport};
use cyberv_agent::defense::enclave::{
    EnclaveAttestationEngine, EnclaveCapabilityMatrix, EnclaveMeasurement, IdentityBindingEngine,
};
use cyberv_agent::defense::firmware::boot_guard::BootGuardReport;
use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::firmware::fusion::FirmwareEvidenceFusionEngine;
use cyberv_agent::defense::firmware::secure_boot::SecureBootDbReport;
use cyberv_agent::defense::firmware::smm::SmmSecurityReport;
use cyberv_agent::defense::kernel::{
    AntiTamperManager, AntiTamperReport, ProtectedProcessRegistration, ShieldTelemetry,
};
use cyberv_agent::defense::policy::{PolicyConfig, PolicyDecision, SecurityPolicyEngine};
use cyberv_agent::evidence::unified::EvidenceSource;
use cyberv_agent::security::assurance::AssuranceLevel;
use cyberv_agent::security::freshness::EvidenceMetadata;

fn helper_hardened_reports() -> (
    u32,
    AntiTamperReport,
    cyberv_agent::defense::dma::DmaSecurityReport,
    cyberv_agent::defense::firmware::FirmwareSecurityReport,
    cyberv_agent::defense::enclave::EnclaveAttestationReport,
) {
    let tpm_score = 10000;

    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let telem = ShieldTelemetry::active(1234);
    let kernel_report = AntiTamperManager::evaluate(&reg, &telem, true);

    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let dma_report = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    let sb = SecureBootDbReport::standard_hardened();
    let bg = BootGuardReport::intel_boot_guard_profile5();
    let smm = SmmSecurityReport::hardened();
    let cfg = FirmwareConfigReport::standard_asus();
    let fw_report = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);

    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    let meas = EnclaveMeasurement {
        author_id: "CyberV-Authority".to_string(),
        image_id: "CyberVEnclave.dll".to_string(),
        svn: 1,
        measurement_hash_sha512: "sha512_digest".to_string(),
    };
    let binding =
        IdentityBindingEngine::create_binding(b"TPM_AK", b"PCR", b"ENCLAVE_PUB", &[0u8; 32]);
    let enclave_report = EnclaveAttestationEngine::evaluate(&cap, Some(&meas), Some(&binding));

    (
        tpm_score,
        kernel_report,
        dma_report,
        fw_report,
        enclave_report,
    )
}

#[test]
fn test_01_policy_engine_allow_optimal_conditions() {
    let (tpm_score, kernel, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();
    let now = 1000000;
    let meta = EvidenceMetadata::new(
        now,
        Some(86400),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm_score,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        now,
    );
    assert_eq!(report.decision, PolicyDecision::Allow);
    assert!(report.composite_score >= 8000);
    assert_eq!(report.achieved_assurance, AssuranceLevel::Attested);
}

#[test]
fn test_02_policy_engine_isolate_on_kernel_tamper() {
    let (tpm_score, _, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();

    // Driver disconnected AND blocked termination attempts
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let mut telem = ShieldTelemetry::inactive();
    telem.blocked_terminations = 3;
    let tampered_kernel = AntiTamperManager::evaluate(&reg, &telem, false);

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm_score,
        &tampered_kernel,
        &dma,
        &fw,
        &enclave,
        None,
        1000,
    );
    match report.decision {
        PolicyDecision::Isolate { reason, severity } => {
            assert_eq!(reason, "Kernel Defense Tampered");
            assert_eq!(severity, 9500);
        }
        _ => panic!("Expected Isolate decision on kernel tamper"),
    }
}

#[test]
fn test_03_policy_engine_step_up_on_low_assurance() {
    let (tpm_score, kernel, dma, fw, _) = helper_hardened_reports();
    let config = PolicyConfig {
        minimum_assurance: AssuranceLevel::HardwareBacked,
        ..Default::default()
    };

    // Enclave is supported but not loaded (achieved: OSProtected)
    let cap = EnclaveCapabilityMatrix::supported_not_loaded();
    let enclave = EnclaveAttestationEngine::evaluate(&cap, None, None);

    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );
    match report.decision {
        PolicyDecision::StepUp {
            reason,
            required_assurance,
        } => {
            assert_eq!(reason, "Assurance Level Insufficient");
            assert_eq!(required_assurance, AssuranceLevel::HardwareBacked);
        }
        _ => panic!("Expected StepUp for low assurance level"),
    }
}

#[test]
fn test_04_policy_engine_step_up_on_freshness_decay() {
    let (tpm_score, kernel, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();
    let observed_at = 1000;
    // Exactly 1 half-life later (86400s) -> confidence drops to 5000 (50%)
    let now = observed_at + config.half_life_secs;
    let meta = EvidenceMetadata::new(
        observed_at,
        Some(300000),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm_score,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        now,
    );
    match report.decision {
        PolicyDecision::StepUp { reason, .. } => {
            assert!(reason.contains("Freshness") || reason.contains("Below Allow Threshold"));
        }
        _ => panic!(
            "Expected StepUp when freshness decays, got {:?}",
            report.decision
        ),
    }
}

#[test]
fn test_05_policy_engine_step_up_on_intermediate_score() {
    let config = PolicyConfig::default();

    // Intermediate composite score: 6200 (between 5000 and 8000)
    let tpm_score = 4000; // 25% -> 1000

    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let mut tele = ShieldTelemetry::active(1234);
    tele.blocked_terminations = 2; // Lowers defense score
    let kernel = AntiTamperManager::evaluate(&reg, &tele, true);

    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::display_port_only();
    let dma = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, false);

    let sb = SecureBootDbReport::standard_hardened();
    let bg = BootGuardReport::intel_boot_guard_profile5();
    let smm = SmmSecurityReport::hardened();
    let cfg = FirmwareConfigReport::unverified_vendor();
    let fw = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);

    let cap = EnclaveCapabilityMatrix::supported_not_loaded();
    let enclave = EnclaveAttestationEngine::evaluate(&cap, None, None);

    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );
    match report.decision {
        PolicyDecision::StepUp { reason, .. } => {
            assert!(reason.contains("Below Allow Threshold") || reason.contains("Insufficient"));
        }
        _ => panic!(
            "Expected StepUp for intermediate score, got {:?}",
            report.decision
        ),
    }
}

#[test]
fn test_06_policy_engine_isolate_on_critical_low_score() {
    let config = PolicyConfig::default();
    let tpm_score = 1000;

    let reg = ProtectedProcessRegistration::new(0, 0, "nonce0", 0);
    let telem = ShieldTelemetry::inactive();
    let kernel = AntiTamperManager::evaluate(&reg, &telem, false);

    let iommu = IommuReport::unsupported();
    let preboot = PreBootDmaReport::unconstrained();
    let dma = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, false);

    let sb = SecureBootDbReport::unconfigured();
    let bg = BootGuardReport::unconfigured();
    let smm = SmmSecurityReport::unconstrained();
    let cfg = FirmwareConfigReport::unverified_vendor();
    let fw = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);

    let cap = EnclaveCapabilityMatrix::unsupported_software_fallback();
    let enclave = EnclaveAttestationEngine::evaluate(&cap, None, None);

    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );
    match report.decision {
        PolicyDecision::Isolate { reason, severity } => {
            assert_eq!(reason, "Composite Security Score Critically Degraded");
            assert!(severity > 5000);
        }
        _ => panic!("Expected Isolate for critically low composite score"),
    }
}

#[test]
fn test_07_weighted_integer_fusion_proportions() {
    let (tpm_score, kernel, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();
    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );

    // All are 10000, so composite must be exactly 10000
    assert_eq!(report.composite_score, 10000);
}

#[test]
fn test_08_evidence_source_fse_variants() {
    let s1 = EvidenceSource::KernelTamperResistance;
    let s2 = EvidenceSource::DmaIommuProtection;
    let s3 = EvidenceSource::FirmwarePlatformIntegrity;
    let s4 = EvidenceSource::VbsEnclaveCore;

    assert_ne!(s1, s2);
    assert_ne!(s3, s4);
}

#[test]
fn test_09_evidence_metadata_effective_confidence_integer_math() {
    let meta = EvidenceMetadata::new(
        1000,
        None,
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );
    // Exact half-life (elapsed = half_life): penalty = 10000, divisor = 20000 -> effective = 5000
    let conf = meta.effective_confidence(1000 + 86400, 86400);
    assert_eq!(conf, 5000);
}

#[test]
fn test_10_evidence_metadata_expired_confidence_zero() {
    let meta = EvidenceMetadata::new(
        1000,
        Some(3600),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );
    // After expiration (now = 1000 + 3601)
    let conf = meta.effective_confidence(1000 + 3601, 86400);
    assert_eq!(conf, 0);
}

#[test]
fn test_11_policy_config_custom_thresholds() {
    let (tpm_score, kernel, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig {
        allow_threshold: 10001,
        ..Default::default()
    };

    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );
    match report.decision {
        PolicyDecision::StepUp { reason, .. } => {
            assert_eq!(reason, "Security Score Below Allow Threshold");
        }
        _ => panic!("Expected StepUp when below strict custom threshold"),
    }
}

#[test]
fn test_12_policy_rationales_tracking() {
    let (tpm_score, kernel, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();
    let report = SecurityPolicyEngine::evaluate(
        &config, tpm_score, &kernel, &dma, &fw, &enclave, None, 1000,
    );
    assert!(!report.rationales.is_empty());
    assert!(report.rationales[0].contains("đạt chuẩn"));
}

#[test]
fn test_13_policy_decision_allow_serialization() {
    let decision = PolicyDecision::Allow;
    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: PolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, deserialized);
}

#[test]
fn test_14_policy_decision_step_up_serialization() {
    let decision = PolicyDecision::StepUp {
        reason: "Need ZKP Proof".to_string(),
        required_assurance: AssuranceLevel::Attested,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: PolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, deserialized);
}

#[test]
fn test_15_policy_decision_isolate_serialization() {
    let decision = PolicyDecision::Isolate {
        reason: "DMA Interposition".to_string(),
        severity: 9000,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: PolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, deserialized);
}
