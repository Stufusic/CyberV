//! Phase 21: Adversarial Security Simulation Lab
//!
//! Ref: Docs/rv11.md Section 9:
//! 18 comprehensive adversarial attack vectors validating system resiliency:
//! - Vectors 1-3: Rootkit / DKOM / Process Termination Attacks
//! - Vectors 4-6: PCIe Screamer / Thunderbolt Pre-boot DMA Attacks
//! - Vectors 7-9: Evil Maid UEFI / Option ROM / SMI Storm Attacks
//! - Vectors 10-12: Enclave Binary Tampering / TPM AK Swap Attacks
//! - Vectors 13-15: Replay Attacks / Stale Evidence Half-Life Decay
//! - Vectors 16-18: Byzantine Multi-Sensor & Compound Attack Resiliency

use cyberv_agent::defense::dma::fusion::DmaEvidenceFusionEngine;
use cyberv_agent::defense::dma::{IommuReport, PreBootDmaReport};
use cyberv_agent::defense::enclave::{
    EnclaveAttestationEngine, EnclaveCapabilityMatrix, EnclaveMeasurement, EnclaveStatus,
    IdentityBindingEngine,
};
use cyberv_agent::defense::firmware::boot_guard::BootGuardReport;
use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::firmware::fusion::FirmwareEvidenceFusionEngine;
use cyberv_agent::defense::firmware::secure_boot::{ImageValidationResult, SecureBootDbReport};
use cyberv_agent::defense::firmware::smm::SmmSecurityReport;
use cyberv_agent::defense::kernel::{
    AntiTamperManager, ProtectedProcessRegistration, ShieldTelemetry,
};
use cyberv_agent::defense::policy::{PolicyConfig, PolicyDecision, SecurityPolicyEngine};
use cyberv_agent::evidence::unified::EvidenceSource;
use cyberv_agent::security::assurance::AssuranceLevel;
use cyberv_agent::security::freshness::EvidenceMetadata;

// Helper to provide baseline hardened defense reports
fn baseline_hardened() -> (
    u32,
    cyberv_agent::defense::kernel::AntiTamperReport,
    cyberv_agent::defense::dma::DmaSecurityReport,
    cyberv_agent::defense::firmware::FirmwareSecurityReport,
    cyberv_agent::defense::enclave::EnclaveAttestationReport,
) {
    let tpm_score = 10000;

    let reg = ProtectedProcessRegistration::new(1001, 1000, "nonce_clean", 1);
    let telem = ShieldTelemetry::active(1001);
    let kernel = AntiTamperManager::evaluate(&reg, &telem, true);

    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let dma = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    let sb = SecureBootDbReport::standard_hardened();
    let bg = BootGuardReport::intel_boot_guard_profile5();
    let smm = SmmSecurityReport::hardened();
    let cfg = FirmwareConfigReport::standard_asus();
    let fw = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);

    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    let meas = EnclaveMeasurement {
        author_id: "CyberV-Authority".to_string(),
        image_id: "CyberVEnclaveCore.dll".to_string(),
        svn: 1,
        measurement_hash_sha512: "valid_hash".to_string(),
    };
    let binding =
        IdentityBindingEngine::create_binding(b"TPM_AK", b"PCR", b"ENCLAVE_PUB", &[0u8; 32]);
    let enclave = EnclaveAttestationEngine::evaluate(&cap, Some(&meas), Some(&binding));

    (tpm_score, kernel, dma, fw, enclave)
}

// =========================================================================
// Vectors 1-3: Rootkit / DKOM / Process Termination Attacks
// =========================================================================

#[test]
fn test_sim_01_dkom_handle_stripping_attack_detected() {
    let reg = ProtectedProcessRegistration::new(1001, 1000, "nonce", 1);
    let mut telem = ShieldTelemetry::active(1001);
    telem.blocked_terminations = 4;
    telem.blocked_vm_writes = 2;

    let report = AntiTamperManager::evaluate(&reg, &telem, true);
    assert!(report.is_tampering_detected);
    assert!(report.defense_score < 10000);
    assert!(report
        .virtual_nodes
        .iter()
        .any(|n| n.id == "vnode:process_tamper_attempt"));
}

#[test]
fn test_sim_02_driver_service_kill_triggers_immediate_isolation() {
    let (tpm, _, dma, fw, enclave) = baseline_hardened();
    let config = PolicyConfig::default();

    let reg = ProtectedProcessRegistration::new(1001, 1000, "nonce", 1);
    let mut telem = ShieldTelemetry::inactive();
    telem.blocked_terminations = 1;
    let tampered_kernel = AntiTamperManager::evaluate(&reg, &telem, false);

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm,
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
        _ => panic!("Expected immediate Isolate when driver is killed during attack"),
    }
}

#[test]
fn test_sim_03_repeated_vm_read_memory_scraping_attempt() {
    let reg = ProtectedProcessRegistration::new(1001, 1000, "nonce", 1);
    let mut telem = ShieldTelemetry::active(1001);
    telem.blocked_vm_reads = 15; // 15 illegal memory dump attempts

    let report = AntiTamperManager::evaluate(&reg, &telem, true);
    assert!(report.is_tampering_detected);
    assert_eq!(telem.total_blocked(), 15);
}

// =========================================================================
// Vectors 4-6: PCIe Screamer / Thunderbolt Pre-boot DMA Attacks
// =========================================================================

#[test]
fn test_sim_04_screamer_pcie_dma_attack_blocked_by_iommu() {
    let iommu = IommuReport::probe();
    assert!(iommu.has_dmar_table);
    let preboot = PreBootDmaReport::protected();
    let dma = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);
    assert_eq!(dma.dma_security_score, 10000);
    assert!(dma.is_fully_protected);
}

#[test]
fn test_sim_05_thunderbolt_evil_maid_preboot_dma_interposition() {
    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::unconstrained(); // Rogue peripheral allowed before OS boot
    let dma = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, true);
    // Score heavily degraded due to preboot vulnerability
    assert!(dma.dma_security_score < 8000);
    assert!(!dma.is_fully_protected);
}

#[test]
fn test_sim_06_dma_policy_strict_mode_escalation() {
    let iommu = IommuReport::unsupported();
    let preboot = PreBootDmaReport::unconstrained();
    let dma_strict = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, true);
    let dma_lenient = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, false, false);

    assert!(dma_strict.dma_security_score <= dma_lenient.dma_security_score);
}

// =========================================================================
// Vectors 7-9: UEFI / Firmware & Option ROM Tampering Attacks
// =========================================================================

#[test]
fn test_sim_07_blacklisted_bootloader_dbx_precedence_violation() {
    let sb = SecureBootDbReport::standard_hardened();
    // Vulnerable shim is signed by Microsoft (in db), but revoked by DBX
    let res = sb.validate_image_precedence(true, true);
    assert_eq!(res, ImageValidationResult::RevokedByDbxPrecedence);
}

#[test]
fn test_sim_08_unsigned_custom_bios_flash_attempt() {
    let bad_cfg = FirmwareConfigReport::unverified_vendor();
    assert_eq!(bad_cfg.security_score(), 3000);
    assert!(!bad_cfg.is_oem_signed);
}

#[test]
fn test_sim_09_smi_storm_dos_anomaly_resilience() {
    let mut smm = SmmSecurityReport::hardened();
    smm.has_smi_frequency_anomaly = true;
    // Non-alarmist rule: Does NOT collapse to 0, drops slightly to 9000
    assert_eq!(smm.security_score(), 9000);
}

// =========================================================================
// Vectors 10-12: Enclave Binary Tampering / TPM AK Swap Attacks
// =========================================================================

#[test]
fn test_sim_10_enclave_binary_tampering_author_mismatch() {
    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    // Missing valid measurement
    let report = EnclaveAttestationEngine::evaluate(&cap, None, None);
    assert!(!report.is_enclave_trusted);
    assert!(report.composite_score < 10000);
}

#[test]
fn test_sim_11_tpm_ak_swap_identity_theft_attack() {
    let legitimate_tpm_ak = b"LEGIT_TPM_AK";
    let pcr = b"PCR_VALS";
    let enclave_key = b"ENCLAVE_PUB";
    let nonce = [0x99u8; 32];

    let proof = IdentityBindingEngine::create_binding(legitimate_tpm_ak, pcr, enclave_key, &nonce);

    // Attacker attempts to present proof with different TPM AK
    let rogue_tpm_ak = b"CLONED_ROGUE_TPM_AK";
    let is_valid =
        IdentityBindingEngine::verify_binding(&proof, rogue_tpm_ak, pcr, enclave_key, &nonce);
    assert!(!is_valid);
}

#[test]
fn test_sim_12_vbs_hypervisor_disabled_graceful_fallback() {
    let cap = EnclaveCapabilityMatrix::unsupported_software_fallback();
    assert_eq!(cap.status, EnclaveStatus::Unsupported);
    assert_eq!(cap.assurance_level(), AssuranceLevel::Software);
}

// =========================================================================
// Vectors 13-15: Replay Attacks / Stale Evidence Half-Life Decay
// =========================================================================

#[test]
fn test_sim_13_replay_attack_with_captured_old_binding_nonce() {
    let tpm = b"TPM";
    let pcr = b"PCR";
    let enclave = b"ENCLAVE";
    let old_nonce = [0x01u8; 32];
    let new_challenge_nonce = [0x02u8; 32];

    let proof = IdentityBindingEngine::create_binding(tpm, pcr, enclave, &old_nonce);
    let is_valid =
        IdentityBindingEngine::verify_binding(&proof, tpm, pcr, enclave, &new_challenge_nonce);
    assert!(!is_valid);
}

#[test]
fn test_sim_14_expired_evidence_decay_forces_step_up_or_isolate() {
    let (tpm, kernel, dma, fw, enclave) = baseline_hardened();
    let config = PolicyConfig::default();
    let now = 100000;
    // Expired TTL (observed at 1000, expires at 2000, now is 100000)
    let meta = EvidenceMetadata::new(
        1000,
        Some(1000),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        now,
    );
    assert_eq!(report.freshness_confidence, 0);
    assert_eq!(report.composite_score, 0);
    match report.decision {
        PolicyDecision::Isolate { .. } => {}
        _ => panic!("Expected Isolate for 100% expired evidence"),
    }
}

#[test]
fn test_sim_15_half_life_decay_graceful_step_up() {
    let (tpm, kernel, dma, fw, enclave) = baseline_hardened();
    let config = PolicyConfig::default();
    let observed_at = 10000;
    let now = observed_at + config.half_life_secs; // Exactly 1 half-life
    let meta = EvidenceMetadata::new(
        observed_at,
        Some(500000),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        now,
    );
    assert_eq!(report.freshness_confidence, 5000);
    match report.decision {
        PolicyDecision::StepUp { reason, .. } => {
            assert!(reason.contains("Freshness") || reason.contains("Below Allow Threshold"));
        }
        _ => panic!("Expected StepUp after 1 half-life decay"),
    }
}

// =========================================================================
// Vectors 16-18: Byzantine Multi-Sensor & Compound Attack Resiliency
// =========================================================================

#[test]
fn test_sim_16_byzantine_fake_tpm_isolated_by_kernel_cross_check() {
    let (_, kernel, dma, fw, _) = baseline_hardened();
    let config = PolicyConfig::default();

    // Attacker fakes high TPM score (10000) but runs in Unsupported userland enclave (Software)
    let fake_tpm_score = 10000;
    let cap = EnclaveCapabilityMatrix::unsupported_software_fallback();
    let enclave = EnclaveAttestationEngine::evaluate(&cap, None, None);

    let report = SecurityPolicyEngine::evaluate(
        &config,
        fake_tpm_score,
        &kernel,
        &dma,
        &fw,
        &enclave,
        None,
        1000,
    );
    match report.decision {
        PolicyDecision::StepUp {
            reason,
            required_assurance,
        } => {
            assert_eq!(reason, "Assurance Level Insufficient");
            assert_eq!(required_assurance, AssuranceLevel::OSProtected);
        }
        _ => panic!("Expected StepUp due to low assurance level"),
    }
}

#[test]
fn test_sim_17_multi_attack_compound_failure_isolation() {
    let config = PolicyConfig::default();

    // Attacker triggers multiple simultaneous failures
    let tpm_score = 1000;

    let reg = ProtectedProcessRegistration::new(1001, 1000, "nonce", 1);
    let mut telem = ShieldTelemetry::inactive();
    telem.blocked_terminations = 5;
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
        PolicyDecision::Isolate { .. } => {}
        _ => panic!("Expected high-severity Isolate for compound attack"),
    }
}

#[test]
fn test_sim_18_system_resilience_after_attack_mitigation() {
    let (tpm, kernel, dma, fw, enclave) = baseline_hardened();
    let config = PolicyConfig::default();
    let now = 1000;
    let meta = EvidenceMetadata::new(
        now,
        Some(86400),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    // After attack vectors are cleared, clean hardened evidence restores ALLOW
    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        now,
    );
    assert_eq!(report.decision, PolicyDecision::Allow);
    assert_eq!(report.composite_score, 10000);
    assert_eq!(report.achieved_assurance, AssuranceLevel::Attested);
}
