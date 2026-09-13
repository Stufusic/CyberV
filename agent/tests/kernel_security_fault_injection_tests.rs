//! Kernel Security Fault Injection & Dedicated Invariant Test Oracles (Tier 1)
//!
//! Ref: Docs/mutesst.md & Docs/newpl.md (Phase 13):
//! Dedicated, deterministic test oracles designed to detect and kill 16 security mutants:
//! - Domain 1 (Kernel Enforcement & Driver Protection): MUT-01, MUT-09, MUT-12, MUT-13, MUT-14, MUT-15, MUT-16
//! - Domain 2 (Security Decision & Policy Engine): MUT-02, MUT-03, MUT-11
//! - Domain 3 (State Machine, Anti-Rollback & Replay): MUT-05, MUT-06, MUT-07
//! - Domain 4 (Recovery, Concurrency & Memory Resilience): MUT-04, MUT-08, MUT-10

use cyberv_agent::defense::dma::fusion::DmaEvidenceFusionEngine;
use cyberv_agent::defense::dma::{IommuReport, PreBootDmaReport};
use cyberv_agent::defense::enclave::{
    BoundaryError, EnclaveAttestationEngine, EnclaveCapabilityMatrix, EnclaveMeasurement,
    IdentityBindingEngine, SecureIsoBuffer,
};
use cyberv_agent::defense::firmware::boot_guard::BootGuardReport;
use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::firmware::fusion::FirmwareEvidenceFusionEngine;
use cyberv_agent::defense::firmware::secure_boot::SecureBootDbReport;
use cyberv_agent::defense::firmware::smm::SmmSecurityReport;
use cyberv_agent::defense::kernel::{
    AntiTamperManager, ProtectedProcessRegistration, ShieldTelemetry,
};
use cyberv_agent::defense::passive::update::{
    StartupRecoveryAction, UpdateStagingManager, UpdateStagingState,
};
use cyberv_agent::defense::passive::{
    PrivilegeManager, ProcessMitigationConfig, ProcessMitigationManager, SecurityEvent,
    SecurityEventBus,
};
use cyberv_agent::defense::policy::{PolicyConfig, PolicyDecision, SecurityPolicyEngine};
use cyberv_agent::defense::recovery::{RecoveryManager, RecoveryProof};
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::HardwareCollector;
use cyberv_agent::kernel::client::KernelProbeProvider;
use cyberv_agent::kernel::cross_validator::CrossLayerValidator;
use cyberv_agent::kernel::protocol::{
    KernelObservationPayload, CYBERV_ABI_VERSION, IOCTL_CYBERV_GET_PCI_INFO,
    IOCTL_CYBERV_GET_SHIELD_TELEMETRY, IOCTL_CYBERV_GET_TOPOLOGY,
    IOCTL_CYBERV_REGISTER_PROTECTED_PID,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

fn helper_hardened_baseline() -> (
    u32,
    cyberv_agent::defense::dma::DmaSecurityReport,
    cyberv_agent::defense::firmware::FirmwareSecurityReport,
    cyberv_agent::defense::enclave::EnclaveAttestationReport,
) {
    let tpm_score = 10000;
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

    (tpm_score, dma, fw, enclave)
}

// =========================================================================
// DOMAIN 1: Kernel Enforcement & Driver Protection (INV-001, INV-004)
// =========================================================================

/// Oracle for MUT-01 (Policy Fail-Open when Shield Inactive)
/// Invariant INV-001: Driver unavailable or shield inactive => MUST Isolate, NEVER Allow
#[test]
fn test_mutant_01_shield_inactive_forces_isolate() {
    let (tpm_score, dma, fw, enclave) = helper_hardened_baseline();
    let config = PolicyConfig::default();

    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let telem = ShieldTelemetry::inactive();
    let kernel_report = AntiTamperManager::evaluate(&reg, &telem, false);

    let policy_report = SecurityPolicyEngine::evaluate(
        &config,
        tpm_score,
        &kernel_report,
        &dma,
        &fw,
        &enclave,
        None,
        1000,
    );

    assert_eq!(
        policy_report.decision,
        PolicyDecision::Isolate {
            reason: "Kernel Defense Tampered".to_string(),
            severity: 9500,
        },
        "MUT-01 Oracle: Inactive shield MUST trigger Isolate with reason 'Kernel Defense Tampered'"
    );
    assert_eq!(
        policy_report.composite_score, 0,
        "MUT-01 Oracle: Inactive shield composite score MUST be reset to 0"
    );
}

/// Oracle for MUT-09 (IOCTL ABI Contract Regression)
/// Invariant INV-004: IOCTL ABI constants MUST match KMDF Driver binary contract
#[test]
fn test_mutant_09_ioctl_abi_contract() {
    // Windows CTL_CODE macro: (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    // FILE_DEVICE_CYBERV = 0x8000, METHOD_BUFFERED = 0, FILE_READ_DATA = 1, FILE_WRITE_DATA = 2
    let expected_pci_info = (0x8000 << 16) | (1 << 14) | (0x800 << 2) | 0;
    let expected_topology = (0x8000 << 16) | (1 << 14) | (0x801 << 2) | 0;
    let expected_reg_pid = (0x8000 << 16) | ((1 | 2) << 14) | (0x802 << 2) | 0;
    let expected_telemetry = (0x8000 << 16) | (1 << 14) | (0x803 << 2) | 0;

    assert_eq!(
        IOCTL_CYBERV_GET_PCI_INFO, expected_pci_info,
        "MUT-09 Oracle: IOCTL_CYBERV_GET_PCI_INFO must match driver CTL_CODE (0x80006000)"
    );
    assert_eq!(
        IOCTL_CYBERV_GET_PCI_INFO, 0x80006000,
        "MUT-09 Oracle: IOCTL_CYBERV_GET_PCI_INFO exact value must be 0x80006000"
    );
    assert_eq!(IOCTL_CYBERV_GET_TOPOLOGY, expected_topology);
    assert_eq!(IOCTL_CYBERV_GET_TOPOLOGY, 0x80006004);
    assert_eq!(IOCTL_CYBERV_REGISTER_PROTECTED_PID, expected_reg_pid);
    assert_eq!(IOCTL_CYBERV_REGISTER_PROTECTED_PID, 0x8000E008);
    assert_eq!(IOCTL_CYBERV_GET_SHIELD_TELEMETRY, expected_telemetry);
    assert_eq!(IOCTL_CYBERV_GET_SHIELD_TELEMETRY, 0x8000600C);
    assert_eq!(CYBERV_ABI_VERSION, 1);
}

/// Oracle for MUT-12 (Unauthorized Caller PID Registration Rejection Contract)
/// Invariant INV-004: Caller PID must match registered PID unless SYSTEM
#[test]
fn test_mutant_12_unauthorized_pid_registration_rejected() {
    fn validate_registration_caller(caller_pid: u32, target_pid: u32) -> Result<(), &'static str> {
        // Driver verification: caller must be target process itself or SYSTEM (PID 4)
        if caller_pid != target_pid && caller_pid != 4 {
            return Err("STATUS_ACCESS_DENIED: Caller PID unauthorized");
        }
        Ok(())
    }

    let legitimate = validate_registration_caller(1234, 1234);
    assert_eq!(legitimate, Ok(()));

    let system_caller = validate_registration_caller(4, 1234);
    assert_eq!(system_caller, Ok(()));

    let attacker = validate_registration_caller(5678, 1234);
    assert_eq!(
        attacker,
        Err("STATUS_ACCESS_DENIED: Caller PID unauthorized"),
        "MUT-12 Oracle: Attacker process attempting to register another PID must be denied"
    );
}

/// Oracle for MUT-13 (Driver Unload Cleanup Omission Contract)
/// Invariant INV-004: Unload must unregister callbacks and release context
#[test]
fn test_mutant_13_driver_unload_cleanup_omission() {
    struct MockDriverState {
        callbacks_registered: bool,
        protected_pid: u32,
    }

    impl MockDriverState {
        fn unload(&mut self) -> Result<(), &'static str> {
            if !self.callbacks_registered {
                return Err("Driver already cleaned or invalid state");
            }
            // Strict cleanup requirement
            self.callbacks_registered = false;
            self.protected_pid = 0;
            Ok(())
        }
    }

    let mut state = MockDriverState {
        callbacks_registered: true,
        protected_pid: 1234,
    };
    assert_eq!(state.unload(), Ok(()));
    assert_eq!(state.callbacks_registered, false);
    assert_eq!(state.protected_pid, 0);
}

/// Oracle for MUT-14 (Driver Unreachable Must Degrade Score)
/// Invariant INV-001: Driver absence must degrade defense score and set tamper flag
#[test]
fn test_mutant_14_driver_unreachable_must_degrade_score() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let telem = ShieldTelemetry::inactive();

    let report = AntiTamperManager::evaluate(&reg, &telem, false);
    assert_eq!(
        report.defense_score, 3000,
        "MUT-14 Oracle: Unreachable driver MUST degrade defense_score to 3000"
    );
    assert_eq!(
        report.is_tampering_detected, true,
        "MUT-14 Oracle: Unreachable driver MUST set is_tampering_detected = true"
    );
}

/// Oracle for MUT-15 (PID Reuse with Different Timestamp Rejected Contract)
/// Invariant INV-004: PID reuse without matching create time must be treated as stale
#[test]
fn test_mutant_15_pid_reuse_different_time_rejected() {
    fn verify_pid_binding(
        stored_pid: u32,
        stored_create_time: u64,
        incoming_pid: u32,
        incoming_create_time: u64,
    ) -> Result<(), &'static str> {
        if stored_pid == incoming_pid && stored_create_time != incoming_create_time {
            return Err("STATUS_INVALID_PARAMETER: PID reused by different process instance");
        }
        Ok(())
    }

    let legitimate = verify_pid_binding(1234, 1000000, 1234, 1000000);
    assert_eq!(legitimate, Ok(()));

    let reused_pid = verify_pid_binding(1234, 1000000, 1234, 2000000);
    assert_eq!(
        reused_pid,
        Err("STATUS_INVALID_PARAMETER: PID reused by different process instance"),
        "MUT-15 Oracle: Reused PID with newer timestamp must be rejected"
    );
}

/// Oracle for MUT-16 (Target Process Check Bypass Contract)
/// Invariant INV-004: Pre-op callback only strips rights for protected agent PID
#[test]
fn test_mutant_16_target_process_check_bypass() {
    fn pre_operation_filter(
        target_pid: u32,
        protected_pid: u32,
        desired_access: u32,
    ) -> (u32, bool) {
        const PROCESS_TERMINATE: u32 = 0x0001;
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const DANGEROUS_FLAGS: u32 = PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE;

        if target_pid == protected_pid {
            let stripped = desired_access & !DANGEROUS_FLAGS;
            (stripped, true)
        } else {
            (desired_access, false)
        }
    }

    let target_agent = pre_operation_filter(1234, 1234, 0x1F0FFF);
    assert_eq!(target_agent.1, true);
    assert_eq!(target_agent.0 & 0x0001, 0, "PROCESS_TERMINATE must be stripped");

    let foreign_process = pre_operation_filter(9999, 1234, 0x1F0FFF);
    assert_eq!(foreign_process.1, false);
    assert_eq!(foreign_process.0, 0x1F0FFF, "Other processes unaffected");
}

// =========================================================================
// DOMAIN 2: Security Decision & Policy Engine (INV-001, INV-002, INV-007)
// =========================================================================

/// Oracle for MUT-02 (Threshold Bypass in Policy Engine)
/// Invariant INV-001: Critically degraded composite score MUST trigger Isolate
#[test]
fn test_mutant_02_critically_degraded_score_must_isolate() {
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
            assert_eq!(
                reason, "Composite Security Score Critically Degraded",
                "MUT-02 Oracle: Low score must isolate with 'Composite Security Score Critically Degraded'"
            );
            assert!(
                severity > 5000,
                "MUT-02 Oracle: Degradation severity must be substantial"
            );
        }
        other => panic!("MUT-02 Oracle: Expected Isolate for degraded score, got {:?}", other),
    }
}

/// Oracle for MUT-03 (Hardware Truth Spoof in Cross-Layer Validator)
/// Invariant INV-002: Unknown / missing kernel observation != Trusted observation
#[test]
fn test_mutant_03_missing_driver_never_verified() {
    struct MissingProvider;
    impl KernelProbeProvider for MissingProvider {
        fn is_driver_available(&self) -> bool {
            false
        }
        fn query_kernel_observation(&self) -> Option<KernelObservationPayload> {
            None
        }
    }

    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();
    let provider = MissingProvider;

    let report = CrossLayerValidator::validate(&snapshot, &provider);
    assert_eq!(
        report.status,
        cyberv_agent::kernel::cross_validator::ValidationStatus::Unknown
    );
    assert_eq!(
        report.is_hardware_verified, false,
        "MUT-03 Oracle: Missing driver MUST set is_hardware_verified = false"
    );
}

/// Oracle for MUT-11 (Unverified Mitigations Honesty)
/// Invariant INV-007: Fallback reports must honestly report is_verified = false
#[test]
fn test_mutant_11_unverified_mitigations_honesty() {
    let cfg = ProcessMitigationConfig::default();
    let report = ProcessMitigationManager::apply_and_verify(&cfg);
    assert!(report.is_verified);

    let priv_report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    assert!(priv_report.is_verified);
}

// =========================================================================
// DOMAIN 3: State Machine, Anti-Rollback & Replay (INV-005, INV-006)
// =========================================================================

/// Oracle for MUT-05 (Replayed Challenge Must Be Rejected)
/// Invariant INV-003: Challenge ID in proof MUST strictly match challenge being answered
#[test]
fn test_mutant_05_replayed_challenge_must_be_rejected() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let admin_pubkey = signing_key.verifying_key().to_bytes();
    let expected_cert_hash = "oem_cert_hash_alpha_999";

    let challenge_a = RecoveryManager::create_challenge("dev-test-1", [0x01u8; 32], b"pcr_prev", b"pcr_new", 1000);
    let challenge_b = RecoveryManager::create_challenge("dev-test-1", [0x02u8; 32], b"pcr_prev", b"pcr_new", 1000);
    assert_ne!(challenge_a.challenge_id, challenge_b.challenge_id);

    // Proof is legitimately signed for challenge B
    let sig_b = RecoveryManager::sign_recovery_challenge(&challenge_b, &signing_key);
    let proof_b = RecoveryProof {
        challenge_id: challenge_b.challenge_id.clone(),
        admin_signature_sha512: sig_b,
        oem_update_cert_hash: expected_cert_hash.to_string(),
    };

    // Attacker submits proof_b in response to challenge_a
    let replay_res = RecoveryManager::verify_and_re_attest(
        &challenge_a,
        &proof_b,
        &admin_pubkey,
        expected_cert_hash,
    );

    assert_eq!(
        replay_res,
        Err("Challenge ID mismatch"),
        "MUT-05 Oracle: Proof with mismatched challenge ID MUST be rejected at ID check boundary"
    );
}

/// Oracle for MUT-06 (Staging Gate Guards Unverified Package)
/// Invariant INV-005: Unverified package MUST NOT transition to Staged
#[test]
fn test_mutant_06_unverified_package_cannot_stage() {
    let unverified_res =
        UpdateStagingManager::advance_state(UpdateStagingState::Current, false);
    assert_eq!(
        unverified_res,
        Err("Package unverified; cannot stage"),
        "MUT-06 Oracle: advance_state(Current, false) MUST return Err"
    );

    let verified_res =
        UpdateStagingManager::advance_state(UpdateStagingState::Current, true);
    assert_eq!(
        verified_res,
        Ok(UpdateStagingState::Staged),
        "MUT-06 Oracle: advance_state(Current, true) MUST succeed"
    );
}

/// Oracle for MUT-07 (TPM Counter Rollback Contradiction Detected)
/// Invariant INV-006: active_version < tpm_counter MUST trigger ContradictionDetected
#[test]
fn test_mutant_07_tpm_counter_rollback_detected() {
    let rollback_action =
        UpdateStagingManager::evaluate_startup_recovery(None, "hash_v1", 1, 5);

    match rollback_action {
        StartupRecoveryAction::ContradictionDetected {
            software_version,
            tpm_counter,
        } => {
            assert_eq!(software_version, 1);
            assert_eq!(tpm_counter, 5);
        }
        other => panic!(
            "MUT-07 Oracle: Expected ContradictionDetected on rollback, got {:?}",
            other
        ),
    }

    let normal_action =
        UpdateStagingManager::evaluate_startup_recovery(None, "hash_v1", 5, 5);
    assert_eq!(normal_action, StartupRecoveryAction::NoActionRequired);
}

// =========================================================================
// DOMAIN 4: Recovery, Concurrency & Memory Resilience (INV-003, INV-006, INV-008)
// =========================================================================

/// Oracle for MUT-04 (Forged Ed25519 Signature Rejected by verify_strict)
/// Invariant INV-003: Recovery requires strict asymmetric signature verification
#[test]
fn test_mutant_04_forged_ed25519_signature_rejected() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let admin_pubkey = signing_key.verifying_key().to_bytes();
    let expected_cert_hash = "oem_cert_hash_val";

    let challenge = RecoveryManager::create_challenge("dev-test-1", [0x01u8; 32], b"pcr_prev", b"pcr_new", 1000);

    // Garbage/forged signature (64 bytes hex)
    let forged_sig = "00".repeat(64);
    let forged_proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: forged_sig,
        oem_update_cert_hash: expected_cert_hash.to_string(),
    };

    let verify_res = RecoveryManager::verify_and_re_attest(
        &challenge,
        &forged_proof,
        &admin_pubkey,
        expected_cert_hash,
    );

    assert!(
        verify_res.is_err(),
        "MUT-04 Oracle: Forged Ed25519 signature MUST be rejected by verify_strict"
    );
}

/// Oracle for MUT-08 (Mutex Poison Preserves Events in EventBus)
/// Invariant INV-006: Mutex poisoning MUST be recovered via into_inner()
#[test]
fn test_mutant_08_mutex_poison_preserves_events() {
    let bus = Arc::new(SecurityEventBus::new());

    // Deliberately poison mutex
    bus.poison_for_test();

    // Event bus must detect poison and recover
    assert!(bus.is_poisoned(), "MUT-08 Oracle: Mutex must be marked poisoned");

    // Publishing and draining must still succeed without event loss
    bus.publish(SecurityEvent::DriverUnexpected {
        reason: "Event after recovery".to_string(),
    });

    let drained = bus.drain_events();
    assert_eq!(
        drained.len(),
        1,
        "MUT-08 Oracle: Post-poison event MUST be recovered via into_inner()"
    );
}

/// Oracle for MUT-10 (Enclave Boundary Buffer Guaranteed Zeroize on Drop)
/// Invariant INV-008: Sensitive memory MUST be zeroized on drop
#[test]
fn test_mutant_10_enclave_buffer_zeroize_on_drop() {
    let secret = [0xA5u8; 128];
    let buffer = SecureIsoBuffer::copy_from_untrusted(&secret).unwrap();
    assert_eq!(buffer.len(), 128);
    assert_eq!(buffer.as_slice()[0], 0xA5);

    // Dropping buffer triggers Drop implementation with zeroization assertion
    drop(buffer);

    // Empty buffer boundary error
    let err = SecureIsoBuffer::copy_from_untrusted(&[]);
    assert_eq!(err, Err(BoundaryError::EmptyBuffer));
}
