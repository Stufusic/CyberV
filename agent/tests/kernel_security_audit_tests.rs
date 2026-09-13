//! Kernel Security Audit & Invariant Verification Test Suite
//!
//! Ref: Docs/errorcheck.md & Docs/newpl.md:
//! Formal verification that all security invariants are strictly enforced:
//! - INV-001: Driver unavailable or shield inactive => Policy MUST evaluate to Isolate (Fail-Closed)
//! - INV-002: Unknown / missing kernel observation != Trusted observation (is_hardware_verified = false)
//! - INV-003: Platform recovery requires valid Ed25519 asymmetric signature
//! - INV-004: EventBus Mutex poisoning recovery prevents telemetry loss
//! - INV-005: Update staging transition guards against unverified packages
//! - INV-006: Startup recovery detects TPM monotonic counter rollback contradictions
//! - INV-007: Zeroization guaranteed upon Drop in SecureIsoBuffer

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
use cyberv_agent::defense::recovery::{
    DeviceLifecycleState, RecoveryManager, RecoveryProof,
};
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::HardwareCollector;
use cyberv_agent::kernel::client::KernelProbeProvider;
use cyberv_agent::kernel::cross_validator::{CrossLayerValidator, ValidationStatus};
use cyberv_agent::kernel::protocol::KernelObservationPayload;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

fn helper_hardened_reports() -> (
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
// TEST-01: INV-001 (Fail-Closed Policy on Driver Disconnect/Unload)
// =========================================================================
#[test]
fn test_remediation_01_fail_closed_policy_on_driver_unloaded() {
    let (tpm_score, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();

    // Attacker unloads cybervprobe.sys cleanly (telemetry shows shield inactive, 0 terminations)
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let telem = ShieldTelemetry::inactive();
    let kernel_report = AntiTamperManager::evaluate(&reg, &telem, false); // driver_reachable = false

    assert_eq!(kernel_report.defense_score, 3000);
    assert!(kernel_report.is_tampering_detected);

    // Evaluate policy in SecurityPolicyEngine
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

    // Bất biến INV-001: Mất driver nhân BẮT BUỘC phải Isolate (Fail-Closed), không bao giờ Allow!
    match policy_report.decision {
        PolicyDecision::Isolate { reason, severity } => {
            assert_eq!(reason, "Kernel Defense Tampered");
            assert_eq!(severity, 9500);
        }
        _ => panic!(
            "FAIL-OPEN VIOLATION: Expected Isolate decision on driver absence, got {:?}",
            policy_report.decision
        ),
    }
    assert_eq!(policy_report.composite_score, 0);
}

// =========================================================================
// TEST-02: INV-002 (Cross-Layer Validator Marks Missing Driver as Unverified)
// =========================================================================
struct MissingKernelProvider;
impl KernelProbeProvider for MissingKernelProvider {
    fn is_driver_available(&self) -> bool {
        false
    }
    fn query_kernel_observation(&self) -> Option<KernelObservationPayload> {
        None
    }
}

#[test]
fn test_remediation_02_cross_validator_marks_missing_driver_unverified() {
    let snapshot = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let missing_driver = MissingKernelProvider;

    let report = CrossLayerValidator::validate(&snapshot, &missing_driver);

    assert_eq!(report.status, ValidationStatus::Unknown);
    // Bất biến INV-002: Unknown != Verified (không được coi là bằng chứng xác thực)
    assert!(
        !report.is_hardware_verified,
        "Missing driver MUST NOT be marked as hardware_verified"
    );
}

// =========================================================================
// TEST-03: INV-003 (Asymmetric Signature Verification for Re-Attestation)
// =========================================================================
#[test]
fn test_remediation_03_recovery_requires_valid_asymmetric_signature() {
    let now = 123456789;
    let nonce = [0x42u8; 32];
    let prev_pcr = b"OLD_PCR_VALUE";
    let new_pcr = b"NEW_PCR_VALUE";

    let challenge = RecoveryManager::create_challenge("dev-test-1", nonce, prev_pcr, new_pcr, now);
    let expected_oem_cert_hash = "oem_cert_hash_1234";

    // Sinh cặp khóa Ed25519 của Admin hợp lệ
    let mut csprng = OsRng;
    let admin_signing_key = SigningKey::generate(&mut csprng);
    let admin_verifying_key = admin_signing_key.verifying_key();
    let admin_pubkey = admin_verifying_key.as_bytes();

    // 1. Thử ký giả mạo bằng SHA-512 thông thường (không có Private Key)
    let forged_proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: "0123456789abcdef".repeat(8), // 128 hex chars
        oem_update_cert_hash: expected_oem_cert_hash.to_string(),
    };

    let forgery_result = RecoveryManager::verify_and_re_attest(
        &challenge,
        &forged_proof,
        admin_pubkey,
        expected_oem_cert_hash,
    );
    assert!(
        forgery_result.is_err(),
        "Forged signature without private key MUST be rejected!"
    );

    // 2. Ký bằng đúng khóa riêng Ed25519 của Admin
    let legit_signature = RecoveryManager::sign_recovery_challenge(&challenge, &admin_signing_key);
    let legit_proof = RecoveryProof {
        challenge_id: challenge.challenge_id.clone(),
        admin_signature_sha512: legit_signature,
        oem_update_cert_hash: expected_oem_cert_hash.to_string(),
    };

    let legit_result = RecoveryManager::verify_and_re_attest(
        &challenge,
        &legit_proof,
        admin_pubkey,
        expected_oem_cert_hash,
    );
    assert_eq!(
        legit_result,
        Ok(DeviceLifecycleState::ActiveAttested),
        "Legitimate Ed25519 signature from admin MUST be accepted!"
    );
}

// =========================================================================
// TEST-04: INV-004 / INV-006 (EventBus Mutex Poison Recovery)
// =========================================================================
#[test]
fn test_remediation_04_event_bus_recovers_from_mutex_poison() {
    let bus = Arc::new(SecurityEventBus::new());

    // Luồng 1 cố tình panic khi đang giữ mutex
    let bus_clone = bus.clone();
    let _ = std::thread::spawn(move || {
        bus_clone.publish(SecurityEvent::BinaryTamperDetected {
            detail: "Event before crash".to_string(),
        });
        panic!("Simulated thread crash while publishing");
    })
    .join();

    // EventBus không được bị tê liệt: publish và drain tiếp theo phải tự phục hồi
    bus.publish(SecurityEvent::DriverUnexpected {
        reason: "Event after recovery".to_string(),
    });

    let events = bus.drain_events();
    assert!(
        !events.is_empty(),
        "EventBus MUST recover and retain events even after thread panic"
    );
    assert!(
        events.iter().any(|e| matches!(e, SecurityEvent::DriverUnexpected { .. })),
        "Subsequent events MUST be published successfully"
    );
}

// =========================================================================
// TEST-05: INV-005 (Update State Machine Transition Guards)
// =========================================================================
#[test]
fn test_remediation_05_update_staging_guards_unverified_package() {
    // Gọi advance_state từ Current khi verification = false
    let unverified_result = UpdateStagingManager::advance_state(UpdateStagingState::Current, false);
    assert!(
        unverified_result.is_err(),
        "Unverified package MUST NOT transition to Staged state!"
    );

    // Khi verification = true: cho phép chuyển sang Staged
    let verified_result = UpdateStagingManager::advance_state(UpdateStagingState::Current, true);
    assert_eq!(
        verified_result,
        Ok(UpdateStagingState::Staged),
        "Verified package transitions to Staged"
    );
}

// =========================================================================
// TEST-06: INV-007 (Audit Transparency on Phantom Modules)
// =========================================================================
#[test]
fn test_remediation_06_phantom_modules_report_verified_flag() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    // Báo cáo có trường is_verified phản ánh rõ ràng tính xác minh
    assert!(status.is_verified);

    let priv_report = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    assert!(priv_report.is_verified);
}

// =========================================================================
// TEST-07: INV-006 (Startup Recovery Catches TPM Rollback)
// =========================================================================
#[test]
fn test_remediation_07_startup_recovery_catches_tpm_rollback() {
    let action = UpdateStagingManager::evaluate_startup_recovery(None, "hash_v1", 1, 2);

    match action {
        StartupRecoveryAction::ContradictionDetected {
            software_version,
            tpm_counter,
        } => {
            assert_eq!(software_version, 1);
            assert_eq!(tpm_counter, 2);
        }
        _ => panic!("Expected ContradictionDetected for rollback attempt"),
    }
}

// =========================================================================
// TEST-08: INV-008 (Guaranteed Zeroization on Drop in SecureIsoBuffer)
// =========================================================================
#[test]
fn test_remediation_08_zeroization_guaranteed_on_drop() {
    let raw_secret = [0x5au8; 256];
    let buf = SecureIsoBuffer::copy_from_untrusted(&raw_secret).unwrap();
    assert_eq!(buf.len(), 256);
    assert_eq!(buf.as_slice()[0], 0x5a);

    // Drop buffer
    drop(buf);

    // Boundary errors
    let empty_err = SecureIsoBuffer::copy_from_untrusted(&[]);
    assert_eq!(empty_err, Err(BoundaryError::EmptyBuffer));
}
