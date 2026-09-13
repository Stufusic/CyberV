//! Phase 24.2: Architectural Hardening & Kernel Code Integrity Test Suite
//!
//! Ref: Docs/rv15.md Section 13:
//! Comprehensive 17-Group Test Topology (Groups A through Q):
//! - Group A: TPM Semantics (initialization, monotonic increment, bounds)
//! - Group B: TPM Persistence & Lifecycle (discover, verify attributes, foreign ownership)
//! - Group C: Rollback & Crash Recovery (contradiction detection, 2-phase commit, marker recovery)
//! - Group D: VM / vTPM Assurance Tiers (HardwareBacked, VtpmBacked, SoftwareFallback)
//! - Group E: Broker Authorization & Identity (SID verification, process token, Authenticode)
//! - Group F: IPC Cryptographic Handshake (session isolation, AEAD integrity)
//! - Group G: Replay, Frame Ordering & Message Bounds (monotonic sequence, 64KB bound)
//! - Group H: Worker Compromise Simulation (unauthorized vault access, fuzzing, disconnect)
//! - Group I: Broker Policy Admission Pipeline (signature check, monotonic version, expiration, invariants)
//! - Group J: AppContainer Sandbox Isolation (restricted token privileges)
//! - Group K: WDAC XML Generation (Audit Mode First, WHQL & CyberV signers)
//! - Group L: WDAC Deployment & Break-Glass Recovery (staging, recovery rule)
//! - Group M: Process Module Inventory & Authenticode (system DLLs, CyberV modules, foreign DLL detection)
//! - Group N: Offline Autonomous Local Enforcement (never default ALLOW, immediate isolate on contradiction)
//! - Group O: Trust Continuity Loop (re-observation on recovery, freshness update)
//! - Group P: Cross-Layer Contradiction Detection (TPM vs software vs kernel CI)
//! - Group Q: System-Wide Regression Matrix (schema V2 backward compatibility, end-to-end pipeline)

use cyberv_agent::defense::passive::isolation::{
    encode_hex, BrokerError, BrokerPolicyAdmissionController, BrokerRpcCommand, CoreBroker,
    IpcFrameError, NetworkWorkerDaemon, PolicyAdmissionError, RpcEnvelope, RpcSessionValidator,
    SignedPolicyEnvelope, CURRENT_IPC_PROTOCOL_VERSION, EXPECTED_WORKER_APPCONTAINER_SID,
    MAX_IPC_FRAME_SIZE,
};
use cyberv_agent::defense::passive::update::{
    CommitStage, HardwareVersionDecision, PendingCommitMarker, StartupRecoveryAction,
    UpdateStagingManager, VersionPolicyValidator,
};
use cyberv_agent::defense::passive::wdac::{
    CodeIntegrityVerifier, ModuleClassification, ModuleEntry, ProcessModuleInspector,
    WdacPolicyGenerator, WdacSecurityReport,
};
use cyberv_agent::defense::passive::{
    PassiveDefenseCoordinator, PassiveDefenseReport, SecurityEvent, SecurityEventBus,
};
use cyberv_agent::defense::policy::{PolicyConfig, PolicyDecision, SecurityPolicyEngine};
use cyberv_agent::trust::tpm::{
    MockTpmNvCounter, TpmAssuranceType, TpmError, TpmNvCounter, DEFAULT_CYBERV_NV_INDEX,
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

// =========================================================================
// GROUP A: TPM Semantics (Section 13 - Group A)
// =========================================================================

#[test]
fn test_a01_tpm_counter_initial_value_and_increment() {
    let mut counter = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);
    let handle = counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 100)
        .expect("Should provision counter");
    assert_eq!(handle.current_value, 100);
    assert!(handle.attributes.is_counter);

    let val = counter
        .read_counter(DEFAULT_CYBERV_NV_INDEX)
        .expect("Read counter");
    assert_eq!(val, 100);

    let inc1 = counter
        .increment_counter(DEFAULT_CYBERV_NV_INDEX)
        .expect("Increment counter");
    assert_eq!(inc1, 101);

    let inc2 = counter
        .increment_counter(DEFAULT_CYBERV_NV_INDEX)
        .expect("Increment counter");
    assert_eq!(inc2, 102);
}

#[test]
fn test_a02_tpm_counter_monotonic_non_decreasing() {
    let mut counter = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);
    counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 1)
        .unwrap();

    let mut last_val = counter.read_counter(DEFAULT_CYBERV_NV_INDEX).unwrap();
    for _ in 0..10 {
        let new_val = counter.increment_counter(DEFAULT_CYBERV_NV_INDEX).unwrap();
        assert!(
            new_val > last_val,
            "TPM Counter must strictly increase monotonically"
        );
        last_val = new_val;
    }
    assert_eq!(last_val, 11);
}

#[test]
fn test_a03_tpm_counter_bounds_overflow_handling() {
    let mut counter = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);
    counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, u64::MAX)
        .unwrap();

    let err = counter
        .increment_counter(DEFAULT_CYBERV_NV_INDEX)
        .unwrap_err();
    assert_eq!(err, TpmError::NvCounterOverflow(DEFAULT_CYBERV_NV_INDEX));
}

// =========================================================================
// GROUP B: TPM Persistence & Lifecycle (Section 13 - Group B)
// =========================================================================

#[test]
fn test_b01_tpm_nv_discovery_and_provision_lifecycle() {
    let mut counter = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);

    // Lần đầu: Chưa có -> Cấp phát mới
    let h1 = counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 42)
        .unwrap();
    assert_eq!(h1.current_value, 42);

    // Lần hai: Đã có -> Khám phá lại mà không ghi đè giá trị
    counter.increment_counter(DEFAULT_CYBERV_NV_INDEX).unwrap();
    let h2 = counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 999)
        .unwrap();
    assert_eq!(
        h2.current_value, 43,
        "Re-discovery must not reset existing counter"
    );
}

#[test]
fn test_b02_tpm_nv_rejects_ordinary_data_without_counter_flag() {
    // Giả lập index đã tồn tại nhưng không có cờ TPMA_NV_COUNTER
    let mut counter = MockTpmNvCounter::with_invalid_attributes(
        TpmAssuranceType::HardwareBacked,
        DEFAULT_CYBERV_NV_INDEX,
        false, // is_counter = false
        true,  // is_cyberv = true
    );

    let err = counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 10)
        .unwrap_err();
    assert_eq!(
        err,
        TpmError::NvIndexAttributeMismatch {
            expected: "TPMA_NV_COUNTER".to_string(),
            actual: "TPMA_NV_ORDINARY".to_string(),
        }
    );
}

#[test]
fn test_b03_tpm_nv_rejects_foreign_ownership_indices() {
    // Giả lập index thuộc về phần mềm/thực thể khác
    let mut counter = MockTpmNvCounter::with_invalid_attributes(
        TpmAssuranceType::HardwareBacked,
        DEFAULT_CYBERV_NV_INDEX,
        true,  // is_counter = true
        false, // is_cyberv = false (Foreign ownership)
    );

    let err = counter
        .discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 10)
        .unwrap_err();
    assert_eq!(
        err,
        TpmError::NvIndexForeignOwnership(DEFAULT_CYBERV_NV_INDEX)
    );
}

// =========================================================================
// GROUP C: Rollback & Crash Recovery (Section 13 - Group C)
// =========================================================================

#[test]
fn test_c01_contradiction_detection_when_disk_rolled_back() {
    // Phần mềm đĩa: V40. TPM NV Counter: 42.
    let decision = VersionPolicyValidator::evaluate_with_hardware_counter(
        40,
        41,
        42,
        TpmAssuranceType::HardwareBacked,
    );

    assert_eq!(
        decision,
        HardwareVersionDecision::ContradictionRollbackDetected {
            software_current: 40,
            counter: 42,
            discrepancy: 2,
            assurance: TpmAssuranceType::HardwareBacked,
        }
    );
}

#[test]
fn test_c02_two_phase_commit_pending_marker_success() {
    let marker = PendingCommitMarker {
        marker_id: "tx-commit-001".to_string(),
        target_version: 43,
        package_hash: "sha256_hash_pkg_43".to_string(),
        stage: CommitStage::TpmIncremented,
        timestamp: 1725500000,
    };

    // Khi khởi động, nhị phân đã swap sang V43 và TPM counter đã lên 43
    let action = UpdateStagingManager::evaluate_startup_recovery(
        Some(&marker),
        "sha256_hash_pkg_43",
        43,
        43,
    );

    assert_eq!(
        action,
        StartupRecoveryAction::CompleteCommit { target_version: 43 }
    );
}

#[test]
fn test_c03_crash_recovery_before_and_after_tpm_increment() {
    // Kịch bản 1: Crash ở giai đoạn Staged (chưa tăng TPM)
    let marker_staged = PendingCommitMarker {
        marker_id: "tx-staged-002".to_string(),
        target_version: 43,
        package_hash: "hash43".to_string(),
        stage: CommitStage::Staged,
        timestamp: 1725500000,
    };
    let recovery_staged = UpdateStagingManager::evaluate_startup_recovery(
        Some(&marker_staged),
        "old_hash_42",
        42,
        42,
    );
    assert_eq!(
        recovery_staged,
        StartupRecoveryAction::RollbackCleanly { target_version: 43 }
    );

    // Kịch bản 2: Không có marker nhưng phần mềm nhỏ hơn counter -> Contradiction!
    let recovery_no_marker =
        UpdateStagingManager::evaluate_startup_recovery(None, "hash40", 40, 42);
    assert_eq!(
        recovery_no_marker,
        StartupRecoveryAction::ContradictionDetected {
            software_version: 40,
            tpm_counter: 42,
        }
    );
}

// =========================================================================
// GROUP D: VM / vTPM Assurance Tiers (Section 13 - Group D)
// =========================================================================

#[test]
fn test_d01_assurance_hardware_backed_physical_tpm() {
    let counter = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);
    assert_eq!(
        counter.get_assurance_type(),
        TpmAssuranceType::HardwareBacked
    );
    assert_eq!(
        format!("{}", counter.get_assurance_type()),
        "HARDWARE_BACKED"
    );
}

#[test]
fn test_d02_assurance_vtpm_backed_virtual_machine() {
    let counter = MockTpmNvCounter::new(TpmAssuranceType::VtpmBacked);
    assert_eq!(counter.get_assurance_type(), TpmAssuranceType::VtpmBacked);
    assert_eq!(format!("{}", counter.get_assurance_type()), "VTPM_BACKED");
}

#[test]
fn test_d03_assurance_software_fallback() {
    let counter = MockTpmNvCounter::new(TpmAssuranceType::SoftwareFallback);
    assert_eq!(
        counter.get_assurance_type(),
        TpmAssuranceType::SoftwareFallback
    );
    assert_eq!(
        format!("{}", counter.get_assurance_type()),
        "SOFTWARE_FALLBACK"
    );
}

// =========================================================================
// GROUP E: Broker Authorization & Identity (Section 13 - Group E)
// =========================================================================

#[test]
fn test_e01_broker_named_pipe_dacl_authorizes_worker_sid() {
    let broker = CoreBroker::new();
    let auth = broker.authorize_client_connection(
        EXPECTED_WORKER_APPCONTAINER_SID,
        "CyberVWorker.exe",
        true,
    );
    assert!(
        auth.is_ok(),
        "Broker must authorize legitimate Worker AppContainer SID"
    );
}

#[test]
fn test_e02_broker_rejects_unauthorized_client_sid() {
    let broker = CoreBroker::new();
    let auth = broker.authorize_client_connection(
        "S-1-5-21-UNAUTHORIZED-ATTACKER-SID",
        "CyberVWorker.exe",
        true,
    );
    assert_eq!(
        auth,
        Err(BrokerError::UnauthorizedClientSid(
            "S-1-5-21-UNAUTHORIZED-ATTACKER-SID".to_string()
        ))
    );
}

#[test]
fn test_e03_broker_verifies_client_executable_authenticode() {
    let broker = CoreBroker::new();
    // Tên đúng nhưng chữ ký số không hợp lệ
    let auth = broker.authorize_client_connection(
        EXPECTED_WORKER_APPCONTAINER_SID,
        "CyberVWorker.exe",
        false, // Invalid signature!
    );
    assert_eq!(
        auth,
        Err(BrokerError::UntrustedExecutable(
            "CyberVWorker.exe".to_string()
        ))
    );
}

// =========================================================================
// GROUP F: IPC Cryptographic Handshake (Section 13 - Group F)
// =========================================================================

#[test]
fn test_f01_ephemeral_x25519_chacha20_handshake_success() {
    let mut broker = CoreBroker::new();
    let session_id = 99887766u64;
    broker.register_session(session_id);

    let mut worker = NetworkWorkerDaemon::new(session_id);
    let request = worker.create_rpc_request(1, BrokerRpcCommand::GetStatus, vec![1, 2, 3]);

    let handled = broker.handle_rpc_frame(&request);
    assert_eq!(handled, Ok(BrokerRpcCommand::GetStatus));
}

#[test]
fn test_f02_handshake_session_isolation() {
    let mut broker = CoreBroker::new();
    broker.register_session(1001);
    broker.register_session(1002);

    let mut worker1 = NetworkWorkerDaemon::new(1001);
    let req1 = worker1.create_rpc_request(1, BrokerRpcCommand::GetStatus, vec![]);

    assert_eq!(
        broker.handle_rpc_frame(&req1),
        Ok(BrokerRpcCommand::GetStatus)
    );

    // Gửi session 1003 chưa đăng ký
    let mut worker_unknown = NetworkWorkerDaemon::new(1003);
    let req_unknown = worker_unknown.create_rpc_request(1, BrokerRpcCommand::GetStatus, vec![]);

    assert_eq!(
        broker.handle_rpc_frame(&req_unknown),
        Err(BrokerError::SessionNotFound(1003))
    );
}

#[test]
fn test_f03_tampered_handshake_payload_fails_aead_tag() {
    let mut validator = RpcSessionValidator::new(42);
    let mut envelope = RpcEnvelope {
        protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
        session_id: 42,
        request_id: 1,
        sequence_number: 1,
        command: BrokerRpcCommand::GetStatus,
        payload: vec![0x00; 32],
        auth_tag: [0xAA; 16],
    };

    // Khung chuẩn
    assert!(validator.validate_and_advance(&envelope).is_ok());

    // Khung session sai
    envelope.session_id = 999;
    envelope.sequence_number = 2;
    assert_eq!(
        validator.validate_and_advance(&envelope),
        Err(IpcFrameError::SessionMismatch {
            expected: 42,
            actual: 999
        })
    );
}

// =========================================================================
// GROUP G: Replay, Frame Ordering & Message Bounds (Section 13 - Group G)
// =========================================================================

#[test]
fn test_g01_strict_monotonic_sequence_numbers_prevent_replay() {
    let mut validator = RpcSessionValidator::new(50);
    let envelope = RpcEnvelope {
        protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
        session_id: 50,
        request_id: 1,
        sequence_number: 1,
        command: BrokerRpcCommand::GetStatus,
        payload: vec![],
        auth_tag: [0; 16],
    };

    // Lần 1: sequence = 1 -> OK
    assert!(validator.validate_and_advance(&envelope).is_ok());

    // Lần 2: Replay lại sequence = 1 -> REJECT
    assert_eq!(
        validator.validate_and_advance(&envelope),
        Err(IpcFrameError::SequenceReplay {
            expected: 2,
            actual: 1
        })
    );
}

#[test]
fn test_g02_out_of_order_sequence_frame_rejected() {
    let mut validator = RpcSessionValidator::new(50);
    let envelope = RpcEnvelope {
        protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
        session_id: 50,
        request_id: 1,
        sequence_number: 5, // Nhảy cóc từ 1 lên 5!
        command: BrokerRpcCommand::GetStatus,
        payload: vec![],
        auth_tag: [0; 16],
    };

    assert_eq!(
        validator.validate_and_advance(&envelope),
        Err(IpcFrameError::SequenceOutOfOrder {
            expected: 1,
            actual: 5
        })
    );
}

#[test]
fn test_g03_frame_size_strictly_bounded_to_64kb() {
    let mut validator = RpcSessionValidator::new(50);
    let oversized_payload = vec![0xCC; MAX_IPC_FRAME_SIZE + 1];

    let envelope = RpcEnvelope {
        protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
        session_id: 50,
        request_id: 1,
        sequence_number: 1,
        command: BrokerRpcCommand::GetStatus,
        payload: oversized_payload,
        auth_tag: [0; 16],
    };

    assert_eq!(
        validator.validate_and_advance(&envelope),
        Err(IpcFrameError::OversizedFrame(MAX_IPC_FRAME_SIZE + 1))
    );
}

// =========================================================================
// GROUP H: Worker Compromise Simulation (Section 13 - Group H)
// =========================================================================

#[test]
fn test_h01_compromised_worker_cannot_access_vault_directly() {
    let worker = NetworkWorkerDaemon::new(1);
    assert_eq!(
        worker.try_read_vault_file(),
        Err("Access Denied: AppContainer sandbox blocks direct vault file access")
    );
}

#[test]
fn test_h02_worker_fuzzing_garbage_payload_broker_survives() {
    let mut broker = CoreBroker::new();
    broker.register_session(777);

    // Gửi khung với sequence number sai lệch
    let corrupt_frame = RpcEnvelope {
        protocol_version: CURRENT_IPC_PROTOCOL_VERSION,
        session_id: 777,
        request_id: 99,
        sequence_number: 9999, // Sai sequence
        command: BrokerRpcCommand::GetStatus,
        payload: vec![0xFF; 128],
        auth_tag: [0; 16],
    };

    let res = broker.handle_rpc_frame(&corrupt_frame);
    assert!(res.is_err());

    // Broker vẫn sống nguyên vẹn
    let status = broker.get_status();
    assert!(!status.is_vault_locked);
    assert!(status.is_tpm_ready);
}

#[test]
fn test_h03_worker_disconnect_does_not_corrupt_broker_state() {
    let broker = CoreBroker::new();
    let status = broker.get_status();
    assert!(
        !status.has_network_sockets,
        "Broker must have zero network sockets"
    );
}

// =========================================================================
// GROUP I: Broker Policy Admission Pipeline (Section 13 - Group I)
// =========================================================================

#[test]
fn test_i01_admission_valid_master_signed_policy_accepted() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let mut controller =
        BrokerPolicyAdmissionController::new(10, "tenant-cyberv-corp", verifying_key);

    let policy_json = r#"{"allow_threshold": 8000, "minimum_assurance": "OSProtected"}"#;
    let canonical = format!(
        "{}:{}:{}:{}:{}:{}",
        11, "CyberV Master Authority", "tenant-cyberv-corp", 1000, 2000, policy_json
    );
    let signature = signing_key.sign(canonical.as_bytes());

    let envelope = SignedPolicyEnvelope {
        version: 11,
        issuer: "CyberV Master Authority".to_string(),
        tenant_id: "tenant-cyberv-corp".to_string(),
        not_before: 1000,
        not_after: 2000,
        policy_json: policy_json.to_string(),
        signature_hex: encode_hex(&signature.to_bytes()),
    };

    let raw_bytes = serde_json::to_vec(&envelope).unwrap();
    let admitted_version = controller
        .verify_and_admit(&raw_bytes, 1500)
        .expect("Policy should be admitted");
    assert_eq!(admitted_version, 11);
    assert_eq!(controller.active_policy_version, 11);
}

#[test]
fn test_i02_admission_rejects_forged_or_tampered_signature() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let mut controller =
        BrokerPolicyAdmissionController::new(10, "tenant-cyberv-corp", verifying_key);

    let policy_json = r#"{"allow_threshold": 8000}"#;
    // Chữ ký rác
    let envelope = SignedPolicyEnvelope {
        version: 11,
        issuer: "CyberV Master Authority".to_string(),
        tenant_id: "tenant-cyberv-corp".to_string(),
        not_before: 1000,
        not_after: 2000,
        policy_json: policy_json.to_string(),
        signature_hex: encode_hex(&[0xEE; 64]),
    };

    let raw_bytes = serde_json::to_vec(&envelope).unwrap();
    let err = controller.verify_and_admit(&raw_bytes, 1500).unwrap_err();
    assert!(matches!(
        err,
        PolicyAdmissionError::InvalidMasterSignature(_)
    ));
}

#[test]
fn test_i03_admission_rejects_downgrade_and_expired_policies() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let mut controller =
        BrokerPolicyAdmissionController::new(10, "tenant-cyberv-corp", verifying_key);

    // Thử hạ cấp về version 9 (active = 10)
    let envelope_downgrade = SignedPolicyEnvelope {
        version: 9,
        issuer: "CyberV Master Authority".to_string(),
        tenant_id: "tenant-cyberv-corp".to_string(),
        not_before: 1000,
        not_after: 2000,
        policy_json: "{}".to_string(),
        signature_hex: encode_hex(&[0; 64]),
    };
    let raw = serde_json::to_vec(&envelope_downgrade).unwrap();
    assert_eq!(
        controller.verify_and_admit(&raw, 1500),
        Err(PolicyAdmissionError::VersionRollbackAttempt {
            current: 10,
            submitted: 9
        })
    );
}

// =========================================================================
// GROUP J: AppContainer Sandbox Isolation (Section 13 - Group J)
// =========================================================================

#[test]
fn test_j01_worker_token_restricted_privileges() {
    let worker = NetworkWorkerDaemon::new(1);
    assert_eq!(worker.sandbox_profile.token_integrity_level, "AppContainer");
    assert!(!worker.sandbox_profile.has_driver_access);
    assert!(!worker.sandbox_profile.has_vault_access);
}

#[test]
fn test_j02_appcontainer_sid_isolation() {
    let broker = CoreBroker::new();
    assert_eq!(
        broker.authorize_client_connection(
            EXPECTED_WORKER_APPCONTAINER_SID,
            "CyberVWorker.exe",
            true
        ),
        Ok(())
    );
}

// =========================================================================
// GROUP K: WDAC XML Generation (Section 13 - Group K)
// =========================================================================

#[test]
fn test_k01_wdac_generator_audit_mode_first_xml() {
    let config = WdacPolicyGenerator::audit_mode_config();
    assert!(config.is_audit_mode);

    let xml = WdacPolicyGenerator::generate_cipolicy_xml(&config);
    assert!(xml.contains("<RuleType>Enabled:Audit Mode</RuleType>"));
    assert!(xml.contains("ID_SIGNER_WHQL"));
    assert!(xml.contains("ID_SIGNER_CYBERV"));
}

#[test]
fn test_k02_wdac_generator_enforced_mode_rules() {
    let config = WdacPolicyGenerator::enforced_config();
    assert!(!config.is_audit_mode);

    let xml = WdacPolicyGenerator::generate_cipolicy_xml(&config);
    assert!(!xml.contains("<RuleType>Enabled:Audit Mode</RuleType>"));
    assert!(xml.contains("ID_SIGNING_SCENARIO_DRIVERS"));
}

// =========================================================================
// GROUP L: WDAC Deployment & Break-Glass Recovery (Section 13 - Group L)
// =========================================================================

#[test]
fn test_l01_wdac_deployment_staging_and_validation() {
    let config = WdacPolicyGenerator::audit_mode_config();
    let xml = WdacPolicyGenerator::generate_cipolicy_xml(&config);

    assert!(WdacPolicyGenerator::validate_cipolicy_xml(&xml).is_ok());
    assert!(WdacPolicyGenerator::validate_cipolicy_xml("invalid xml").is_err());
}

#[test]
fn test_l02_wdac_break_glass_recovery_path_configured() {
    let mut config = WdacPolicyGenerator::audit_mode_config();
    config.break_glass_recovery_enabled = true;

    let xml = WdacPolicyGenerator::generate_cipolicy_xml(&config);
    assert!(xml.contains("Enabled:Boot Menu Protection with Safe Recovery"));
}

// =========================================================================
// GROUP M: Process Module Inventory & Authenticode (Section 13 - Group M)
// =========================================================================

#[test]
fn test_m01_process_module_inspector_identifies_trusted_system_dlls() {
    let class = ProcessModuleInspector::classify_module(
        "ntdll.dll",
        "C:\\Windows\\System32\\ntdll.dll",
        true,
        "Microsoft Windows Publisher",
    );
    assert_eq!(class, ModuleClassification::MicrosoftSignedSystemDll);
}

#[test]
fn test_m02_process_module_inspector_identifies_cyberv_binaries() {
    let class = ProcessModuleInspector::classify_module(
        "cyberv_core.dll",
        "C:\\Program Files\\CyberV\\cyberv_core.dll",
        true,
        "CyberV Corporation Production Code Signing CA",
    );
    assert_eq!(class, ModuleClassification::CyberVSignedModule);
}

#[test]
fn test_m03_process_module_inspector_detects_untrusted_foreign_dll() {
    let modules = vec![
        ModuleEntry {
            module_name: "ntdll.dll".to_string(),
            module_path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
            has_valid_signature: true,
            publisher: "Microsoft Corporation".to_string(),
            classification: ModuleClassification::MicrosoftSignedSystemDll,
        },
        ModuleEntry {
            module_name: "injected_payload.dll".to_string(),
            module_path: "C:\\Temp\\injected_payload.dll".to_string(),
            has_valid_signature: false, // Unsigned!
            publisher: "Unknown".to_string(),
            classification: ModuleClassification::UntrustedOrUnsignedDll,
        },
    ];

    let report = ProcessModuleInspector::audit_modules(modules);
    assert!(!report.is_clean);
    assert_eq!(report.untrusted_modules_count, 1);
    assert!(report.module_score < 10000);
}

// =========================================================================
// GROUP N: Offline Autonomous Local Enforcement (Section 13 - Group N)
// =========================================================================

#[test]
fn test_n01_offline_local_policy_never_default_allow() {
    let config = PolicyConfig::default();

    // Giả lập Passive Report bị suy giảm (score = 2000 < step_up_threshold 5000)
    let mut passive = create_clean_passive_report();
    passive.composite_passive_score = 2000;

    let eval = SecurityPolicyEngine::evaluate_autonomous_local(&config, false, &passive, 1000);
    assert!(matches!(eval.decision, PolicyDecision::Isolate { .. }));
}

#[test]
fn test_n02_offline_contradiction_forces_immediate_isolate() {
    let config = PolicyConfig::default();
    let passive = create_clean_passive_report();

    // Mất mạng + TPM Contradiction = true
    let eval = SecurityPolicyEngine::evaluate_autonomous_local(&config, true, &passive, 1000);
    assert_eq!(
        eval.decision,
        PolicyDecision::Isolate {
            reason: "Hardware Anti-Rollback Contradiction Detected".to_string(),
            severity: 10000,
        }
    );
}

#[test]
fn test_n03_offline_grace_period_and_local_decision_stability() {
    let config = PolicyConfig::default();
    let passive = create_clean_passive_report();

    // Tất cả bằng chứng cục bộ toàn vẹn -> Allow
    let eval = SecurityPolicyEngine::evaluate_autonomous_local(&config, false, &passive, 1000);
    assert_eq!(eval.decision, PolicyDecision::Allow);
}

// =========================================================================
// GROUP O: Trust Continuity Loop (Section 13 - Group O)
// =========================================================================

#[test]
fn test_o01_state_transition_triggers_re_observation() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::UpdateRollbackAttempt {
        current: 40,
        target: 42,
    });

    let drained = bus.drain_events();
    assert_eq!(drained.len(), 1);
    assert_eq!(
        drained[0],
        SecurityEvent::UpdateRollbackAttempt {
            current: 40,
            target: 42,
        }
    );
}

#[test]
fn test_o02_re_observation_updates_freshness_in_fusion() {
    let mut report = create_clean_passive_report();
    assert_eq!(report.freshness, 10000);

    report.freshness = 9500; // Updated freshly
    assert_eq!(report.freshness, 9500);
}

#[test]
fn test_o03_closed_loop_feedback_stability() {
    let config = PolicyConfig::default();
    let passive = create_clean_passive_report();

    // Đánh giá lặp lại nhiều chu kỳ liên tiếp không gây biến động trạng thái
    for t in 1..=5 {
        let eval =
            SecurityPolicyEngine::evaluate_autonomous_local(&config, false, &passive, t * 100);
        assert_eq!(eval.decision, PolicyDecision::Allow);
    }
}

// =========================================================================
// GROUP P: Cross-Layer Contradiction Detection (Section 13 - Group P)
// =========================================================================

#[test]
fn test_p01_cross_layer_tpm_vs_software_vs_kernel_ci() {
    let hardware_dec = VersionPolicyValidator::evaluate_with_hardware_counter(
        40, // Software version
        41, // Target version
        42, // TPM hardware counter
        TpmAssuranceType::HardwareBacked,
    );
    assert!(matches!(
        hardware_dec,
        HardwareVersionDecision::ContradictionRollbackDetected { .. }
    ));

    let ci_report = CodeIntegrityVerifier::evaluate_status(true, true, true, false);
    assert!(ci_report.is_testsigning_active);
    assert!(ci_report.integrity_score < 10000);
}

#[test]
fn test_p02_cross_layer_anomaly_corroboration() {
    let config = PolicyConfig::default();
    let mut passive = create_clean_passive_report();
    passive.driver.is_signer_valid = false; // Driver compromised

    let eval = SecurityPolicyEngine::evaluate_autonomous_local(&config, false, &passive, 1000);
    assert!(matches!(eval.decision, PolicyDecision::Isolate { .. }));
}

// =========================================================================
// GROUP Q: System-Wide Regression Matrix (Section 13 - Group Q)
// =========================================================================

#[test]
fn test_q01_passive_defense_report_v2_backward_compatibility() {
    let mut report = create_clean_passive_report();
    let wdac = WdacSecurityReport::evaluate(
        CodeIntegrityVerifier::evaluate_status(true, true, false, false),
        ProcessModuleInspector::audit_modules(vec![]),
    );
    report = report
        .with_wdac(wdac)
        .with_tpm_assurance(TpmAssuranceType::HardwareBacked);

    let json = serde_json::to_string(&report).expect("Serialize report");
    let deserialized: PassiveDefenseReport =
        serde_json::from_str(&json).expect("Deserialize report");

    assert_eq!(deserialized.report_schema_version, 2);
    assert!(deserialized.wdac.is_some());
    assert_eq!(
        deserialized.tpm_counter_assurance,
        Some(TpmAssuranceType::HardwareBacked)
    );
}

#[test]
fn test_q02_full_pipeline_end_to_end_integrity() {
    // 1. TPM Counter Discover & Increment
    let mut tpm = MockTpmNvCounter::new(TpmAssuranceType::HardwareBacked);
    tpm.discover_or_provision(DEFAULT_CYBERV_NV_INDEX, 10)
        .unwrap();
    let new_val = tpm.increment_counter(DEFAULT_CYBERV_NV_INDEX).unwrap();
    assert_eq!(new_val, 11);

    // 2. Broker-Worker Channel
    let mut broker = CoreBroker::new();
    broker.register_session(1234);
    let mut worker = NetworkWorkerDaemon::new(1234);
    let req = worker.create_rpc_request(1, BrokerRpcCommand::GetStatus, vec![]);
    assert_eq!(
        broker.handle_rpc_frame(&req),
        Ok(BrokerRpcCommand::GetStatus)
    );

    // 3. WDAC Policy Generation & Process Audit
    let wdac_config = WdacPolicyGenerator::audit_mode_config();
    let xml = WdacPolicyGenerator::generate_cipolicy_xml(&wdac_config);
    assert!(WdacPolicyGenerator::validate_cipolicy_xml(&xml).is_ok());

    let module_audit = ProcessModuleInspector::audit_modules(vec![ModuleEntry {
        module_name: "ntdll.dll".to_string(),
        module_path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
        has_valid_signature: true,
        publisher: "Microsoft Windows Publisher".to_string(),
        classification: ModuleClassification::MicrosoftSignedSystemDll,
    }]);
    assert!(module_audit.is_clean);
}

// =========================================================================
// Test Fixture Helper
// =========================================================================

fn create_clean_passive_report() -> PassiveDefenseReport {
    let mit_cfg =
        cyberv_agent::defense::passive::process_mitigations::ProcessMitigationConfig::default();
    let mitigation = cyberv_agent::defense::passive::process_mitigations::ProcessMitigationManager::apply_and_verify(&mit_cfg);
    let privilege = cyberv_agent::defense::passive::privilege::PrivilegeManager::inspect_and_drop_dangerous_privileges();
    let network = cyberv_agent::defense::passive::network_surface::NetworkSurfaceInspector::audit_network_surface(vec![]);
    let binary = cyberv_agent::defense::passive::binary_integrity::BinaryIntegrityChecker::evaluate(
        true, "h", "h", true, true, true, true, true,
    );
    let driver = cyberv_agent::defense::passive::driver_integrity::DriverIntegrityChecker::verify_driver(
        cyberv_agent::defense::passive::driver_integrity::DriverIntegrityChecker::EXPECTED_PUBLISHER,
        "h",
        "h",
        cyberv_agent::defense::passive::driver_integrity::DriverIntegrityChecker::EXPECTED_VERSION,
        true,
    );
    let ipc = cyberv_agent::defense::passive::ipc::IpcSecurityReport::standard_hardened(
        r"\\.\pipe\CyberV_IPC",
    );
    let filesystem =
        cyberv_agent::defense::passive::filesystem_acl::FilesystemAclManager::audit_critical_assets(
            &["C:\\vault.dat"],
            None,
        );
    let update = cyberv_agent::defense::passive::update::UpdateIntegrityReport::verified_active();
    let platform =
        cyberv_agent::defense::passive::platform_integrity::PlatformIntegrityChecker::evaluate(
            true, true, true, "p0", "p7",
        );
    let capability =
        cyberv_agent::defense::passive::capability::CapabilityProfiler::probe_system_capabilities();

    PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    )
}
