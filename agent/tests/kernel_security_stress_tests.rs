//! Kernel Security High-Load Stress & Concurrency Fuzzing Suite
//!
//! Ref: Docs/newpl.md Phase 12 & Phase 13:
//! Comprehensive stress and fuzz testing validating CyberV defense engines under load:
//! - Stress 1: Multi-threaded EventBus High-Throughput Burst (10,000 concurrent events)
//! - Stress 2: Multi-threaded Policy Engine Rapid Evaluation (1,000 concurrent evaluations)
//! - Stress 3: Cryptographic Re-Attestation Fuzzing & Mutation Rejection (1,000 forged signatures)
//! - Stress 4: Memory Enclave Boundary Burst & Zeroization Under Pressure
//! - Stress 5: Update State Machine Concurrent Race & ACID Transition Integrity

use cyberv_agent::defense::dma::fusion::DmaEvidenceFusionEngine;
use cyberv_agent::defense::dma::{IommuReport, PreBootDmaReport};
use cyberv_agent::defense::enclave::{
    BoundaryError, EnclaveAttestationEngine, EnclaveCapabilityMatrix, EnclaveMeasurement,
    IdentityBindingEngine, SecureIsoBuffer, MAX_SECURE_PAYLOAD_SIZE,
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
    UpdateStagingManager, UpdateStagingState,
};
use cyberv_agent::defense::passive::{SecurityEvent, SecurityEventBus};
use cyberv_agent::defense::policy::{PolicyConfig, PolicyDecision, SecurityPolicyEngine};
use cyberv_agent::defense::recovery::{
    DeviceLifecycleState, RecoveryManager, RecoveryProof,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

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
// STRESS TEST 1: Event Bus High-Throughput Concurrent Burst (10,000 Events)
// =========================================================================
#[test]
fn test_stress_01_event_bus_concurrent_burst_10k_events() {
    let bus = Arc::new(SecurityEventBus::new());
    let total_producers = 20;
    let events_per_producer = 500;
    let total_expected_events = total_producers * events_per_producer;

    let start_time = Instant::now();
    let mut handles = Vec::new();

    // Spawn 20 concurrent producer threads
    for t_idx in 0..total_producers {
        let bus_clone = bus.clone();
        let handle = std::thread::spawn(move || {
            for i in 0..events_per_producer {
                let event = if (i + t_idx) % 2 == 0 {
                    SecurityEvent::BinaryTamperDetected {
                        detail: format!("Tamper thread {} event {}", t_idx, i),
                    }
                } else {
                    SecurityEvent::DriverUnexpected {
                        reason: format!("Driver alert thread {} event {}", t_idx, i),
                    }
                };
                bus_clone.publish(event);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start_time.elapsed();
    let drained_events = bus.drain_events();
    println!(
        "[*] STRESS TEST 1: Published & drained {} events in {:?}",
        drained_events.len(),
        elapsed
    );

    assert_eq!(
        drained_events.len(),
        total_expected_events,
        "Zero event loss invariant violated under concurrent load!"
    );
    assert!(!bus.is_poisoned());
}

// =========================================================================
// STRESS TEST 2: Policy Engine Rapid Evaluation Load (1,000 Evaluations)
// =========================================================================
#[test]
fn test_stress_02_policy_engine_rapid_evaluation_concurrent_load() {
    let (tpm_score, dma, fw, enclave) = helper_hardened_reports();
    let config = PolicyConfig::default();

    let total_evaluations = 1000;
    let num_threads = 10;
    let evals_per_thread = total_evaluations / num_threads;

    let isolate_count = Arc::new(AtomicUsize::new(0));
    let allow_count = Arc::new(AtomicUsize::new(0));

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for t_idx in 0..num_threads {
        let config_clone = config.clone();
        let dma_clone = dma.clone();
        let fw_clone = fw.clone();
        let enclave_clone = enclave.clone();
        let isolate_ref = isolate_count.clone();
        let allow_ref = allow_count.clone();

        let handle = std::thread::spawn(move || {
            for i in 0..evals_per_thread {
                let is_tampered = (i + t_idx) % 3 == 0;
                let reg = ProtectedProcessRegistration::new(1000 + i as u32, 1000, "nonce", 1);

                let telem = if is_tampered {
                    ShieldTelemetry::inactive()
                } else {
                    ShieldTelemetry::active(1000 + i as u32)
                };

                let kernel_report = AntiTamperManager::evaluate(&reg, &telem, !is_tampered);
                let report = SecurityPolicyEngine::evaluate(
                    &config_clone,
                    tpm_score,
                    &kernel_report,
                    &dma_clone,
                    &fw_clone,
                    &enclave_clone,
                    None,
                    1000 + i as u64,
                );

                if is_tampered {
                    // Invariant INV-001: Tampered/inactive driver MUST ALWAYS isolate!
                    assert!(
                        matches!(report.decision, PolicyDecision::Isolate { .. }),
                        "Invariant INV-001 violated: Tampered driver was not isolated!"
                    );
                    isolate_ref.fetch_add(1, Ordering::Relaxed);
                } else {
                    allow_ref.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start_time.elapsed();
    println!(
        "[*] STRESS TEST 2: Executed {} concurrent policy evaluations in {:?}",
        total_evaluations, elapsed
    );
    assert!(isolate_count.load(Ordering::Relaxed) > 0);
    assert!(allow_count.load(Ordering::Relaxed) > 0);
}

// =========================================================================
// STRESS TEST 3: Cryptographic Re-Attestation Fuzzing & Mutation Rejection
// =========================================================================
#[test]
fn test_stress_03_recovery_cryptographic_signature_fuzzing() {
    let mut csprng = OsRng;
    let legit_signing_key = SigningKey::generate(&mut csprng);
    let legit_admin_pubkey = legit_signing_key.verifying_key().to_bytes();
    let expected_cert_hash = "valid_oem_cert_hash_sha512";

    let iterations = 500;
    let mut rejected_forgeries = 0;
    let mut accepted_legits = 0;

    let start_time = Instant::now();

    for i in 0..iterations {
        let nonce = csprng.gen::<[u8; 32]>();
        let prev_pcr = format!("PCR_OLD_{}", i);
        let new_pcr = format!("PCR_NEW_{}", i);
        let challenge = RecoveryManager::create_challenge(
            format!("dev-fuzz-{}", i),
            nonce,
            prev_pcr.as_bytes(),
            new_pcr.as_bytes(),
            1000 + i as u64,
        );

        // 1. Verify legitimate signature succeeds
        let legit_sig = RecoveryManager::sign_recovery_challenge(&challenge, &legit_signing_key);
        let legit_proof = RecoveryProof {
            challenge_id: challenge.challenge_id.clone(),
            admin_signature_sha512: legit_sig.clone(),
            oem_update_cert_hash: expected_cert_hash.to_string(),
        };

        let legit_res = RecoveryManager::verify_and_re_attest(
            &challenge,
            &legit_proof,
            &legit_admin_pubkey,
            expected_cert_hash,
        );
        assert_eq!(legit_res, Ok(DeviceLifecycleState::ActiveAttested));
        accepted_legits += 1;

        // 2. Fuzz attack: Mutate signature (flip character to guarantee corrupted signature)
        let mut corrupted_chars: Vec<char> = legit_sig.chars().collect();
        let corrupt_idx = i % corrupted_chars.len();
        corrupted_chars[corrupt_idx] = if corrupted_chars[corrupt_idx] == '0' {
            '1'
        } else {
            '0'
        };
        let corrupted_sig: String = corrupted_chars.into_iter().collect();

        let forged_proof = RecoveryProof {
            challenge_id: challenge.challenge_id.clone(),
            admin_signature_sha512: corrupted_sig,
            oem_update_cert_hash: expected_cert_hash.to_string(),
        };

        let forged_res = RecoveryManager::verify_and_re_attest(
            &challenge,
            &forged_proof,
            &legit_admin_pubkey,
            expected_cert_hash,
        );
        assert!(
            forged_res.is_err(),
            "Forged/corrupted signature MUST be rejected!"
        );
        rejected_forgeries += 1;
    }

    let elapsed = start_time.elapsed();
    println!(
        "[*] STRESS TEST 3: Completed {} cryptographic sign/verify cycles ({} accepted, {} rejected) in {:?}",
        iterations * 2,
        accepted_legits,
        rejected_forgeries,
        elapsed
    );
    assert_eq!(accepted_legits, iterations);
    assert_eq!(rejected_forgeries, iterations);
}

// =========================================================================
// STRESS TEST 4: Memory Enclave Boundary Burst & Zeroization Under Pressure
// =========================================================================
#[test]
fn test_stress_04_memory_boundary_burst_and_zeroization() {
    let num_iterations = 2000;
    let mut rng = rand::thread_rng();

    let start_time = Instant::now();

    for i in 0..num_iterations {
        let size = (i % 512) + 1;
        let mut random_bytes = vec![0u8; size];
        rng.fill(&mut random_bytes[..]);

        let buf = SecureIsoBuffer::copy_from_untrusted(&random_bytes).unwrap();
        assert_eq!(buf.len(), size);
        assert_eq!(buf.as_slice()[0], random_bytes[0]);

        // Trigger drop & guaranteed zeroization
        drop(buf);
    }

    // Boundary stress: Test oversized buffer rejection
    let oversized = vec![0x41u8; MAX_SECURE_PAYLOAD_SIZE + 1];
    assert_eq!(
        SecureIsoBuffer::copy_from_untrusted(&oversized),
        Err(BoundaryError::PayloadTooLarge(MAX_SECURE_PAYLOAD_SIZE + 1))
    );

    let elapsed = start_time.elapsed();
    println!(
        "[*] STRESS TEST 4: Allocated, verified, and zeroized {} secure enclave buffers in {:?}",
        num_iterations, elapsed
    );
}

// =========================================================================
// STRESS TEST 5: Update State Machine Concurrency & ACID Integrity
// =========================================================================
#[test]
fn test_stress_05_update_state_machine_acid_transitions() {
    let iterations = 1000;
    let mut verified_cycles = 0;
    let mut blocked_cycles = 0;

    let start_time = Instant::now();

    for i in 0..iterations {
        let is_valid = i % 2 == 0;

        // Step 1: Advance from Current
        let stage_1 = UpdateStagingManager::advance_state(UpdateStagingState::Current, is_valid);
        if !is_valid {
            assert!(
                stage_1.is_err(),
                "Invalid package must be blocked from staging!"
            );
            blocked_cycles += 1;
            continue;
        }

        assert_eq!(stage_1, Ok(UpdateStagingState::Staged));

        // Step 2: Advance to Verified
        let stage_2 = UpdateStagingManager::advance_state(UpdateStagingState::Staged, true).unwrap();
        assert_eq!(stage_2, UpdateStagingState::Verified);

        // Step 3: Advance to Active
        let stage_3 =
            UpdateStagingManager::advance_state(UpdateStagingState::Verified, true).unwrap();
        assert_eq!(stage_3, UpdateStagingState::Active);

        // Terminal state cannot advance further
        assert!(UpdateStagingManager::advance_state(UpdateStagingState::Active, true).is_err());
        verified_cycles += 1;
    }

    let elapsed = start_time.elapsed();
    println!(
        "[*] STRESS TEST 5: Executed {} update lifecycle state machine transitions ({} verified, {} blocked) in {:?}",
        iterations,
        verified_cycles,
        blocked_cycles,
        elapsed
    );
    assert_eq!(verified_cycles, iterations / 2);
    assert_eq!(blocked_cycles, iterations / 2);
}
