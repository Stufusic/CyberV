//! CyberV Phase 5 Risk Engine & Decision Matrix Tests
//!
//! Ref: Pipeline.md Section 29, Plan.md Section 19, Rule.md Điều 2, 4, 15, 17:
//! "Không dùng một tỷ lệ similarity duy nhất để ra quyết định...
//! Tính điểm số nguyên 0-10000, không dùng float...
//! Phân định rạch ròi AutoPromote vs RequiresUserApproval vs Rejected.
//! Re-enrollment Request có chữ ký Ed25519 của stable device identity...
//! Chống Rollback Attack và Cross-Purpose Attack."

use cyberv_agent::fingerprint::component_hasher::hash_snapshot;
use cyberv_agent::fingerprint::graph::builder::build_evidence_graph;
use cyberv_agent::fingerprint::graph::diff::diff_evidence_graphs;
use cyberv_agent::fingerprint::graph::models::{DeviceEvidenceGraph, VirtualPoint};
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::models::{ComponentType, HardwareSnapshot, NormalizedComponent};
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::protocol::challenge::{create_challenge_proof, ChallengeObject};
use cyberv_agent::protocol::constants::PURPOSE_DEVICE_AUTH;
use cyberv_agent::protocol::reenroll::{
    create_reenrollment_request, verify_reenrollment_request, ReenrollmentRequest,
};
use cyberv_agent::risk::engine::{
    evaluate_risk, PENALTY_CPU_MUTATION, PENALTY_MOTHERBOARD_MUTATION, PENALTY_PARTIAL_STATUS,
    PENALTY_RAM_MUTATION, PENALTY_ROLLBACK, PENALTY_STORAGE_MUTATION, PENALTY_VERSION_JUMP,
};
use cyberv_agent::risk::models::{PolicyDecision, RiskLevel};

/// Helper: Builds an evidence graph from a snapshot and graph version
fn build_graph(snapshot: &HardwareSnapshot, version: u32) -> DeviceEvidenceGraph {
    let hashed = hash_snapshot(snapshot);
    build_evidence_graph(&hashed, version)
}

/// Helper: Clones baseline snapshot and mutates the CPU attributes
fn create_cpu_swapped_snapshot() -> HardwareSnapshot {
    let collector = MockHardwareCollector::baseline().expect("Baseline collector failed");
    let mut snapshot = collector.collect().expect("Collect failed");
    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Cpu {
            comp.canonical_id = "cpu:amd:amd ryzen 9 7950x".to_string();
            comp.attributes
                .insert("model".to_string(), "amd ryzen 9 7950x".to_string());
            comp.attributes
                .insert("vendor".to_string(), "amd".to_string());
            comp.attributes
                .insert("processor_id".to_string(), "178bfbff00a60f12".to_string());
        }
    }
    snapshot
}

/// Helper: Clones baseline snapshot and mutates the Motherboard attributes
fn create_board_swapped_snapshot() -> HardwareSnapshot {
    let collector = MockHardwareCollector::baseline().expect("Baseline collector failed");
    let mut snapshot = collector.collect().expect("Collect failed");
    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Motherboard {
            comp.canonical_id = "board:msi:mpg z790 carbon wifi".to_string();
            comp.attributes
                .insert("model".to_string(), "mpg z790 carbon wifi".to_string());
            comp.attributes
                .insert("manufacturer".to_string(), "msi".to_string());
            comp.attributes
                .insert("serial".to_string(), "msi-999-swapped".to_string());
        }
    }
    snapshot
}

/// Helper: Clones baseline snapshot and mutates both RAM and Disk
fn create_ram_and_disk_mutated_snapshot() -> HardwareSnapshot {
    let ram_collector = MockHardwareCollector::ram_upgrade().expect("RAM upgrade collector failed");
    let ram_snapshot = ram_collector.collect().expect("Collect failed");

    let disk_collector =
        MockHardwareCollector::disk_replace().expect("Disk replace collector failed");
    let disk_snapshot = disk_collector.collect().expect("Collect failed");

    let mut combined_components: Vec<NormalizedComponent> = Vec::new();
    // Keep CPU and Board from RAM snapshot
    for comp in ram_snapshot.components {
        if comp.component_type != ComponentType::Storage {
            combined_components.push(comp);
        }
    }
    // Take Disks from Disk Replace snapshot
    for comp in disk_snapshot.components {
        if comp.component_type == ComponentType::Storage {
            combined_components.push(comp);
        }
    }

    HardwareSnapshot::new(combined_components, "1.0.0-mock")
}

// ====================================================================
// Group 1: Component Mutation Scoring Tests
// ====================================================================

#[test]
fn test_01_identical_baseline_produces_zero_risk_and_trusted() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let g1 = build_graph(&snapshot, 1);
    let g2 = build_graph(&snapshot, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert_eq!(assessment.score, 0);
    assert_eq!(assessment.level, RiskLevel::Low);
    assert_eq!(assessment.decision, PolicyDecision::Trusted);
    assert!(assessment.signals.is_empty());
}

#[test]
fn test_02_ram_upgrade_produces_auto_promote() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = MockHardwareCollector::ram_upgrade()
        .unwrap()
        .collect()
        .unwrap();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert_eq!(assessment.score, PENALTY_RAM_MUTATION); // 1500
    assert_eq!(assessment.level, RiskLevel::Medium);
    assert_eq!(assessment.decision, PolicyDecision::AutoPromote);
    assert_eq!(assessment.breakdown.get("ram_mutation"), Some(&1500));
}

#[test]
fn test_03_disk_replace_produces_auto_promote() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = MockHardwareCollector::disk_replace()
        .unwrap()
        .collect()
        .unwrap();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert_eq!(assessment.score, PENALTY_STORAGE_MUTATION); // 2500
    assert_eq!(assessment.level, RiskLevel::Medium);
    assert_eq!(assessment.decision, PolicyDecision::AutoPromote);
    assert_eq!(assessment.breakdown.get("storage_mutation"), Some(&2500));
}

#[test]
fn test_04_combined_ram_and_disk_requires_user_approval() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = create_ram_and_disk_mutated_snapshot();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    // RAM (1500) + Storage (2500) = 4000
    assert_eq!(
        assessment.score,
        PENALTY_RAM_MUTATION + PENALTY_STORAGE_MUTATION
    );
    assert_eq!(assessment.score, 4000);
    assert_eq!(assessment.level, RiskLevel::High);
    // Score 4000 > 3000 threshold -> RequiresUserApproval
    assert_eq!(assessment.decision, PolicyDecision::RequiresUserApproval);
}

#[test]
fn test_05_cpu_swap_requires_user_approval() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = create_cpu_swapped_snapshot();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert_eq!(assessment.score, PENALTY_CPU_MUTATION); // 4000
    assert_eq!(assessment.level, RiskLevel::High);
    // CPU mutation explicitly blocks AutoPromote
    assert_eq!(assessment.decision, PolicyDecision::RequiresUserApproval);
    assert_eq!(assessment.breakdown.get("cpu_mutation"), Some(&4000));
}

#[test]
fn test_06_motherboard_swap_requires_user_approval() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = create_board_swapped_snapshot();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert_eq!(assessment.score, PENALTY_MOTHERBOARD_MUTATION); // 5500
    assert_eq!(assessment.level, RiskLevel::High);
    assert_eq!(assessment.decision, PolicyDecision::RequiresUserApproval);
    assert_eq!(assessment.breakdown.get("board_mutation"), Some(&5500));
}

// ====================================================================
// Group 2: Invariants & Rollback Protection Tests
// ====================================================================

#[test]
fn test_07_board_and_cpu_swap_rejected() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let mut snap2 = create_board_swapped_snapshot();
    // Also mutate CPU in snap2
    for comp in &mut snap2.components {
        if comp.component_type == ComponentType::Cpu {
            comp.canonical_id = "cpu:amd:swapped".to_string();
            comp.attributes
                .insert("processor_id".to_string(), "amd-swap-cpu".to_string());
        }
    }

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    // Board (5500) + CPU (4000) = 9500
    assert_eq!(
        assessment.score,
        PENALTY_MOTHERBOARD_MUTATION + PENALTY_CPU_MUTATION
    );
    assert_eq!(assessment.score, 9500);
    assert_eq!(assessment.level, RiskLevel::Critical);
    // Dual core swap -> Strict Reject
    assert_eq!(assessment.decision, PolicyDecision::Rejected);
}

#[test]
fn test_08_board_and_storage_swap_rejected() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let mut snap2 = create_board_swapped_snapshot();
    // Also mutate Storage in snap2
    for comp in &mut snap2.components {
        if comp.component_type == ComponentType::Storage {
            comp.canonical_id = "disk:kingston:swapped-ssd".to_string();
            comp.attributes
                .insert("serial".to_string(), "disk-swap-999".to_string());
        }
    }

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    // Board (5500) + Storage (2500) = 8000
    assert_eq!(
        assessment.score,
        PENALTY_MOTHERBOARD_MUTATION + PENALTY_STORAGE_MUTATION
    );
    assert_eq!(assessment.score, 8000);
    assert_eq!(assessment.level, RiskLevel::Critical);
    // Motherboard + Storage swap -> Strict Reject
    assert_eq!(assessment.decision, PolicyDecision::Rejected);
}

#[test]
fn test_09_rollback_attack_rejected_with_maximum_penalty() {
    let snap = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let g1 = build_graph(&snap, 2);
    let g2 = build_graph(&snap, 1); // Attempting to rollback version 2 -> 1

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 2, 1);

    assert_eq!(assessment.score, PENALTY_ROLLBACK); // 10000
    assert_eq!(assessment.level, RiskLevel::Critical);
    assert_eq!(assessment.decision, PolicyDecision::Rejected);
    assert!(assessment
        .signals
        .iter()
        .any(|s| s.code == "ROLLBACK_ATTACK_DETECTED"));
}

#[test]
fn test_10_version_jump_anomaly_penalty() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = MockHardwareCollector::ram_upgrade()
        .unwrap()
        .collect()
        .unwrap();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 3); // Jump from v1 to v3 (gap > 1)

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 3);

    // RAM (1500) + Version Jump (1000) = 2500
    assert_eq!(
        assessment.score,
        PENALTY_RAM_MUTATION + PENALTY_VERSION_JUMP
    );
    assert_eq!(assessment.score, 2500);
    assert!(assessment
        .signals
        .iter()
        .any(|s| s.code == "VERSION_JUMP_ANOMALY"));
}

// ====================================================================
// Group 3: Observation Integrity & Virtual Points Tests
// ====================================================================

#[test]
fn test_11_partial_hardware_status_penalty() {
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = MockHardwareCollector::incomplete_wmi()
        .unwrap()
        .collect()
        .unwrap();

    let g1 = build_graph(&snap1, 1);
    let g2 = build_graph(&snap2, 2);

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert!(assessment.breakdown.contains_key("partial_attributes"));
    assert_eq!(
        assessment.breakdown.get("partial_attributes"),
        Some(&PENALTY_PARTIAL_STATUS)
    );
}

#[test]
fn test_12_virtual_point_degradation_penalty() {
    let snap = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let g1 = build_graph(&snap, 1);
    let mut g2 = build_graph(&snap, 2);

    // Artificially degrade an existing virtual point in g2: ratio drops from 10000 to 5000
    g2.virtual_points = vec![VirtualPoint::new(
        "point:platform_consistency",
        5000,
        10000,
        1,
    )];

    let diff = diff_evidence_graphs(&g1, &g2);
    let assessment = evaluate_risk(&diff, &g1, &g2, 1, 2);

    assert!(assessment
        .signals
        .iter()
        .any(|s| s.code.starts_with("POINT_DEGRADATION_")));
    assert!(assessment.score >= 5000);
}

// ====================================================================
// Group 4: Re-enrollment Signatures & Purpose Separation Tests
// ====================================================================

#[test]
fn test_13_reenrollment_request_creation_and_verification() {
    let mut rng = OsCryptoRng;
    let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-00123";
    let prev_state = "a".repeat(128);
    let new_state = "b".repeat(128);
    let new_graph_hash = "c".repeat(128);
    let new_version = 2;
    let reason = "RAM Upgrade from 32GB to 64GB";

    let req = create_reenrollment_request(
        &identity_key,
        device_id,
        &prev_state,
        &new_state,
        &new_graph_hash,
        new_version,
        reason,
    )
    .expect("Create reenrollment request failed");

    assert_eq!(req.device_id, device_id);
    assert_eq!(req.proof_signature.len(), 128);

    // Verification must succeed with the true verifying key
    let result = verify_reenrollment_request(identity_key.verifying_key(), &req);
    assert!(result.is_ok(), "Verification should pass for authentic key");
}

#[test]
fn test_14_reenrollment_tampered_payload_fails_verification() {
    let mut rng = OsCryptoRng;
    let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-00123";
    let prev_state = "a".repeat(128);
    let new_state = "b".repeat(128);
    let new_graph_hash = "c".repeat(128);

    let req = create_reenrollment_request(
        &identity_key,
        device_id,
        &prev_state,
        &new_state,
        &new_graph_hash,
        2,
        "Original Reason",
    )
    .expect("Create request failed");

    // Case 1: Tampered reason
    let mut tampered_reason = req.clone();
    tampered_reason.reason = "Tampered Reason".to_string();
    assert!(
        verify_reenrollment_request(identity_key.verifying_key(), &tampered_reason).is_err(),
        "Tampered reason must fail verification"
    );

    // Case 2: Tampered version
    let mut tampered_version = req.clone();
    tampered_version.new_graph_version = 3;
    assert!(
        verify_reenrollment_request(identity_key.verifying_key(), &tampered_version).is_err(),
        "Tampered version must fail verification"
    );

    // Case 3: Tampered signature
    let mut tampered_sig = req;
    let mut corrupted = tampered_sig.proof_signature.into_bytes();
    corrupted[0] = if corrupted[0] == b'a' { b'b' } else { b'a' };
    tampered_sig.proof_signature = String::from_utf8(corrupted).unwrap();
    assert!(
        verify_reenrollment_request(identity_key.verifying_key(), &tampered_sig).is_err(),
        "Corrupted signature must fail verification"
    );
}

#[test]
fn test_15_cross_purpose_and_domain_separation_attack_rejected() {
    let mut rng = OsCryptoRng;
    let identity_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-00123";
    let state_hash = "f".repeat(128);

    let challenge = ChallengeObject {
        challenge_id: "chal-9999".to_string(),
        nonce: "nonce-123456".to_string(),
        device_id: device_id.to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1000,
        expires_at: 2000,
    };

    // Generate challenge proof intended for PURPOSE_DEVICE_AUTH
    let chal_proof = create_challenge_proof(&identity_key, &challenge, &state_hash, 1)
        .expect("Create challenge proof failed");

    // Attempt Cross-Purpose Attack: Try to use the challenge response signature
    // as a re-enrollment request signature!
    let forged_reenroll_request = ReenrollmentRequest {
        device_id: device_id.to_string(),
        previous_state_hash: state_hash.clone(),
        new_state_hash: "0".repeat(128),
        new_graph_hash: "1".repeat(128),
        new_graph_version: 2,
        reason: "Malicious reenrollment with stolen auth signature".to_string(),
        proof_signature: chal_proof.signature_hex, // Stolen signature from device-auth!
    };

    // Verification must strictly fail because DOMAIN_AUTH != DOMAIN_REENROLL
    // and the canonical byte payload construction differs.
    let verify_result =
        verify_reenrollment_request(identity_key.verifying_key(), &forged_reenroll_request);
    assert!(
        verify_result.is_err(),
        "Cross-purpose substitution attack MUST be rejected by domain separation"
    );
}
