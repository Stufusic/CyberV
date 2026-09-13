//! CyberV Phase 15: Zero-Knowledge Device Attestation & Privacy Layer Tests (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7:
//! Privacy-Preserving Proofs, Public Statement, Private Witness, Constraint Circuit,
//! ZK Prover & Verifier, Anti-Replay Nonce, Selective Disclosure.

use cyberv_agent::evidence::constraints::PhysicalConstraintEngine;
use cyberv_agent::evidence::merkle::proof::generate_inclusion_proof;
use cyberv_agent::evidence::merkle::tree::MerkleEvidenceTree;
use cyberv_agent::evidence::topology::HardwareTopologyEngine;
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::privacy::{
    CircuitError, DevicePolicy, DisclosedAttribute, HardwareLeafWitness, HardwareWitness,
    NonceTracker, SelectiveDisclosureClaim, SelectiveDisclosureEngine, SelectiveDisclosureError,
    VerifierError, ZkProver, ZkVerifier, CIRCUIT_VERSION,
};

/// Helper tạo Merkle tree chuẩn từ Mock Baseline
fn create_test_merkle_tree() -> (MerkleEvidenceTree, String) {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let constraint_report = PhysicalConstraintEngine::new().evaluate(&snapshot);
    let topology_report = HardwareTopologyEngine::new().build_topology(&snapshot);

    let tree = MerkleEvidenceTree::build(&snapshot, &constraint_report, &topology_report);
    let root_hex = tree.root_hash_hex();
    (tree, root_hex)
}

fn create_valid_witness(tree: &MerkleEvidenceTree) -> (HardwareWitness, String) {
    let root_hex = tree.root.hash_hex();
    // Lấy một leaf từ cây, ví dụ CPU
    let cpu_leaf_label = "comp:cpu:intel:intel core i7-13700k";
    let cpu_proof = generate_inclusion_proof(&tree.root, cpu_leaf_label)
        .expect("Phải sinh được inclusion proof cho CPU leaf");

    let leaf_witness = HardwareLeafWitness {
        label: cpu_leaf_label.to_string(),
        canonical_id: "cpu:intel:intel core i7-13700k".to_string(),
        leaf_hash_hex: cpu_proof.leaf_hash_hex.clone(),
        proof: cpu_proof,
    };

    let witness = HardwareWitness::new(
        vec![leaf_witness],
        true,                              // tpm_active
        true,                              // kernel_consistent
        "6",                               // cpu_family
        34359738368,                       // 32 GB RAM
        "salt_blinding_secret_9876543210", // blinding_factor
    );

    (witness, root_hex)
}

#[test]
fn test_01_valid_zk_proof_generation_and_verification() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "challenge_nonce_abc123";

    // Prover tạo ZK proof
    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION)
        .expect("Tạo ZK proof thành công");

    assert_eq!(proof.circuit_version, CIRCUIT_VERSION);
    assert_eq!(proof.public_root, root_hex);
    assert_eq!(proof.policy_id, policy.policy_id);
    assert_eq!(proof.nonce, nonce);
    assert_eq!(proof.proof_commitment.len(), 128); // SHA-512 hex

    // Verifier kiểm tra proof
    let mut tracker = NonceTracker::new();
    let verified = ZkVerifier::verify(&proof, &root_hex, &policy, nonce, &mut tracker)
        .expect("Xác minh ZK proof thành công");
    assert!(verified);
}

#[test]
fn test_02_invalid_proof_commitment_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_1";

    let mut proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();
    // Giả mạo cam kết proof
    proof.proof_commitment = "0".repeat(128);

    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &root_hex, &policy, nonce, &mut tracker);
    assert_eq!(result.unwrap_err(), VerifierError::CorruptedProof);
}

#[test]
fn test_03_wrong_root_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_2";

    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();

    let wrong_root = "f".repeat(128);
    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &wrong_root, &policy, nonce, &mut tracker);

    match result.unwrap_err() {
        VerifierError::RootMismatch { expected_root, .. } => {
            assert_eq!(expected_root, wrong_root);
        }
        e => panic!("Kỳ vọng RootMismatch, nhận được: {:?}", e),
    }
}

#[test]
fn test_04_wrong_policy_id_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_3";

    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();

    let mut wrong_policy = policy.clone();
    wrong_policy.policy_id = "pol:wrong_policy_id".to_string();

    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &root_hex, &wrong_policy, nonce, &mut tracker);

    match result.unwrap_err() {
        VerifierError::PolicyMismatch {
            expected_policy, ..
        } => {
            assert_eq!(expected_policy, "pol:wrong_policy_id");
        }
        e => panic!("Kỳ vọng PolicyMismatch, nhận được: {:?}", e),
    }
}

#[test]
fn test_05_wrong_policy_version_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_4";

    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();

    let mut wrong_policy = policy.clone();
    wrong_policy.version = 99;

    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &root_hex, &wrong_policy, nonce, &mut tracker);

    match result.unwrap_err() {
        VerifierError::PolicyMismatch {
            expected_version, ..
        } => {
            assert_eq!(expected_version, 99);
        }
        e => panic!("Kỳ vọng PolicyMismatch, nhận được: {:?}", e),
    }
}

#[test]
fn test_06_wrong_nonce_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "correct_nonce";

    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();

    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &root_hex, &policy, "different_nonce", &mut tracker);

    match result.unwrap_err() {
        VerifierError::NonceMismatch { expected_nonce, .. } => {
            assert_eq!(expected_nonce, "different_nonce");
        }
        e => panic!("Kỳ vọng NonceMismatch, nhận được: {:?}", e),
    }
}

#[test]
fn test_07_proof_replay_attack_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "replay_target_nonce";

    let proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();

    let mut tracker = NonceTracker::new();
    // Lần 1: Thành công
    assert!(ZkVerifier::verify(&proof, &root_hex, &policy, nonce, &mut tracker).unwrap());

    // Lần 2: Tấn công phát lại cùng một proof và nonce -> Phải bị từ chối
    let result = ZkVerifier::verify(&proof, &root_hex, &policy, nonce, &mut tracker);
    assert_eq!(
        result.unwrap_err(),
        VerifierError::NonceReplayed(nonce.to_string())
    );
}

#[test]
fn test_08_old_circuit_version_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_circuit_0";

    // Thử tạo proof với phiên bản mạch cũ = 0
    let result = ZkProver::prove(&witness, &policy, &root_hex, nonce, 0);
    assert!(result.is_err());
}

#[test]
fn test_09_cross_version_proof_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_cross_ver";

    let mut proof = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION).unwrap();
    proof.circuit_version = 999; // Giả lập cross-version

    let mut tracker = NonceTracker::new();
    let result = ZkVerifier::verify(&proof, &root_hex, &policy, nonce, &mut tracker);
    assert_eq!(
        result.unwrap_err(),
        VerifierError::VersionMismatch {
            expected: CIRCUIT_VERSION,
            actual: 999
        }
    );
}

#[test]
fn test_10_tampered_witness_merkle_proof_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (mut witness, _) = create_valid_witness(&tree);
    let policy = DevicePolicy::enterprise_baseline();
    let nonce = "nonce_tampered_witness";

    // Can thiệp vào sibling hash trong đường dẫn Merkle của nhân chứng
    if let Some(step) = witness.leaves[0].proof.path.first_mut() {
        let last_char = step.sibling_hash_hex.chars().last().unwrap();
        let new_char = if last_char == '0' { '1' } else { '0' };
        step.sibling_hash_hex.pop();
        step.sibling_hash_hex.push(new_char);
    }

    let result = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION);
    assert!(result.is_err());
}

#[test]
fn test_11_tpm_required_policy_fails_if_tpm_inactive() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (mut witness, _) = create_valid_witness(&tree);
    witness.tpm_active = false; // TPM không khả dụng

    let policy = DevicePolicy::enterprise_baseline(); // require_tpm = true
    let nonce = "nonce_tpm_test";

    let result = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION);
    assert!(matches!(
        result.unwrap_err(),
        cyberv_agent::privacy::ProverError::CircuitFailed(CircuitError::TpmRequirementFailed)
    ));
}

#[test]
fn test_12_kernel_consistency_required_policy_fails_if_inconsistent() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (mut witness, _) = create_valid_witness(&tree);
    witness.kernel_consistent = false; // Có mâu thuẫn WMI - Kernel

    let policy = DevicePolicy::enterprise_baseline(); // require_kernel_consistent = true
    let nonce = "nonce_kernel_test";

    let result = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION);
    assert!(matches!(
        result.unwrap_err(),
        cyberv_agent::privacy::ProverError::CircuitFailed(CircuitError::KernelRequirementFailed)
    ));
}

#[test]
fn test_13_memory_threshold_policy_enforcement() {
    let (tree, root_hex) = create_test_merkle_tree();
    let (mut witness, _) = create_valid_witness(&tree);
    witness.total_memory_bytes = 4 * 1024 * 1024 * 1024; // 4 GB RAM

    let mut policy = DevicePolicy::enterprise_baseline();
    policy.min_memory_bytes = 16 * 1024 * 1024 * 1024; // Yêu cầu 16 GB

    let nonce = "nonce_ram_test";
    let result = ZkProver::prove(&witness, &policy, &root_hex, nonce, CIRCUIT_VERSION);
    assert!(matches!(
        result.unwrap_err(),
        cyberv_agent::privacy::ProverError::CircuitFailed(CircuitError::InsufficientMemory { .. })
    ));
}

#[test]
fn test_14_selective_disclosure_valid_attribute() {
    let (tree, root_hex) = create_test_merkle_tree();
    let cpu_label = "comp:cpu:intel:intel core i7-13700k";
    let proof = generate_inclusion_proof(&tree.root, cpu_label).unwrap();

    let attr = DisclosedAttribute {
        field_name: "cpu_model".to_string(),
        field_value: "Intel Core i7-13700K".to_string(),
        inclusion_proof: proof,
    };

    let claim = SelectiveDisclosureClaim {
        public_root: root_hex.clone(),
        attributes: vec![attr],
    };

    let verified = SelectiveDisclosureEngine::verify_claim(&claim, &root_hex).unwrap();
    assert!(verified);
}

#[test]
fn test_15_selective_disclosure_tampered_root_rejected() {
    let (tree, root_hex) = create_test_merkle_tree();
    let cpu_label = "comp:cpu:intel:intel core i7-13700k";
    let proof = generate_inclusion_proof(&tree.root, cpu_label).unwrap();

    let attr = DisclosedAttribute {
        field_name: "cpu_model".to_string(),
        field_value: "Intel Core i7-13700K".to_string(),
        inclusion_proof: proof,
    };

    let wrong_root = "1".repeat(128);
    let claim = SelectiveDisclosureClaim {
        public_root: wrong_root.clone(),
        attributes: vec![attr],
    };

    let result = SelectiveDisclosureEngine::verify_claim(&claim, &root_hex);
    assert!(matches!(
        result.unwrap_err(),
        SelectiveDisclosureError::RootMismatch(..)
    ));
}
