//! CyberV Phase 13: Verifiable Revocation Log & MMR Tests (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8:
//! Merkle Mountain Range (MMR), Signed Checkpoints, Inclusion Proofs,
//! Anti-Rogue-Admin Protection (Silent Un-revoke detection), Append-Only Transparency.

use cyberv_agent::transparency::{
    EventType, MerkleMountainRange, RevocationEvent, RevocationVerificationResult,
    RevocationVerifier, SignedCheckpoint,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[test]
fn test_01_single_event_append_and_mmr_root() {
    let mut mmr = MerkleMountainRange::new();
    let event = RevocationEvent::new(
        "device-001",
        EventType::DeviceRevoked,
        "state_hash_001",
        "STOLEN_DEVICE",
        1757077200,
        "GENESIS_HASH",
    );

    let idx = mmr.append(event.entry_hash());
    assert_eq!(idx, 0);
    assert_eq!(mmr.tree_size(), 1);

    let root = mmr.root();
    assert_eq!(root.len(), 128); // SHA-512 hex
    assert_eq!(root, event.entry_hash());
}

#[test]
fn test_02_multiple_events_append_and_peaks_bagging() {
    let mut mmr = MerkleMountainRange::new();

    // Thêm 5 sự kiện (5 = 4 + 1 -> gồm 2 đỉnh: đỉnh cây nhị phân size 4 và đỉnh cây size 1)
    for i in 0..5 {
        let event = RevocationEvent::new(
            format!("device-00{}", i),
            EventType::DeviceRevoked,
            format!("state_hash_00{}", i),
            "POLICY_VIOLATION",
            1757077200 + i as u64,
            "prev_hash",
        );
        mmr.append(event.entry_hash());
    }

    assert_eq!(mmr.tree_size(), 5);
    let peaks = mmr.get_peaks();
    assert_eq!(peaks.len(), 2, "Size 5 phải phân rã thành 2 đỉnh (4 + 1)");

    let root = mmr.root();
    assert_eq!(root.len(), 128);
}

#[test]
fn test_03_mmr_inclusion_proof_valid() {
    let mut mmr = MerkleMountainRange::new();
    let mut target_hash = String::new();

    for i in 0..7 {
        let event = RevocationEvent::new(
            format!("device-00{}", i),
            EventType::DeviceRevoked,
            format!("state_hash_00{}", i),
            "MALICIOUS_FIRMWARE",
            1757077200 + i as u64,
            "prev",
        );
        let h = event.entry_hash();
        if i == 2 {
            target_hash = h.clone();
        }
        mmr.append(h);
    }

    // Sinh bằng chứng bao hàm cho phần tử thứ 2
    let proof = mmr.generate_proof(2).expect("Sinh MMR proof thành công");
    assert_eq!(proof.leaf_hash, target_hash);
    assert_eq!(proof.leaf_index, 2);
    assert_eq!(proof.mmr_root, mmr.root());

    // Xác minh bằng chứng
    assert!(proof.verify(), "Bằng chứng bao hàm MMR phải hợp lệ");
}

#[test]
fn test_04_mmr_inclusion_proof_tampered_leaf_rejected() {
    let mut mmr = MerkleMountainRange::new();
    for i in 0..4 {
        let event = RevocationEvent::new(
            format!("device-00{}", i),
            EventType::DeviceRevoked,
            "state",
            "REASON",
            1757077200,
            "prev",
        );
        mmr.append(event.entry_hash());
    }

    let mut proof = mmr.generate_proof(1).unwrap();

    // Sửa 1 ký tự trong leaf hash bảo đảm khác biệt
    let mut bad_leaf = proof.leaf_hash.clone();
    let last = bad_leaf.pop().unwrap();
    let new_char = if last == '0' { '1' } else { '0' };
    bad_leaf.push(new_char);
    proof.leaf_hash = bad_leaf;

    assert!(
        !proof.verify(),
        "Bằng chứng có leaf hash bị sửa phải bị từ chối"
    );
}

#[test]
fn test_05_mmr_inclusion_proof_tampered_sibling_rejected() {
    let mut mmr = MerkleMountainRange::new();
    for i in 0..4 {
        let event = RevocationEvent::new(
            format!("device-00{}", i),
            EventType::DeviceRevoked,
            "state",
            "REASON",
            1757077200,
            "prev",
        );
        mmr.append(event.entry_hash());
    }

    let mut proof = mmr.generate_proof(0).unwrap();

    // Sửa sibling hash trong đường đi bảo đảm khác biệt
    let mut bad_sibling = proof.path_to_peak[0].sibling_hash.clone();
    let last = bad_sibling.pop().unwrap();
    let new_char = if last == '0' { '1' } else { '0' };
    bad_sibling.push(new_char);
    proof.path_to_peak[0].sibling_hash = bad_sibling;

    assert!(
        !proof.verify(),
        "Bằng chứng có sibling bị sửa phải bị từ chối"
    );
}

#[test]
fn test_06_signed_checkpoint_generation_and_verification() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let log_id = "cyberv-revocation-transparency-v1";
    let mmr_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let checkpoint = SignedCheckpoint::sign(log_id, 10, mmr_root, 1757077200, &signing_key);

    assert_eq!(checkpoint.log_id, log_id);
    assert_eq!(checkpoint.tree_size, 10);
    assert!(checkpoint.verify(), "Xác thực chữ ký Checkpoint thành công");
}

#[test]
fn test_07_checkpoint_forged_signature_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut checkpoint =
        SignedCheckpoint::sign("cyberv-log", 5, "00".repeat(64), 1757077200, &signing_key);

    // Kẻ gian sửa chữ ký
    checkpoint.authority_signature_hex = "deadbeef".repeat(16);

    assert!(!checkpoint.verify(), "Chữ ký giả mạo phải bị từ chối");
}

#[test]
fn test_08_checkpoint_tampered_tree_size_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut checkpoint =
        SignedCheckpoint::sign("cyberv-log", 5, "00".repeat(64), 1757077200, &signing_key);

    // Kẻ gian sửa tree_size từ 5 lên 50
    checkpoint.tree_size = 50;

    assert!(
        !checkpoint.verify(),
        "Payload Checkpoint bị sửa phải khiến xác thực thất bại"
    );
}

#[test]
fn test_09_full_revocation_flow_confirmed() {
    let authority_key = SigningKey::generate(&mut OsRng);
    let mut mmr = MerkleMountainRange::new();

    let target_device = "device-target-666";
    let event = RevocationEvent::new(
        target_device,
        EventType::DeviceRevoked,
        "state_hash_compromised",
        "STOLEN_LAPTOP",
        1757077200,
        "prev_hash_genesis",
    );

    let leaf_idx = mmr.append(event.entry_hash());
    let mmr_root = mmr.root();
    let proof = mmr.generate_proof(leaf_idx).unwrap();

    let checkpoint = SignedCheckpoint::sign(
        "cyberv-log",
        mmr.tree_size(),
        mmr_root,
        1757077200,
        &authority_key,
    );

    // Client xác minh lệnh thu hồi
    let result = RevocationVerifier::verify_revocation(&checkpoint, &event, &proof, target_device);

    match result {
        RevocationVerificationResult::RevocationConfirmed {
            device_id, reason, ..
        } => {
            assert_eq!(device_id, target_device);
            assert_eq!(reason, "STOLEN_LAPTOP");
        }
        _ => panic!("Phải xác thực thu hồi thành công"),
    }
}

#[test]
fn test_10_revocation_proof_wrong_device_id_rejected() {
    let authority_key = SigningKey::generate(&mut OsRng);
    let mut mmr = MerkleMountainRange::new();

    let event = RevocationEvent::new(
        "device-victim-01",
        EventType::DeviceRevoked,
        "state_hash_01",
        "REVOKED_REASON",
        1757077200,
        "prev",
    );

    let leaf_idx = mmr.append(event.entry_hash());
    let proof = mmr.generate_proof(leaf_idx).unwrap();
    let checkpoint = SignedCheckpoint::sign(
        "cyberv-log",
        mmr.tree_size(),
        mmr.root(),
        1757077200,
        &authority_key,
    );

    // Server kiểm tra cho device khác
    let result =
        RevocationVerifier::verify_revocation(&checkpoint, &event, &proof, "device-innocent-99");

    assert!(matches!(
        result,
        RevocationVerificationResult::VerificationFailed(_)
    ));
}

#[test]
fn test_11_anti_rogue_admin_silent_unrevoke_detected() {
    // Kịch bản: Máy "device-x" từng bị thu hồi trong quá khứ.
    // Rogue Admin truy cập DB sửa trạng thái thành ACTIVE, nhưng KHÔNG tạo sự kiện trong MMR log!
    let db_status_active = true;
    let was_previously_revoked = true;
    let unrevoke_event = None; // Không có event trong MMR

    let result = RevocationVerifier::verify_unrevocation_guard(
        db_status_active,
        was_previously_revoked,
        unrevoke_event,
        "device-x",
    );

    match result {
        RevocationVerificationResult::RogueAdminTamperDetected { device_id, reason } => {
            assert_eq!(device_id, "device-x");
            assert!(reason.contains("không có sự kiện UNREVOKED"));
        }
        _ => panic!("Phải phát hiện hành vi Rogue Admin can thiệp DB"),
    }
}

#[test]
fn test_12_authorized_unrevocation_confirmed() {
    let authority_key = SigningKey::generate(&mut OsRng);
    let mut mmr = MerkleMountainRange::new();

    let device_id = "device-pardoned-01";
    let event = RevocationEvent::new(
        device_id,
        EventType::DeviceUnrevoked,
        "new_state_hash",
        "SECURITY_CLEARANCE_RESTORED",
        1757077200,
        "prev_hash",
    );

    let leaf_idx = mmr.append(event.entry_hash());
    let proof = mmr.generate_proof(leaf_idx).unwrap();
    let checkpoint = SignedCheckpoint::sign(
        "cyberv-log",
        mmr.tree_size(),
        mmr.root(),
        1757077200,
        &authority_key,
    );

    let result = RevocationVerifier::verify_unrevocation_guard(
        true,
        true,
        Some((&event, &proof, &checkpoint)),
        device_id,
    );

    assert_eq!(
        result,
        RevocationVerificationResult::RevocationConfirmed {
            device_id: device_id.to_string(),
            timestamp: 0,
            reason: "UNREVOCATION_VALID".to_string(),
        }
    );
}

#[test]
fn test_13_deterministic_event_canonical_encoding() {
    let event1 = RevocationEvent::new(
        "dev1",
        EventType::DeviceRevoked,
        "state1",
        "R1",
        1000,
        "prev",
    );
    let event2 = RevocationEvent::new(
        "dev1",
        EventType::DeviceRevoked,
        "state1",
        "R1",
        1000,
        "prev",
    );

    assert_eq!(event1.entry_hash(), event2.entry_hash());
    assert_eq!(event1.to_canonical_bytes(), event2.to_canonical_bytes());
}

#[test]
fn test_14_mmr_growth_append_only_consistency() {
    let mut mmr = MerkleMountainRange::new();

    for i in 0..8 {
        mmr.append(format!("hash_{}", i));
    }

    // Ở size 8, chỉ có 1 đỉnh duy nhất (cây nhị phân hoàn hảo $2^3$)
    assert_eq!(mmr.get_peaks().len(), 1);

    // Thêm 1 phần tử thành size 9 -> có 2 đỉnh ($2^3 + 2^0 = 8 + 1$)
    mmr.append("hash_8");
    assert_eq!(mmr.get_peaks().len(), 2);
}

#[test]
fn test_15_end_to_end_transparency_log_integration() {
    let authority_key = SigningKey::generate(&mut OsRng);
    let mut mmr = MerkleMountainRange::new();

    // 1. Thêm 10 sự kiện vào sổ cái
    for i in 0..10 {
        let ev = RevocationEvent::new(
            format!("dev-{}", i),
            EventType::DeviceRevoked,
            format!("state-{}", i),
            "TEST_AUDIT",
            1757077200 + i,
            "root",
        );
        mmr.append(ev.entry_hash());
    }

    // 2. Ký Checkpoint
    let checkpoint = SignedCheckpoint::sign(
        "main-transparency-log",
        mmr.tree_size(),
        mmr.root(),
        1757077200,
        &authority_key,
    );
    assert!(checkpoint.verify());

    // 3. Chứng minh phần tử thứ 5 thuộc Checkpoint
    let proof = mmr.generate_proof(5).unwrap();
    assert!(proof.verify());
    assert_eq!(proof.mmr_root, checkpoint.mmr_root);
}
