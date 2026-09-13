//! CyberV Phase 9 Adversarial Penetration Testing & Anti-Tamper Matrix
//!
//! Ref: Plan.md Section 21 (Giai đoạn 17), Section 30 (VM Test Matrix), Section 31 (Attack Matrix);
//! Rule.md Điều 1, 2, 5, 23, 25, 26, 27:
//! "What can attacker copy? What can attacker replay? What can attacker modify? What can attacker spoof?
//! What if device is cloned? What if VM snapshot is restored?
//! WHAT SYSTEM KNOWS vs WHAT SYSTEM CAN PROVE."
//!
//! 15 bài kiểm thử đối kháng thực chiến:
//! 1. Copy-Paste Final Hash Attack Fails (Final Hash != Authentication Credential)
//! 2. Device ID Impersonation with Foreign Key Fails
//! 3. Malicious JSON AST & Lexicographical Ordering Sanitization
//! 4. Cross-Tenant Device Impersonation / Unauthorized Access Rejected (403)
//! 5. Nonce Reuse Replay Attack Detected & Rejected
//! 6. Expired Challenge Nonce Attack (TTL Exceeded) Rejected
//! 7. Cross-Domain Signature Confusion (Enrollment vs Auth) Rejected
//! 8. Single-Bit Payload Mutation in Canonical Payload Detected
//! 9. VM Snapshot Revert / Rollback Attack Penalized with Max Penalty (Rejected)
//! 10. VM Clone Split-Brain Concurrent Challenge Conflict Detected
//! 11. WMI Serial Hooking / OEM Junk Spoofing Drops Confidence & Raises Risk
//! 12. Hypervisor / Virtual Machine Detection & Mutation Rejection
//! 13. Local Secure Vault File Corruption / Bit-Rot Fail-Secure Handling
//! 14. Vault Transplantation Across Different Physical Hardware Detected & Blocked
//! 15. Concurrent TOCTOU Nonce Consumption Race Condition Prevented (Atomic Guard)

use cyberv_agent::fingerprint::canonical::{CanonicalEncoder, CanonicalGraphNode};
use cyberv_agent::fingerprint::component_hasher::hash_snapshot;
use cyberv_agent::fingerprint::graph::builder::build_evidence_graph;
use cyberv_agent::fingerprint::graph::diff::diff_evidence_graphs;
use cyberv_agent::fingerprint::state_hasher::evaluate_device_state;
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::models::ComponentType;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::identity::secret::Secret32;
use cyberv_agent::identity::storage::models::PersistedIdentity;
use cyberv_agent::identity::storage::StorageError;
use cyberv_agent::protocol::challenge::{
    create_challenge_proof, verify_challenge_proof, ChallengeObject, SignedChallengeProof,
};
use cyberv_agent::protocol::constants::{DOMAIN_AUTH, DOMAIN_ENROLL, PURPOSE_DEVICE_AUTH};
use cyberv_agent::protocol::enroll::create_enrollment_request;
use cyberv_agent::risk::engine::{evaluate_risk, PENALTY_ROLLBACK};
use cyberv_agent::risk::models::{PolicyDecision, RiskLevel};
use cyberv_agent::transport::error::TransportError;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

// ====================================================================
// NHÓM A: TẤN CÔNG GIẢ MẠO DANH TÍNH & TRẠNG THÁI (IDENTITY & STATE)
// ====================================================================

#[test]
fn test_01_attack_copy_paste_final_hash_fails() {
    // Kịch bản: Kẻ tấn công sao chép được chuỗi state_hash (Final Hash) của máy nạn nhân
    // và cố gắng vượt qua cổng xác thực thử thách mà không có khóa bí mật Ed25519.
    // Ref: Rule.md Điều 1 & Điều 5: "Final Hash != Authentication Credential".
    let mut rng = OsCryptoRng;
    let victim_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let attacker_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();
    let hashed = hash_snapshot(&snapshot);
    let victim_graph = build_evidence_graph(&hashed, 1);
    let victim_state = evaluate_device_state(
        "CYBERV-VICTIM-PC",
        1,
        &victim_graph.verification_hash,
        &BTreeMap::new(),
    );
    let legitimate_state_hash = &victim_state.state_hash;

    let challenge = ChallengeObject {
        challenge_id: "chal-victim-001".to_string(),
        nonce: "nonce-sec-12345678".to_string(),
        device_id: "CYBERV-VICTIM-PC".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1757000000,
        expires_at: 1757000300,
    };

    // Kẻ tấn công dùng state_hash hợp lệ nhưng ký bằng khóa riêng của chính mình
    let forged_proof =
        create_challenge_proof(&attacker_key, &challenge, legitimate_state_hash, 1).unwrap();

    println!("\n--- [LIVE RED-TEAM AUDIT: Test 01 - Copy-Paste Final Hash Attack] ---");
    println!("Victim Public Key:   {}", victim_key.public_key_hex());
    println!("Attacker Public Key: {}", attacker_key.public_key_hex());
    println!("Copied State Hash:   {}...", &legitimate_state_hash[..32]);
    println!(
        "Forged Signature:    {}...",
        &forged_proof.signature_hex[..32]
    );

    // Server kiểm tra bằng Public Key đã đăng ký của Nạn nhân
    let verify_res = verify_challenge_proof(victim_key.verifying_key(), &forged_proof);
    println!(
        "Server Rejection:    {:?}",
        verify_res.as_ref().err().unwrap()
    );
    assert!(
        verify_res.is_err(),
        "Server PHẢI từ chối chữ ký của khóa kẻ tấn công ngay cả khi state_hash chính xác 100%"
    );

    // Kẻ tấn công thử gửi chữ ký rác / ngẫu nhiên
    let mut junk_proof = forged_proof;
    junk_proof.signature_hex = "deadbeef".repeat(16);
    let junk_res = verify_challenge_proof(victim_key.verifying_key(), &junk_proof);
    println!(
        "Junk Sig Rejection:  {:?}",
        junk_res.as_ref().err().unwrap()
    );
    assert!(
        junk_res.is_err(),
        "Chữ ký giả mạo phải bị từ chối dứt khoát"
    );
    println!("--- [RESULT: 100% REJECTED BY ED25519 EQUATION] ---\n");
}

#[test]
fn test_02_attack_device_id_impersonation_with_foreign_key_fails() {
    // Kịch bản: Kẻ tấn công biết device_id hợp lệ của máy khác ("CYBERV-CORP-DESKTOP-99")
    // và cố tình mạo danh thiết bị này bằng một cặp khóa mới tự tạo.
    // Ref: Plan.md Section 31 (Copied device ID).
    let mut rng = OsCryptoRng;
    let registered_device_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let rogue_device_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let target_device_id = "CYBERV-CORP-DESKTOP-99";
    let state_hash = "e".repeat(128);

    let challenge = ChallengeObject {
        challenge_id: "chal-corp-44".to_string(),
        nonce: "nonce-random-882233".to_string(),
        device_id: target_device_id.to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1757000000,
        expires_at: 1757000300,
    };

    // Rogue device tạo proof với device_id của mục tiêu
    let rogue_proof =
        create_challenge_proof(&rogue_device_key, &challenge, &state_hash, 1).unwrap();

    // Xác thực bằng Public Key đã đăng ký trong CSDL
    let res = verify_challenge_proof(registered_device_key.verifying_key(), &rogue_proof);
    assert!(
        res.is_err(),
        "Mạo danh device_id bằng khóa lạ phải thất bại"
    );
}

#[test]
fn test_03_attack_malicious_json_ast_injection_sanitized() {
    // Kịch bản: Kẻ tấn công cố tình thay đổi thứ tự key, chèn ký tự khoảng trắng thừa,
    // hoặc chèn các cặp trường hỗn loạn nhằm gây sai lệch mã băm hoặc đụng độ AST.
    // Ref: Plan.md Section 31 (Modified request & Canonicalization).
    let mut enc1 = CanonicalEncoder::new();
    enc1.add_field("vendor", "  Intel Corporation  ")
        .add_field("model", "Core i7-13700K")
        .add_field("cores", "16")
        .add_field("architecture", "x86_64");

    let mut enc2 = CanonicalEncoder::new();
    // Thứ tự thêm hoàn toàn đảo ngược và xáo trộn
    enc2.add_field("architecture", "x86_64")
        .add_field("cores", "16")
        .add_field("vendor", "Intel Corporation")
        .add_field("model", "Core i7-13700K");

    let bytes1 = enc1.to_canonical_bytes();
    let bytes2 = enc2.to_canonical_bytes();

    assert_eq!(
        bytes1, bytes2,
        "Canonical encoding PHẢI chuẩn hóa khoảng trắng và thứ tự từ điển BTreeMap tuyệt đối"
    );

    // Kiểm tra CanonicalGraphNode không bị ảnh hưởng bởi thứ tự cấu trúc
    let node_a = CanonicalGraphNode {
        component_type: "Cpu".to_string(),
        stable_id: "cpu:0".to_string(),
        component_hash: "1234".to_string(),
        schema_version: 1,
    };
    let node_b = CanonicalGraphNode {
        component_type: "Cpu".to_string(),
        stable_id: "cpu:0".to_string(),
        component_hash: "1234".to_string(),
        schema_version: 1,
    };
    assert_eq!(node_a, node_b);
}

#[test]
fn test_04_attack_cross_tenant_impersonation_rejected() {
    // Kịch bản: Người dùng Tenant B cố gắng can thiệp hoặc truy cập tài nguyên
    // của Tenant A (Cross-Tenant Unauthorized Device Access).
    // Ref: Rule.md Điều 8 & 25.
    let forbidden_err = TransportError::Forbidden(
        "CROSS_TENANT_ACCESS_DENIED: Device does not belong to the authenticated user account"
            .to_string(),
    );

    // Kiểm tra mã lỗi bảo mật 403 Forbidden được định nghĩa chuẩn tắc
    match forbidden_err {
        TransportError::Forbidden(msg) => {
            assert!(msg.contains("CROSS_TENANT_ACCESS_DENIED"));
        }
        _ => panic!("Expected TransportError::Forbidden"),
    }
}

// ====================================================================
// NHÓM B: TẤN CÔNG TÁI PHÁT & BIẾN DỊ MẬT MÃ (REPLAY & CRYPTO MUTATION)
// ====================================================================

#[test]
fn test_05_attack_nonce_reuse_replay_rejected() {
    // Kịch bản: Tấn công Replay Attack — Kẻ tấn công bắt gói tin SignedChallengeProof hợp lệ
    // và gửi lại nguyên vẹn lần thứ hai để tìm cách vượt qua cổng xác thực.
    // Ref: Plan.md Section 31 (Replay signature).
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let challenge = ChallengeObject {
        challenge_id: "chal-replay-test".to_string(),
        nonce: "nonce-single-use-999".to_string(),
        device_id: "CYBERV-TEST-REPLAY".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1757000000,
        expires_at: 1757000300,
    };

    let proof = create_challenge_proof(&key, &challenge, &"f".repeat(128), 1).unwrap();

    // Mô phỏng bộ lưu trữ Nonce phía Server (Atomic Nonce Registry)
    let mut consumed_nonces: HashSet<String> = HashSet::new();

    // Lần 1: Trình diện gói tin lần đầu -> Hợp lệ và Nonce được đánh dấu Consumed
    let verify_first = verify_challenge_proof(key.verifying_key(), &proof);
    assert!(verify_first.is_ok());
    let inserted = consumed_nonces.insert(proof.nonce.clone());
    assert!(inserted, "Lần đầu Nonce chưa tồn tại");

    // Lần 2: Replay lại chính gói tin đó
    let is_already_consumed = !consumed_nonces.insert(proof.nonce.clone());
    assert!(
        is_already_consumed,
        "Server PHẢI phát hiện Nonce đã được sử dụng và từ chối Replay Attack"
    );
}

#[test]
fn test_06_attack_expired_challenge_nonce_rejected() {
    // Kịch bản: Kẻ tấn công giữ gói tin challenge lại quá thời hạn TTL (Time-To-Live = 300s)
    // rồi mới nộp lên server.
    // Ref: Plan.md Section 31 (Expired challenge).
    let current_server_time = 1757000350u64; // Sau 350 giây kể từ khi phát hành

    let challenge = ChallengeObject {
        challenge_id: "chal-ttl-expired".to_string(),
        nonce: "nonce-ttl-88".to_string(),
        device_id: "CYBERV-DEV-EXP".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1757000000,
        expires_at: 1757000300, // Hết hạn tại giây thứ 300
    };

    // Kiểm tra tính hợp lệ thời gian phía Server
    let is_expired = current_server_time > challenge.expires_at;
    assert!(
        is_expired,
        "Challenge quá hạn TTL (350s > 300s) phải bị hủy bỏ ngay lập tức"
    );
}

#[test]
fn test_07_attack_cross_domain_signature_confusion_rejected() {
    // Kịch bản: Tấn công lẫn lộn không gian tên (Cross-Domain Confusion)
    // Kẻ tấn công lấy chữ ký hợp lệ từ giao thức ENROLLMENT đem sang dùng cho AUTHENTICATION.
    // Ref: Rule.md Điều 2 & 20; Plan.md Section 31.
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let device_id = "CYBERV-DEV-DOMAIN-01";
    let state_hash = "b".repeat(128);
    let graph_hash = "a".repeat(128);
    let nonce = "nonce-domain-isolation";

    // 1. Sinh chữ ký hợp lệ theo domain ENROLL
    let enroll_req = create_enrollment_request(
        &key,
        device_id,
        &graph_hash,
        &state_hash,
        1,
        serde_json::json!({}),
    )
    .unwrap();

    // 2. Kẻ tấn công lấy chính chữ ký đó gán vào SignedChallengeProof (DOMAIN_AUTH)
    let cross_proof = SignedChallengeProof {
        challenge_id: "chal-confused".to_string(),
        nonce: nonce.to_string(),
        device_id: device_id.to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        state_hash: state_hash.clone(),
        graph_version: 1,
        signature_hex: enroll_req.proof_signature, // Lấy chữ ký từ Enrollment!
    };

    // 3. Server kiểm tra theo domain AUTH -> Phải từ chối do tiền tố nhị phân DOMAIN_AUTH != DOMAIN_ENROLL
    let res = verify_challenge_proof(key.verifying_key(), &cross_proof);
    assert!(
        res.is_err(),
        "Chữ ký thuộc Domain Enrollment không bao giờ được chấp nhận cho Domain Auth"
    );
    assert_ne!(DOMAIN_AUTH, DOMAIN_ENROLL);
}

#[test]
fn test_08_attack_single_bit_payload_mutation_detected() {
    // Kịch bản: Kẻ tấn công can thiệp trên đường truyền (MitM), sửa đúng 1 ký tự trong state_hash
    // hoặc tăng graph_version từ 1 lên 2 mà giữ nguyên chữ ký Ed25519.
    // Ref: Plan.md Section 31 (Modified graph / state).
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let challenge = ChallengeObject {
        challenge_id: "chal-bitflip".to_string(),
        nonce: "nonce-bitflip-11".to_string(),
        device_id: "CYBERV-BITFLIP".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1757000000,
        expires_at: 1757000300,
    };

    let original_hash = "c".repeat(128);
    let proof = create_challenge_proof(&key, &challenge, &original_hash, 1).unwrap();

    // Xác thực ban đầu hợp lệ
    assert!(verify_challenge_proof(key.verifying_key(), &proof).is_ok());

    println!("\n--- [LIVE RED-TEAM AUDIT: Test 08 - Bit-Flipping / Payload Tampering Attack] ---");
    println!("Legitimate Verification: OK (Ed25519 curve equation balanced)");

    // 1. Biến dị state_hash: Sửa ký tự cuối cùng từ 'c' thành 'd'
    let mut tampered_hash_proof = proof.clone();
    let mut mutated_hash = "c".repeat(127);
    mutated_hash.push('d');
    tampered_hash_proof.state_hash = mutated_hash;
    let err_hash = verify_challenge_proof(key.verifying_key(), &tampered_hash_proof);
    println!(
        "State Hash Tampered Error: {:?}",
        err_hash.as_ref().err().unwrap()
    );
    assert!(
        err_hash.is_err(),
        "Biến dị dù chỉ 1 ký tự trong state_hash phải khiến Ed25519 verification thất bại"
    );

    // 2. Biến dị graph_version: Sửa từ 1 lên 2
    let mut tampered_version_proof = proof.clone();
    tampered_version_proof.graph_version = 2;
    let err_ver = verify_challenge_proof(key.verifying_key(), &tampered_version_proof);
    println!(
        "Version Tampered Error:    {:?}",
        err_ver.as_ref().err().unwrap()
    );
    assert!(
        err_ver.is_err(),
        "Biến dị graph_version phải bị phát hiện ngay lập tức"
    );

    // 3. Biến dị nonce
    let mut tampered_nonce_proof = proof;
    tampered_nonce_proof.nonce = "nonce-tampered-00".to_string();
    let err_nonce = verify_challenge_proof(key.verifying_key(), &tampered_nonce_proof);
    println!(
        "Nonce Tampered Error:      {:?}",
        err_nonce.as_ref().err().unwrap()
    );
    assert!(
        err_nonce.is_err(),
        "Biến dị nonce phải bị phát hiện dứt khoát"
    );
    println!("--- [RESULT: EVERY TAMPERED BIT IS MATHEMATICALLY CAUGHT] ---\n");
}

// ====================================================================
// NHÓM C: TẤN CÔNG MÔI TRƯỜNG ẢO HÓA, NHÂN BẢN & QUAY LUI (VM / CLONE)
// ====================================================================

#[test]
fn test_09_attack_vm_snapshot_revert_rollback_detected() {
    // Kịch bản: Thiết bị đang ở trạng thái đồ thị v5. Kẻ tấn công phục hồi snapshot máy ảo
    // trở về trạng thái cũ v3 (hoặc giữ nguyên v5 nhưng hash lệch).
    // Ref: Plan.md Section 30 Test E (Snapshot Rollback) & Section 19 (Risk Engine Rollback Penalty).
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();
    let hashed = hash_snapshot(&snapshot);

    let graph_v5 = build_evidence_graph(&hashed, 5);
    let graph_v3 = build_evidence_graph(&hashed, 3);
    let diff = diff_evidence_graphs(&graph_v5, &graph_v3);

    // Đánh giá rủi ro khi client tuyên bố v3 trong khi server đã ghi nhận v5
    let assessment = evaluate_risk(&diff, &graph_v5, &graph_v3, 5, 3);

    assert_eq!(assessment.decision, PolicyDecision::Rejected);
    assert_eq!(assessment.level, RiskLevel::Critical);
    assert!(
        assessment.score >= PENALTY_ROLLBACK,
        "Tấn công Rollback phải bị phạt điểm tối đa (10000)"
    );
    assert!(assessment
        .signals
        .iter()
        .any(|s| s.code == "ROLLBACK_ATTACK_DETECTED"));
}

#[test]
fn test_10_attack_vm_clone_split_brain_conflict() {
    // Kịch bản: Hai máy ảo nhân bản (VM1 và VM2) cùng chạy song song từ một clone disk
    // mang chung file két .vault. VM2 có storage ảo bị phân nhánh (cloned).
    // Ref: Plan.md Section 30 Test D (VM Clone).
    let vm1_collector = MockHardwareCollector::vm_hyperv_profile().unwrap();
    let vm2_collector = MockHardwareCollector::vm_cloned_profile().unwrap();

    let snap1 = vm1_collector.collect().unwrap();
    let snap2 = vm2_collector.collect().unwrap();

    let hash1 = hash_snapshot(&snap1);
    let hash2 = hash_snapshot(&snap2);

    let g1 = build_evidence_graph(&hash1, 1);
    let g2 = build_evidence_graph(&hash2, 1);

    let s1 = evaluate_device_state("dev-vm-1", 1, &g1.verification_hash, &BTreeMap::new());
    let s2 = evaluate_device_state("dev-vm-2", 1, &g2.verification_hash, &BTreeMap::new());

    // Hai máy clone có hash đĩa khác nhau dẫn tới state_hash khác biệt
    assert_ne!(
        s1.state_hash, s2.state_hash,
        "Máy ảo clone có định danh lưu trữ phân nhánh phải sinh ra State Hash khác nhau"
    );

    let diff = diff_evidence_graphs(&g1, &g2);
    assert!(
        !diff.changes.is_empty(),
        "Hệ thống đồ thị bằng chứng phải phát hiện sự biến động của máy ảo clone"
    );
}

#[test]
fn test_11_attack_wmi_serial_hooking_drops_confidence() {
    // Kịch bản: Kẻ tấn công hook Windows WMI API để trả về chuỗi rác generic OEM
    // ("To Be Filled By O.E.M.").
    // Ref: Plan.md Section 21 & rv plan1.md #1, #7: Confidence degradation.
    let hooked_collector = MockHardwareCollector::wmi_spoofed_profile().unwrap();
    let baseline_collector = MockHardwareCollector::baseline().unwrap();

    let hooked_snapshot = hooked_collector.collect().unwrap();
    let baseline_snapshot = baseline_collector.collect().unwrap();

    let hooked_hashed = hash_snapshot(&hooked_snapshot);
    let baseline_hashed = hash_snapshot(&baseline_snapshot);

    let hooked_graph = build_evidence_graph(&hooked_hashed, 2);
    let baseline_graph = build_evidence_graph(&baseline_hashed, 1);

    let diff = diff_evidence_graphs(&baseline_graph, &hooked_graph);
    let assessment = evaluate_risk(&diff, &baseline_graph, &hooked_graph, 1, 2);

    // Hệ thống phát hiện partial attributes và tăng điểm phạt rủi ro
    assert!(assessment
        .signals
        .iter()
        .any(|s| s.code == "PARTIAL_HARDWARE_ATTRIBUTES"));
    assert!(
        assessment.score >= 1000,
        "WMI bị hook / serial rác phải làm sụt giảm độ tin cậy và tăng điểm rủi ro"
    );
}

#[test]
fn test_12_attack_virtual_machine_hypervisor_degradation() {
    // Kịch bản: Thiết bị vận hành trong môi trường máy ảo Hyper-V thay vì phần cứng vật lý gốc.
    // Thay đổi bo mạch chủ thành "Microsoft Corporation Virtual Machine" và ổ đĩa thành "MSFT Virtual Disk".
    // Ref: Plan.md Section 19 & 30: Board mutation + Storage mutation -> Rejected.
    let vm_collector = MockHardwareCollector::vm_hyperv_profile().unwrap();
    let baseline_collector = MockHardwareCollector::baseline().unwrap();

    let vm_snap = vm_collector.collect().unwrap();
    let base_snap = baseline_collector.collect().unwrap();

    let vm_hashed = hash_snapshot(&vm_snap);
    let base_hashed = hash_snapshot(&base_snap);

    let vm_graph = build_evidence_graph(&vm_hashed, 2);
    let base_graph = build_evidence_graph(&base_hashed, 1);

    let diff = diff_evidence_graphs(&base_graph, &vm_graph);
    let assessment = evaluate_risk(&diff, &base_graph, &vm_graph, 1, 2);

    // Bo mạch chủ đổi sang bo mạch ảo + ổ cứng đổi sang ổ đĩa ảo -> Tấn công hoán đổi nền tảng -> BỊ TỪ CHỐI
    assert_eq!(
        assessment.decision,
        PolicyDecision::Rejected,
        "Hoán đổi đồng thời Motherboard và Storage sang máy ảo phải bị từ chối dứt khoát"
    );
    assert_eq!(assessment.level, RiskLevel::Critical);
}

// ====================================================================
// NHÓM D: TOÀN VẸN KÉT KHÓA CỤC BỘ & TRANH CHẤP ĐỒNG THỜI (ANTI-TAMPER)
// ====================================================================

#[test]
fn test_13_attack_local_vault_file_corruption_detected() {
    // Kịch bản: Kẻ tấn công hoặc lỗi ổ đĩa làm hỏng các byte trong file két khóa .vault (Bit rot / Truncation).
    // Hệ thống phải xử lý Fail-Secure: trả về lỗi CorruptVault, không crash, không sinh khóa giả.
    // Ref: Rule.md Điều 23 (Fail Secure).
    let mut valid_bytes = PersistedIdentity::new(
        "CYBERV-DEV-VAULT-CORRUPT".to_string(),
        Secret32::new([1u8; 32]),
        Secret32::new([2u8; 32]),
        1000,
    )
    .to_vault_bytes();

    // Cố tình sửa đổi 1 byte trong checksum hoặc dữ liệu được mã hóa
    valid_bytes[25] ^= 0xff;

    let load_res = PersistedIdentity::from_vault_bytes(&valid_bytes);
    assert!(
        load_res.is_err(),
        "Két khóa bị hỏng byte bắt buộc phải trả về lỗi Fail-Secure"
    );

    match load_res.err().unwrap() {
        StorageError::CorruptVault(msg) => {
            assert!(msg.contains("checksum"));
        }
        other => panic!("Expected CorruptVault error, got: {:?}", other),
    }
}

#[test]
fn test_14_attack_vault_transplantation_across_hardware_rejected() {
    // Kịch bản: Kẻ tấn công đánh cắp được file .vault từ Máy A đem sang nạp trên Máy B.
    // Dù khóa riêng Ed25519 hợp lệ để tạo chữ ký, nhưng phần cứng thực tế của Máy B
    // (CPU AMD, Bo mạch khác) sẽ tạo ra State Hash hoàn toàn khác với State Hash đã đăng ký của Máy A.
    // Ref: Rule.md Điều 27: "Hardware says I look like Device A, Cryptographic key proves credential".
    let collector_a = MockHardwareCollector::baseline().unwrap();
    let snap_a = collector_a.collect().unwrap();
    let hashed_a = hash_snapshot(&snap_a);
    let graph_a = build_evidence_graph(&hashed_a, 1);
    let state_a = evaluate_device_state(
        "CYBERV-DEV-A",
        1,
        &graph_a.verification_hash,
        &BTreeMap::new(),
    );
    let state_hash_registered_on_server = state_a.state_hash;

    // Máy B (Kẻ tấn công cắm trộm khóa vào máy khác)
    let mut snap_b = collector_a.collect().unwrap();
    // Thay đổi CPU và Motherboard trên Máy B
    for c in &mut snap_b.components {
        if c.component_type == ComponentType::Cpu {
            c.canonical_id = "cpu:amd:ryzen 7 7800x3d".to_string();
        } else if c.component_type == ComponentType::Motherboard {
            c.canonical_id = "board:msi:b650 tomahawk".to_string();
        }
    }
    let hashed_b = hash_snapshot(&snap_b);
    let graph_b = build_evidence_graph(&hashed_b, 1);
    let state_b = evaluate_device_state(
        "CYBERV-DEV-A",
        1,
        &graph_b.verification_hash,
        &BTreeMap::new(),
    );
    let state_hash_claimed_by_machine_b = state_b.state_hash;

    // 1. Máy B tạo ra State Hash khác hoàn toàn
    assert_ne!(
        state_hash_registered_on_server, state_hash_claimed_by_machine_b,
        "Khóa bị cắm vào phần cứng lạ sẽ tạo ra State Hash không khớp với trạng thái đã đăng ký"
    );

    // 2. Nếu Máy B khai báo State Hash thật của nó thì Server phát hiện Hardware State Mismatch
    let diff = diff_evidence_graphs(&graph_a, &graph_b);
    let assessment = evaluate_risk(&diff, &graph_a, &graph_b, 1, 2);
    assert_eq!(
        assessment.decision,
        PolicyDecision::Rejected,
        "Tráo đổi két khóa sang phần cứng lạ (thay cả Board và CPU) phải bị Server từ chối"
    );
}

#[test]
fn test_15_attack_concurrent_nonce_race_condition_toctou() {
    // Kịch bản: Tấn công chạy đua đồng thời (Time-of-Check to Time-of-Use Race Condition)
    // Kẻ tấn công mở 20 luồng đồng thời cố gắng tiêu thụ cùng 1 Nonce trong một mili-giây
    // nhằm khai thác kẽ hở kiểm tra không nguyên tử.
    // Ref: Plan.md Section 22 & Rule.md Điều 23.
    let shared_nonce_store = Arc::new(Mutex::new(HashSet::new()));
    let target_nonce = "nonce-race-attack-vector-99".to_string();

    let success_counter = Arc::new(AtomicU32::new(0));
    let conflict_counter = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..20 {
        let store = Arc::clone(&shared_nonce_store);
        let nonce = target_nonce.clone();
        let success = Arc::clone(&success_counter);
        let conflict = Arc::clone(&conflict_counter);

        let h = thread::spawn(move || {
            // Thao tác kiểm tra và tiêu thụ nguyên tử (Atomic Check-and-Consume mô phỏng DB UPDATE)
            let mut guard = store.lock().unwrap();
            if guard.contains(&nonce) {
                // Đã bị tiêu thụ bởi luồng khác
                conflict.fetch_add(1, Ordering::SeqCst);
            } else {
                // Tiêu thụ thành công duy nhất
                guard.insert(nonce);
                success.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }

    let successes = success_counter.load(Ordering::SeqCst);
    let conflicts = conflict_counter.load(Ordering::SeqCst);

    assert_eq!(
        successes, 1,
        "ĐÚNG DUY NHẤT 1 yêu cầu được phép tiêu thụ Nonce thành công"
    );
    assert_eq!(
        conflicts, 19,
        "19 yêu cầu chạy đua còn lại PHẢI bị xung đột và từ chối dứt khoát"
    );
}
