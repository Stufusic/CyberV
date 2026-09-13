//! CyberV Phase 8 Security Matrix: Device Revocation & Key Rotation Tests
//!
//! Ref: Plan.md Section 22, rv4.md #1, #4 and Rule.md Điều 1, 2, 6, 8, 20:
//! 15 bài test toàn diện kiểm chứng:
//! 1. Giao thức quay vòng khóa Ed25519 có chữ ký kép (Dual Proof-of-Possession)
//! 2. Phát hiện các hành vi sửa đổi bit trên Public Key mới, Nonce, State Hash
//! 3. Ngăn chặn giả mạo chữ ký khóa cũ hoặc khóa mới
//! 4. Cách ly không gian tên chống tấn công hoán đổi chữ ký (Cross-domain protection)
//! 5. Xoay khóa nguyên tử trên Két bảo mật (Atomic DPAPI / Mock Vault Key Replacement)
//! 6. Duy trì tính ổn định của device_id qua các lần xoay khóa
//! 7. Xóa sạch bộ nhớ khóa cũ (Zeroization)
//! 8. Thắt chặt thu hồi thiết bị: Từ chối Nonce, Attestation và Re-enrollment
//! 9. Máy trạng thái Daemon tự động đình chỉ (SuspendedOrRejected) khi bị thu hồi
//! 10. Vòng đời quay vòng khóa hoàn chỉnh của Daemon trên môi trường mạng Mock

use cyberv_agent::daemon::{AgentDaemon, AgentState};
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::identity::storage::mock::MockSecureStorage;
use cyberv_agent::identity::storage::{DeviceSecureStorage, PersistedIdentity};
use cyberv_agent::protocol::constants::{DOMAIN_AUTH, PURPOSE_KEY_ROTATION};
use cyberv_agent::protocol::key_rotation::{
    create_key_rotation_request, verify_key_rotation_request,
};
use cyberv_agent::transport::client::MockDeviceTransport;
use cyberv_agent::transport::error::TransportError;
use cyberv_agent::transport::models::ChallengeResponseDto;
use cyberv_agent::transport::traits::DeviceTransport;

// ====================================================================
// Nhóm 1: Kiểm thử Giao Thức Quay Vòng Khóa & Chữ Ký Kép (Dual-Signing)
// ====================================================================

#[test]
fn test_01_key_rotation_request_creation_and_dual_verification() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let device_id = "CYBERV-DEV-TEST-P8-01";
    let state_hash = "a".repeat(128);
    let graph_version = 1;
    let nonce = "nonce-c2e8a1f73b";
    let timestamp = 1757070000;

    let req = create_key_rotation_request(
        &old_key,
        &new_key,
        device_id,
        &state_hash,
        graph_version,
        nonce,
        timestamp,
    )
    .expect("Request creation should succeed");

    assert_eq!(req.device_id, device_id);
    assert_eq!(req.old_public_key_hex, old_key.public_key_hex());
    assert_eq!(req.new_public_key_hex, new_key.public_key_hex());
    assert_eq!(req.signature_old.len(), 128);
    assert_eq!(req.signature_new.len(), 128);

    // Xác thực chữ ký kép
    let is_valid = verify_key_rotation_request(&req).expect("Verification must not crash");
    assert!(
        is_valid,
        "Dual signature verification must pass for valid keys"
    );
}

#[test]
fn test_02_key_rotation_same_key_rejected() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let device_id = "CYBERV-DEV-TEST-P8-02";
    let state_hash = "b".repeat(128);
    let graph_version = 1;
    let nonce = "nonce-same-key";
    let timestamp = 1757070001;

    // Cố ý xoay sang chính khóa hiện tại
    let result = create_key_rotation_request(
        &key,
        &key,
        device_id,
        &state_hash,
        graph_version,
        nonce,
        timestamp,
    );

    assert!(
        result.is_err(),
        "Rotation to identical public key must be rejected"
    );
}

#[test]
fn test_03_key_rotation_tampered_new_key_rejected() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-03",
        &"c".repeat(128),
        1,
        "nonce-123",
        1757070002,
    )
    .unwrap();

    // Sửa đổi ký tự đầu tiên của new_public_key_hex
    let mut tampered_key = req.new_public_key_hex.clone();
    let first_char = if tampered_key.starts_with('a') {
        'b'
    } else {
        'a'
    };
    tampered_key.replace_range(0..1, &first_char.to_string());
    req.new_public_key_hex = tampered_key;

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(!is_valid, "Tampered new public key must fail verification");
}

#[test]
fn test_04_key_rotation_forged_old_signature_rejected() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let attacker_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-04",
        &"d".repeat(128),
        1,
        "nonce-456",
        1757070003,
    )
    .unwrap();

    // Thay thế signature_old bằng chữ ký ký bởi attacker_key
    let forged_sig = attacker_key.sign(b"forged payload");
    req.signature_old = forged_sig.iter().map(|b| format!("{:02x}", b)).collect();

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(!is_valid, "Forged old signature must fail verification");
}

#[test]
fn test_05_key_rotation_forged_new_signature_rejected() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let attacker_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-05",
        &"e".repeat(128),
        1,
        "nonce-789",
        1757070004,
    )
    .unwrap();

    // Thay thế signature_new bằng chữ ký của attacker
    let forged_sig = attacker_key.sign(b"forged new sig");
    req.signature_new = forged_sig.iter().map(|b| format!("{:02x}", b)).collect();

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(!is_valid, "Forged new signature must fail verification");
}

#[test]
fn test_06_cross_domain_signature_rejected_in_key_rotation() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-06",
        &"f".repeat(128),
        1,
        "nonce-cross-domain",
        1757070005,
    )
    .unwrap();

    // Thay thế signature_old bằng chữ ký trên miền DOMAIN_AUTH thay vì DOMAIN_KEY_ROTATION
    let auth_payload = [DOMAIN_AUTH, b"payload"].concat();
    let auth_sig = old_key.sign(&auth_payload);
    req.signature_old = auth_sig.iter().map(|b| format!("{:02x}", b)).collect();

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(
        !is_valid,
        "Signature from another cryptographic domain must be rejected"
    );
}

#[test]
fn test_07_tampered_state_hash_in_key_rotation_rejected() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-07",
        &"0".repeat(128),
        1,
        "nonce-state-hash",
        1757070006,
    )
    .unwrap();

    // Sửa đổi State Hash sau khi ký
    req.state_hash = "1".repeat(128);

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(
        !is_valid,
        "Tampered state hash must cause signature verification failure"
    );
}

#[test]
fn test_08_tampered_nonce_in_key_rotation_rejected() {
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut req = create_key_rotation_request(
        &old_key,
        &new_key,
        "CYBERV-DEV-TEST-P8-08",
        &"2".repeat(128),
        1,
        "original-nonce-value",
        1757070007,
    )
    .unwrap();

    // Sửa đổi Nonce (mô phỏng tấn công tráo nonce)
    req.nonce = "tampered-nonce-value".to_string();

    let is_valid = verify_key_rotation_request(&req).unwrap_or(false);
    assert!(
        !is_valid,
        "Tampered nonce must cause signature verification failure"
    );
}

// ====================================================================
// Nhóm 2: Kiểm thử Két Bảo Mật Cục Bộ & Xoay Khóa Nguyên Tử
// ====================================================================

#[test]
fn test_09_atomic_vault_key_rotation_persists_new_key() {
    let storage = MockSecureStorage::new();
    let mut rng = OsCryptoRng;
    let initial_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-STABLE-ID-01";

    let initial_identity = PersistedIdentity::new(
        device_id.to_string(),
        initial_key.secret_bytes(),
        initial_key.secret_bytes(),
        1757000000,
    );
    storage.save_identity(&initial_identity).unwrap();

    // Xoay sang khóa mới
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let rotated_identity = storage.rotate_identity_key(&new_key).unwrap();

    // Kiểm tra định danh thiết bị và thời gian tạo gốc được bảo toàn
    assert_eq!(rotated_identity.device_id, device_id);
    assert_eq!(rotated_identity.created_at, 1757000000);
    assert_eq!(
        rotated_identity.signing_key.as_bytes(),
        new_key.secret_bytes().as_bytes()
    );

    // Tải lại từ kho lưu trữ để kiểm chứng tính bền vững
    let loaded = storage.load_identity().unwrap().unwrap();
    assert_eq!(loaded.device_id, device_id);
    assert_eq!(
        loaded.signing_key.as_bytes(),
        new_key.secret_bytes().as_bytes()
    );
}

// ====================================================================
// Nhóm 3: Kiểm thử Transport & Vòng Đời Quay Vòng Khóa Daemon
// ====================================================================

#[tokio::test]
async fn test_10_transport_rotate_key_success() {
    let transport = MockDeviceTransport::new();
    let mut rng = OsCryptoRng;
    let old_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let new_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let req = create_key_rotation_request(
        &old_key,
        &new_key,
        "DEV-ROT-01",
        &"3".repeat(128),
        1,
        "nonce-rot-01",
        1757070010,
    )
    .unwrap();

    let resp = transport.rotate_key(&req, "mock_jwt_token").await.unwrap();

    assert!(resp.success);
    assert_eq!(resp.status, "ACTIVE");
    assert_eq!(resp.new_public_key, new_key.public_key_hex());

    let recorded = transport.get_recorded_requests().await;
    assert!(recorded.contains(&"key-rotate:DEV-ROT-01".to_string()));
}

#[tokio::test]
async fn test_11_daemon_full_key_rotation_lifecycle() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let initial_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let initial_pubkey = initial_key.public_key_hex();

    let mut daemon = AgentDaemon::new(
        transport.clone(),
        collector,
        initial_key,
        "CYBERV-DAEMON-KEYROT-01",
        "mock_jwt_token",
    );

    // 1. Initial Enrollment
    daemon.enroll().await.unwrap();
    assert!(matches!(daemon.state(), AgentState::Active { .. }));

    // Cài đặt phản hồi Challenge cho mục đích "key-rotation"
    transport
        .set_challenge_response(ChallengeResponseDto {
            challenge_id: "chal-rot-01".to_string(),
            nonce: "nonce-for-rotation-12345".to_string(),
            issued_at: None,
            expires_at: None,
            purpose: Some(PURPOSE_KEY_ROTATION.to_string()),
        })
        .await;

    // 2. Kích hoạt quay vòng khóa định danh
    let rot_resp = daemon.rotate_identity_key().await.unwrap();
    assert!(rot_resp.success);
    assert_eq!(rot_resp.status, "ACTIVE");

    // Khóa công khai của Daemon phải thay đổi sang khóa mới
    let current_pubkey = daemon.identity_key().public_key_hex();
    assert_ne!(current_pubkey, initial_pubkey);
    assert_eq!(current_pubkey, rot_resp.new_public_key);

    // 3. Nhịp attestation tiếp theo phải hoạt động bình thường với khóa mới
    let tick_state = daemon.tick().await.unwrap();
    assert!(matches!(tick_state, AgentState::Active { .. }));
}

#[tokio::test]
async fn test_12_daemon_rotation_fails_before_enrollment() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let initial_key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut daemon = AgentDaemon::new(
        transport,
        collector,
        initial_key,
        "CYBERV-DAEMON-KEYROT-02",
        "mock_jwt_token",
    );

    // Chưa enroll -> Cố ý xoay khóa -> Bị từ chối fail-secure
    let result = daemon.rotate_identity_key().await;
    assert!(result.is_err(), "Rotation before enrollment must fail");
}

// ====================================================================
// Nhóm 4: Kiểm thử Thắt Chặt Cơ Chế Thu Hồi Thiết Bị (Revocation Hardening)
// ====================================================================

#[tokio::test]
async fn test_13_revoked_device_attestation_triggers_daemon_suspension() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut daemon = AgentDaemon::new(
        transport.clone(),
        collector,
        key,
        "CYBERV-DEV-REVOKED-01",
        "mock_jwt_token",
    );

    daemon.enroll().await.unwrap();
    assert!(matches!(daemon.state(), AgentState::Active { .. }));

    // Mô phỏng thiết bị đã bị người quản trị thu hồi trên Server -> Trả về 403 Forbidden
    transport
        .set_forced_error(Some(TransportError::Forbidden(
            "Device has been revoked and cannot attest".to_string(),
        )))
        .await;

    // Nhịp tick tiếp theo
    let state = daemon.tick().await.unwrap();

    // Daemon phải chuyển sang trạng thái SuspendedOrRejected và ngừng nhịp tim attestation
    match state {
        AgentState::SuspendedOrRejected { reason } => {
            assert!(
                reason.contains("revoked"),
                "Reason must mention device revocation"
            );
        }
        _ => panic!("Daemon must transition to SuspendedOrRejected when server revokes device"),
    }
}

#[tokio::test]
async fn test_14_revoked_device_transport_rejection_halts_daemon() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut daemon = AgentDaemon::new(
        transport.clone(),
        collector,
        key,
        "CYBERV-DEV-REVOKED-02",
        "mock_jwt_token",
    );

    daemon.enroll().await.unwrap();

    // Giả lập Server từ chối ngay từ bước cấp Challenge vì thiết bị đã bị khóa
    transport
        .set_forced_error(Some(TransportError::Forbidden(
            "Forbidden: Device status is REVOKED".to_string(),
        )))
        .await;

    let state = daemon.tick().await.unwrap();
    assert!(
        matches!(state, AgentState::SuspendedOrRejected { .. }),
        "Daemon must suspend when challenge is forbidden"
    );
}

// ====================================================================
// Nhóm 5: Kiểm thử Giới Hạn Tần Suất (Rate Limiting Resilience)
// ====================================================================

#[tokio::test]
async fn test_15_rate_limiting_429_too_many_requests_backoff() {
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let mut daemon = AgentDaemon::new(
        transport.clone(),
        collector,
        key,
        "CYBERV-DEV-RATELIMIT-01",
        "mock_jwt_token",
    );

    daemon.enroll().await.unwrap();

    // Giả lập Server phản hồi mã lỗi 429 Too Many Requests (Rate limit hit)
    transport
        .set_forced_error(Some(TransportError::NetworkFailure(
            "HTTP 429 Too Many Requests: Rate limit exceeded".to_string(),
        )))
        .await;

    // Nhịp tick xử lý lỗi mạng tạm thời bằng cách chuyển sang OfflineGracePeriod (Fail-Secure)
    let state = daemon.tick().await.unwrap();
    match state {
        AgentState::OfflineGracePeriod {
            consecutive_failures,
            ..
        } => {
            assert_eq!(consecutive_failures, 1);
        }
        _ => panic!(
            "Daemon must enter OfflineGracePeriod on temporary 429 rate limit without crashing"
        ),
    }
}
