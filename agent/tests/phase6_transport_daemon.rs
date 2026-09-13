//! CyberV Phase 6 Network Transport & Agent Daemon Tests
//!
//! Ref: Plan.md Section 1, 15, 17, 18, Rule.md Điều 1, 8, 10, 15, 18, 19, 20:
//! 15 bài test toàn diện kiểm chứng:
//! 1. Enrollment protocol & anti-tampering
//! 2. Transport Trait & Mock operations
//! 3. Challenge-response attestation qua mạng
//! 4. Tự động phát hiện biến động phần cứng và kích hoạt re-enrollment
//! 5. Xử lý các mã trạng thái mạng (401, 403, 409, Offline, Timeout)
//! 6. Máy trạng thái Daemon hoàn chỉnh (Unregistered -> Active -> Mutated -> Active)
//! 7. Cách ly không gian tên (Cross-domain protection)

use cyberv_agent::daemon::{AgentDaemon, AgentState};
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::protocol::challenge::{create_challenge_proof, ChallengeObject};
use cyberv_agent::protocol::constants::PURPOSE_DEVICE_AUTH;
use cyberv_agent::protocol::enroll::{
    create_enrollment_request, verify_enrollment_request, DeviceEnrollmentRequest,
};
use cyberv_agent::transport::client::MockDeviceTransport;
use cyberv_agent::transport::error::TransportError;
use cyberv_agent::transport::models::{
    ChallengeResponseDto, EnrollResponseDto, ReenrollResponseDto, VerifyStateResponseDto,
};
use cyberv_agent::transport::traits::DeviceTransport;

// ====================================================================
// Group 1: Enrollment Protocol & Signature Verification Tests
// ====================================================================

#[test]
fn test_01_enrollment_request_creation_and_signature_verification() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-TEST-001";
    let graph_hash = "1".repeat(128);
    let state_hash = "2".repeat(128);
    let graph_version = 1;
    let graph_json = serde_json::json!({ "version": 1, "nodes": [] });

    let req = create_enrollment_request(
        &key,
        device_id,
        &graph_hash,
        &state_hash,
        graph_version,
        graph_json,
    )
    .expect("Create enrollment request failed");

    assert_eq!(req.device_id, device_id);
    assert_eq!(req.proof_signature.len(), 128);

    let verify_res = verify_enrollment_request(key.verifying_key(), &req);
    assert!(
        verify_res.is_ok(),
        "Verification should pass for valid key & payload"
    );
}

#[test]
fn test_02_enrollment_tampered_payload_rejected() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "CYBERV-DEV-TEST-001";
    let graph_hash = "1".repeat(128);
    let state_hash = "2".repeat(128);

    let req = create_enrollment_request(
        &key,
        device_id,
        &graph_hash,
        &state_hash,
        1,
        serde_json::json!({}),
    )
    .expect("Create request failed");

    // Case A: Tampered state hash
    let mut tampered_state = req.clone();
    tampered_state.current_state_hash = "3".repeat(128);
    assert!(
        verify_enrollment_request(key.verifying_key(), &tampered_state).is_err(),
        "Tampered state_hash must fail verification"
    );

    // Case B: Tampered graph hash
    let mut tampered_graph = req.clone();
    tampered_graph.current_graph_hash = "4".repeat(128);
    assert!(
        verify_enrollment_request(key.verifying_key(), &tampered_graph).is_err(),
        "Tampered graph_hash must fail verification"
    );

    // Case C: Tampered version
    let mut tampered_version = req.clone();
    tampered_version.current_graph_version = 2;
    assert!(
        verify_enrollment_request(key.verifying_key(), &tampered_version).is_err(),
        "Tampered version must fail verification"
    );

    // Case D: Corrupted signature
    let mut tampered_sig = req;
    let mut sig_bytes = tampered_sig.proof_signature.into_bytes();
    sig_bytes[0] = if sig_bytes[0] == b'a' { b'b' } else { b'a' };
    tampered_sig.proof_signature = String::from_utf8(sig_bytes).unwrap();
    assert!(
        verify_enrollment_request(key.verifying_key(), &tampered_sig).is_err(),
        "Corrupted signature must fail verification"
    );
}

// ====================================================================
// Group 2: Transport Trait & Mock Operations Tests
// ====================================================================

#[tokio::test]
async fn test_03_http_transport_successful_enrollment() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();

    let req = DeviceEnrollmentRequest {
        device_id: "DEV-001".to_string(),
        public_key_hex: key.public_key_hex(),
        current_graph_hash: "a".repeat(128),
        current_state_hash: "b".repeat(128),
        current_graph_version: 1,
        canonical_graph_json: serde_json::json!({}),
        proof_signature: "c".repeat(128),
    };

    transport
        .set_enroll_response(EnrollResponseDto {
            status: "ACTIVE".to_string(),
            device_id: "DEV-001".to_string(),
            graph_version: Some(1),
            message: Some("Enrolled".to_string()),
        })
        .await;

    let res = transport.enroll_device(&req, "mock_jwt").await;
    assert!(res.is_ok());
    let data = res.unwrap();
    assert_eq!(data.status, "ACTIVE");
    assert_eq!(data.device_id, "DEV-001");

    let rec = transport.get_recorded_requests().await;
    assert_eq!(rec, vec!["enroll:DEV-001".to_string()]);
}

#[tokio::test]
async fn test_04_http_transport_challenge_issuance() {
    let transport = MockDeviceTransport::new();
    transport
        .set_challenge_response(ChallengeResponseDto {
            challenge_id: "chal-123".to_string(),
            nonce: "nonce-456".to_string(),
            issued_at: Some("2026-09-05T00:00:00Z".to_string()),
            expires_at: Some("2026-09-05T00:01:00Z".to_string()),
            purpose: Some(PURPOSE_DEVICE_AUTH.to_string()),
        })
        .await;

    let res = transport
        .request_challenge("DEV-001", PURPOSE_DEVICE_AUTH, "mock_jwt")
        .await;
    assert!(res.is_ok());
    let data = res.unwrap();
    assert_eq!(data.challenge_id, "chal-123");
    assert_eq!(data.nonce, "nonce-456");
}

#[tokio::test]
async fn test_05_http_transport_challenge_response_attestation() {
    let transport = MockDeviceTransport::new();
    transport
        .set_attest_response(VerifyStateResponseDto {
            authenticated: true,
            status: "AUTHENTICATED".to_string(),
            message: Some("State matched".to_string()),
            expected_state_hash: Some("state-abc".to_string()),
            presented_state_hash: Some("state-abc".to_string()),
        })
        .await;

    let proof = cyberv_agent::protocol::challenge::SignedChallengeProof {
        challenge_id: "chal-1".to_string(),
        nonce: "nonce-1".to_string(),
        device_id: "DEV-001".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        state_hash: "state-abc".to_string(),
        graph_version: 1,
        signature_hex: "0".repeat(128),
    };

    let res = transport.submit_attestation(&proof, "mock_jwt").await;
    assert!(res.is_ok());
    let data = res.unwrap();
    assert!(data.authenticated);
    assert_eq!(data.status, "AUTHENTICATED");
}

// ====================================================================
// Group 3: Agent Daemon Autonomous Lifecycle Tests
// ====================================================================

#[tokio::test]
async fn test_06_daemon_initial_enrollment_flow() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-DAEMON-01";

    let mut daemon = AgentDaemon::new(transport, collector, key, device_id, "mock_jwt");
    assert_eq!(*daemon.state(), AgentState::Unregistered);

    let enroll_res = daemon.enroll().await;
    assert!(enroll_res.is_ok());

    match daemon.state() {
        AgentState::Active {
            graph_version,
            state_hash,
            ..
        } => {
            assert_eq!(*graph_version, 1);
            assert_eq!(state_hash.len(), 128);
        }
        _ => panic!("Expected AgentState::Active after enrollment"),
    }
}

#[tokio::test]
async fn test_07_daemon_tick_with_stable_hardware_performs_attestation() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-DAEMON-02";

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, device_id, "mock_jwt");

    // Tick 1: Unregistered -> Enrolls -> Active
    let state1 = daemon.tick().await.unwrap();
    assert!(matches!(state1, AgentState::Active { .. }));

    // Tick 2: Active with same hardware -> Attests -> Stays Active
    let state2 = daemon.tick().await.unwrap();
    assert!(matches!(state2, AgentState::Active { .. }));

    let recorded = transport.get_recorded_requests().await;
    assert!(recorded.contains(&format!("enroll:{}", device_id)));
    assert!(recorded.contains(&format!("challenge:{}:{}", device_id, PURPOSE_DEVICE_AUTH)));
    assert!(recorded.contains(&format!("verify-state:{}", device_id)));
}

#[tokio::test]
async fn test_08_daemon_hardware_mutation_triggers_auto_promote() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-DAEMON-03";

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, device_id, "mock_jwt");
    daemon.enroll().await.unwrap();
    assert_eq!(daemon.current_graph_version(), 1);

    // Simulate RAM upgrade by switching collector on the same daemon
    daemon.set_collector(MockHardwareCollector::ram_upgrade().unwrap());

    // Server returns AUTO_PROMOTE
    transport
        .set_reenroll_response(ReenrollResponseDto {
            status: "ACTIVE".to_string(),
            decision: Some("AUTO_PROMOTE".to_string()),
            request_id: None,
            message: Some("Promoted".to_string()),
            error: None,
        })
        .await;

    let state = daemon.tick().await.unwrap();
    match state {
        AgentState::Active { graph_version, .. } => {
            assert_eq!(graph_version, 2, "Graph version must be promoted to 2");
        }
        _ => panic!("Expected AgentState::Active after auto-promotion"),
    }
}

#[tokio::test]
async fn test_09_daemon_hardware_mutation_pending_approval() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-DAEMON-04";

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, device_id, "mock_jwt");
    daemon.enroll().await.unwrap();

    // Mutate to RAM upgrade
    daemon.set_collector(MockHardwareCollector::ram_upgrade().unwrap());

    // Server returns PENDING_APPROVAL
    transport
        .set_reenroll_response(ReenrollResponseDto {
            status: "PENDING_APPROVAL".to_string(),
            decision: Some("REQUIRES_USER_APPROVAL".to_string()),
            request_id: Some("req-approval-999".to_string()),
            message: Some("Pending user confirmation".to_string()),
            error: None,
        })
        .await;

    let state = daemon.tick().await.unwrap();
    match state {
        AgentState::PendingApproval { request_id, .. } => {
            assert_eq!(request_id, Some("req-approval-999".to_string()));
        }
        _ => panic!("Expected AgentState::PendingApproval"),
    }
}

#[tokio::test]
async fn test_10_daemon_hardware_mutation_rejected_by_policy() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-DAEMON-05";

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, device_id, "mock_jwt");
    daemon.enroll().await.unwrap();

    // Mutate to RAM upgrade
    daemon.set_collector(MockHardwareCollector::ram_upgrade().unwrap());

    // Server returns REJECTED
    transport
        .set_reenroll_response(ReenrollResponseDto {
            status: "REJECTED".to_string(),
            decision: Some("REJECTED".to_string()),
            request_id: None,
            message: None,
            error: Some("Critical risk violation".to_string()),
        })
        .await;

    let state = daemon.tick().await.unwrap();
    match state {
        AgentState::SuspendedOrRejected { reason } => {
            assert!(reason.contains("Critical risk violation"));
        }
        _ => panic!("Expected AgentState::SuspendedOrRejected"),
    }
}

// ====================================================================
// Group 4: Network Error Handling & Offline Resilience Tests
// ====================================================================

#[tokio::test]
async fn test_11_transport_401_unauthorized_handling() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, "DEV-006", "expired_jwt");

    // Force 401 Unauthorized
    transport
        .set_forced_error(Some(TransportError::Unauthorized))
        .await;

    let res = daemon.enroll().await;
    assert_eq!(res, Err(TransportError::Unauthorized));
}

#[tokio::test]
async fn test_12_transport_offline_network_failure_handling() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, "DEV-007", "mock_jwt");
    daemon.enroll().await.unwrap();

    // Now disconnect network during attestation tick
    transport
        .set_forced_error(Some(TransportError::NetworkFailure(
            "DNS lookup failed".to_string(),
        )))
        .await;

    let state = daemon.tick().await.unwrap();
    match state {
        AgentState::OfflineGracePeriod {
            consecutive_failures,
            ..
        } => {
            assert_eq!(consecutive_failures, 1);
        }
        _ => panic!("Expected AgentState::OfflineGracePeriod on network drop"),
    }
}

#[tokio::test]
async fn test_13_offline_grace_period_recovery() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, "DEV-008", "mock_jwt");
    daemon.enroll().await.unwrap();

    // Drop network
    transport
        .set_forced_error(Some(TransportError::Timeout))
        .await;
    let _ = daemon.tick().await.unwrap();
    assert!(matches!(
        daemon.state(),
        AgentState::OfflineGracePeriod { .. }
    ));

    // Restore network
    transport.set_forced_error(None).await;
    let state = daemon.tick().await.unwrap();
    assert!(
        matches!(state, AgentState::Active { .. }),
        "Daemon should recover to Active when network restores"
    );
}

// ====================================================================
// Group 5: Cross-Domain & End-to-End Simulation Tests
// ====================================================================

#[test]
fn test_14_cross_domain_signature_rejected_in_enrollment() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let device_id = "DEV-009";
    let state_hash = "f".repeat(128);

    // Create a challenge proof meant for PURPOSE_DEVICE_AUTH
    let challenge = ChallengeObject {
        challenge_id: "chal-1".to_string(),
        nonce: "nonce-1".to_string(),
        device_id: device_id.to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 100,
        expires_at: 200,
    };
    let chal_proof =
        create_challenge_proof(&key, &challenge, &state_hash, 1).expect("Create chal proof failed");

    // Attempt to forge enrollment request with the challenge proof signature
    let forged_enroll_req = DeviceEnrollmentRequest {
        device_id: device_id.to_string(),
        public_key_hex: key.public_key_hex(),
        current_graph_hash: "0".repeat(128),
        current_state_hash: state_hash,
        current_graph_version: 1,
        canonical_graph_json: serde_json::json!({}),
        proof_signature: chal_proof.signature_hex, // Stolen signature from device-auth!
    };

    // Verification must strictly fail due to domain separation (DOMAIN_AUTH != DOMAIN_ENROLL)
    let verify_res = verify_enrollment_request(key.verifying_key(), &forged_enroll_req);
    assert!(
        verify_res.is_err(),
        "Cross-domain signature substitution must be strictly rejected"
    );
}

#[tokio::test]
async fn test_15_end_to_end_daemon_full_lifecycle() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let transport = MockDeviceTransport::new();
    let collector = MockHardwareCollector::baseline().unwrap();
    let device_id = "DEV-E2E-LIFECYCLE";

    let mut daemon = AgentDaemon::new(transport.clone(), collector, key, device_id, "mock_jwt");

    // 1. Initial Tick -> Auto-Enroll -> Active (v1)
    let s1 = daemon.tick().await.unwrap();
    assert!(matches!(
        s1,
        AgentState::Active {
            graph_version: 1,
            ..
        }
    ));

    // 2. Periodic Attestation Tick -> Active (v1)
    let s2 = daemon.tick().await.unwrap();
    assert!(matches!(
        s2,
        AgentState::Active {
            graph_version: 1,
            ..
        }
    ));

    // 3. Hardware mutation occurs: switch collector to RAM upgrade
    daemon.set_collector(MockHardwareCollector::ram_upgrade().unwrap());

    // 4. Tick detects mutation -> Re-enrolls -> Promotes to v2 -> Active (v2)
    let s3 = daemon.tick().await.unwrap();
    assert!(matches!(
        s3,
        AgentState::Active {
            graph_version: 2,
            ..
        }
    ));

    // 5. Subsequent Tick on v2 -> Periodic Attestation on v2 -> Stays Active (v2)
    let s4 = daemon.tick().await.unwrap();
    assert!(matches!(
        s4,
        AgentState::Active {
            graph_version: 2,
            ..
        }
    ));
}
