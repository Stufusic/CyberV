//! Phase 24C: Network Surface & Hardened IPC Tests
//!
//! Ref: Docs/rv13.md Section 5 & Docs/rv12.md Section 2:
//! Validates:
//! - "No inbound listener by default" audit
//! - Outbound payload bounds & strict timeouts
//! - Named Pipe DACL & Client Token authorization
//! - IPC message schema bounds (max 64KB)

use cyberv_agent::defense::passive::ipc::{
    IpcAuthorizer, IpcCommand, IpcMessageEnvelope, IpcProtocolError, IpcProtocolValidator,
    PipeAclManager, MAX_IPC_MESSAGE_SIZE,
};
use cyberv_agent::defense::passive::network_surface::NetworkSurfaceInspector;

#[test]
fn test_01_no_inbound_listening_ports_optimal() {
    let empty_listeners = vec![];
    let report = NetworkSurfaceInspector::audit_network_surface(empty_listeners);
    assert!(!report.has_inbound_listener);
    assert_eq!(report.network_surface_score, 10000);
}

#[test]
fn test_02_inbound_listener_detected_penalizes_score() {
    // Rogue open port 8080 detected on Agent PID
    let listening_ports = vec![8080];
    let report = NetworkSurfaceInspector::audit_network_surface(listening_ports);
    assert!(report.has_inbound_listener);
    assert_eq!(report.network_surface_score, 2000);
}

#[test]
fn test_03_outbound_payload_size_limit_enforced() {
    let empty_listeners = vec![];
    let report = NetworkSurfaceInspector::audit_network_surface(empty_listeners);
    assert!(report.is_outbound_constrained);
    assert_eq!(report.max_payload_bytes, 1048576); // 1 MB
}

#[test]
fn test_04_hardened_pipe_dacl_created() {
    let desc = PipeAclManager::create_hardened_pipe_descriptor("\\\\.\\pipe\\CyberV_IPC");
    assert!(desc.allows_system);
    assert!(desc.allows_current_user);
    assert!(desc.denies_everyone);
    assert!(desc.denies_network_logon);
    assert!(desc.is_hardened);
}

#[test]
fn test_05_ipc_client_authorization_known_component_success() {
    let identity = IpcAuthorizer::authorize_client(
        1234,
        "S-1-5-21-12345-67890",
        "CyberVWatchdog.exe",
        "S-1-5-21-12345-67890",
    );
    assert!(identity.is_authenticated);
    assert_eq!(identity.client_pid, 1234);
}

#[test]
fn test_06_ipc_client_authorization_unknown_component_rejected() {
    let identity = IpcAuthorizer::authorize_client(
        5555,
        "S-1-5-21-12345-67890",
        "MaliciousPayload.exe",
        "S-1-5-21-12345-67890",
    );
    assert!(!identity.is_authenticated);
}

#[test]
fn test_07_ipc_message_deserialization_success() {
    let env = IpcMessageEnvelope {
        message_id: "msg_123".to_string(),
        command: IpcCommand::GetStatus,
        sender_pid: 1234,
        timestamp: 1700000000,
    };
    let json = serde_json::to_vec(&env).unwrap();
    let parsed = IpcProtocolValidator::parse_and_validate(&json).unwrap();
    assert_eq!(parsed.message_id, "msg_123");
    assert_eq!(parsed.command, IpcCommand::GetStatus);
}

#[test]
fn test_08_ipc_oversized_message_rejected() {
    let oversized = vec![0x41u8; MAX_IPC_MESSAGE_SIZE + 1];
    let res = IpcProtocolValidator::parse_and_validate(&oversized);
    assert_eq!(
        res.unwrap_err(),
        IpcProtocolError::MessageTooLarge(MAX_IPC_MESSAGE_SIZE + 1)
    );
}
