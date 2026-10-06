// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
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
    // P1-3: audit đo THẬT qua GetExtendedTcpTable (PID hiện tại)
    let report = NetworkSurfaceInspector::audit_network_surface();
    assert!(!report.has_inbound_listener);
    assert_eq!(report.network_surface_score, 10000);
    assert!(report.summary.contains("queried"), "{}", report.summary);
}

#[test]
fn test_02_inbound_listener_semantics() {
    // P1-3: tự mở 1 listener thật trên loopback rồi audit PHẢI phát hiện
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();

    let report = NetworkSurfaceInspector::audit_network_surface();
    assert!(report.has_inbound_listener, "listener trên port {} phải được phát hiện", port);
    assert!(report.inbound_ports.contains(&port));
    assert_eq!(report.network_surface_score, 2000);
    // Drop listener -> các test khác không bị ảnh hưởng
    drop(listener);
}

#[test]
fn test_03_outbound_payload_size_limit_enforced() {
    let report = NetworkSurfaceInspector::audit_network_surface();
    assert_eq!(report.max_payload_bytes, 1048576); // 1 MB
    assert_eq!(report.timeout_seconds, 10);
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
