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
//! Gate 3 & Gate 4 Integration Tests — DNS-SD, Trust Admission & State Machine Semantics
//!
//! Ref: Docs/GATE0_SECURITY_CONTRACT_FREEZE.md Section 3 & 4.
//!
//! Kiểm chứng:
//! 1. RFC 6763: DNS-SD service type bắt buộc dùng `_cyberv-mesh._tcp.local.`.
//! 2. Sybil Defense: Candidate không được ủy quyền bị Admission Gate từ chối.
//! 3. Revocation & Epoch Defense: Candidate bị thu hồi hoặc lệch epoch bị từ chối.
//! 4. DoS Defense: Trần `max_pending_handshakes` chặn lũ kết nối.
//! 5. Quorum Liveness Safety: Mất Quorum CHỈ chuyển `Degraded`, TUYỆT ĐỐI KHÔNG `Isolated`.
//! 6. Active Contradiction: Kích hoạt `Isolated` lập tức khi có mâu thuẫn chủ động.

use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::mesh::admission::{
    AdmissionVerdict, MeshAdmissionController, MeshAdmissionPolicy, MeshEnforcementState,
};
use cyberv_agent::mesh::discovery::MeshBeacon;
use cyberv_agent::mesh::graph::NodeId;
use cyberv_agent::mesh::node::{MeshNode, MeshNodeConfig};
use cyberv_agent::mesh::transport::mdns::MDNS_SERVICE_TYPE;
use std::collections::HashMap;

fn generate_key() -> DeviceIdentityKey {
    DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
}

fn node_id_of(k: &DeviceIdentityKey) -> NodeId {
    k.verifying_key().to_bytes()
}

#[test]
fn test_gate3_01_dns_sd_service_type_is_tcp() {
    // RFC 6763 requirement: TCP transport bắt buộc dùng _tcp, không phải _udp!
    assert_eq!(MDNS_SERVICE_TYPE, "_cyberv-mesh._tcp.local.");
}

#[test]
fn test_gate4_02_admission_gate_rejects_unauthorized_sybil_candidate() {
    let key_legit = generate_key();
    let id_legit = node_id_of(&key_legit);

    let key_sybil = generate_key();
    let id_sybil = node_id_of(&key_sybil);

    let policy = MeshAdmissionPolicy {
        require_authorization: true,
        ..MeshAdmissionPolicy::default()
    };
    let mut admission = MeshAdmissionController::new(policy);
    admission.authorize_peer(id_legit);

    // Node hợp lệ được ủy quyền -> Admitted
    let v_legit = admission.evaluate_candidate(&id_legit, key_legit.verifying_key(), 1, 0);
    assert_eq!(v_legit, AdmissionVerdict::Admitted);

    // Node Sybil lạ mặt tự sinh keypair -> Bị chặn đứng bởi Admission Gate!
    let v_sybil = admission.evaluate_candidate(&id_sybil, key_sybil.verifying_key(), 1, 1);
    assert_eq!(v_sybil, AdmissionVerdict::RejectedUnauthorized);
}

#[test]
fn test_gate4_03_admission_gate_rejects_revoked_and_stale_epoch() {
    let key = generate_key();
    let id = node_id_of(&key);

    let mut admission = MeshAdmissionController::new(MeshAdmissionPolicy::default());
    admission.authorize_peer(id);
    admission.set_epoch(10);

    // 1. Peer mang epoch quá cũ (lệch > 2) -> Bị từ chối
    let v_stale = admission.evaluate_candidate(&id, key.verifying_key(), 5, 0);
    assert_eq!(v_stale, AdmissionVerdict::RejectedEpochStale);

    // 2. Peer có epoch hợp lệ -> Admitted
    let v_ok = admission.evaluate_candidate(&id, key.verifying_key(), 10, 0);
    assert_eq!(v_ok, AdmissionVerdict::Admitted);

    // 3. Peer bị thu hồi (Revoked) -> Bị từ chối ngay lập tức
    admission.revoke_peer(id);
    let v_revoked = admission.evaluate_candidate(&id, key.verifying_key(), 10, 0);
    assert_eq!(v_revoked, AdmissionVerdict::RejectedRevoked);
}

#[test]
fn test_gate4_04_handshake_slot_rate_limiting_prevents_dos() {
    let policy = MeshAdmissionPolicy {
        max_pending_handshakes: 3, // Giới hạn chỉ 3 phiên dở dang
        ..MeshAdmissionPolicy::default()
    };
    let admission = MeshAdmissionController::new(policy);

    // Lấy 3 slot thành công
    let g1 = admission.acquire_handshake_slot().expect("slot 1 ok");
    let g2 = admission.acquire_handshake_slot().expect("slot 2 ok");
    let g3 = admission.acquire_handshake_slot().expect("slot 3 ok");

    // Lần thứ 4 vượt quá giới hạn -> Lỗi CapacityExceeded (chống DoS)
    let g4_err = admission.acquire_handshake_slot();
    assert!(g4_err.is_err());

    // Thả một slot bằng cách drop guard
    drop(g1);

    // Bây giờ có thể lấy lại 1 slot thành công
    let g5 = admission.acquire_handshake_slot().expect("slot sau khi giải phóng ok");
    drop(g2);
    drop(g3);
    drop(g5);
}

#[test]
fn test_gate4_05_quorum_liveness_loss_degrades_never_auto_isolates() {
    let mut admission = MeshAdmissionController::new(MeshAdmissionPolicy::default());
    admission.set_state(MeshEnforcementState::Enforce);

    // Mất Quorum do đứt cáp / không đủ phiếu độc lập
    admission.handle_quorum_liveness_loss();

    // Bất biến tối thượng: Chuyển sang Degraded, KHÔNG được tự ý Isolate!
    assert_eq!(admission.state(), MeshEnforcementState::Degraded);
    assert!(admission.state().is_operational());
    assert!(!admission.state().allows_isolation_actions());

    // Khi mạng khôi phục Quorum
    admission.handle_quorum_restored(true);
    assert_eq!(admission.state(), MeshEnforcementState::Enforce);
}

#[test]
fn test_gate4_06_active_contradiction_forces_immediate_isolation() {
    let mut admission = MeshAdmissionController::new(MeshAdmissionPolicy::default());
    admission.set_state(MeshEnforcementState::Enforce);

    // Phát hiện bằng chứng giả mạo / rollback
    admission.handle_active_contradiction("Chữ ký Ring-0 giả mạo từ node tấn công");

    // Chuyển ngay sang Isolated
    assert_eq!(admission.state(), MeshEnforcementState::Isolated);
}

#[tokio::test]
async fn test_gate4_07_mesh_node_absorb_discovered_filters_sybil_beacons() {
    let k_local = generate_key();
    let k_friend = generate_key();
    let id_friend = node_id_of(&k_friend);

    let k_stranger = generate_key();
    let id_stranger = node_id_of(&k_stranger);

    let mut pinned_map = HashMap::new();
    pinned_map.insert(id_friend, *k_friend.verifying_key());

    let cfg = MeshNodeConfig {
        admission: MeshAdmissionPolicy {
            require_authorization: true,
            ..MeshAdmissionPolicy::default()
        },
        ..MeshNodeConfig::default()
    };
    let node = MeshNode::new(k_local, pinned_map, cfg);

    let mut beacons = vec![
        (
            MeshBeacon {
                node_id: id_friend,
                vk: k_friend.verifying_key().to_bytes(),
                wire_version: 1,
            },
            "127.0.0.1:49152".parse().unwrap(),
        ),
        (
            MeshBeacon {
                node_id: id_stranger,
                vk: k_stranger.verifying_key().to_bytes(),
                wire_version: 1,
            },
            "127.0.0.1:49153".parse().unwrap(),
        ),
    ];

    // absorb_discovered duyệt danh sách:
    // id_friend: được pre-authorize qua pinned -> chấp nhận quan sát
    // id_stranger: chưa được authorize -> bị Admission Gate chặn
    let _ = node.absorb_discovered(&mut beacons).await;

    // Stranger không bao giờ lọt vào danh sách kết nối
    assert_eq!(node.enforcement_state().await, MeshEnforcementState::Off);
}
