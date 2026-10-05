//! NSG-1 — MeshGraph integration tests
//!
//! Ref: plan v2 §3 (state machine fail-closed), §8 M10/M11 (bound + accounting),
//! §9 (TTL tuyệt đối, auto-lift). Mọi test đều chứng minh nhánh bị tấn công
//! bị từ chối, không chỉ happy path (quy tắc AGENTS.md §2.7).

use cyberv_agent::mesh::graph::{
    EdgeState, MeshGraph, NodeId, NodeState, EDGE_STALE_MS, ISOLATION_TTL_MS, MAX_EDGES,
    MAX_NODES,
};
use cyberv_agent::mesh::MeshError;

fn nid(seed: u8) -> NodeId {
    let mut n = [0u8; 32];
    n[0] = seed;
    n
}

// ====================================================================
// Nhóm 1: Máy trạng thái fail-closed
// ====================================================================

#[test]
fn test_01_full_lifecycle_with_signed_recovery_path() {
    let mut g = MeshGraph::new();
    assert_eq!(g.observe(nid(1), 1000).unwrap(), NodeState::Discovered);
    assert_eq!(g.transition(&nid(1), NodeState::Attested).unwrap(), NodeState::Attested);
    assert_eq!(g.transition(&nid(1), NodeState::Suspect).unwrap(), NodeState::Suspect);
    assert_eq!(
        g.isolate_with_ttl(&nid(1), 2000, ISOLATION_TTL_MS).unwrap(),
        NodeState::Isolated
    );
    // Recovery có chữ ký authority — graph chỉ giữ bất biến, caller verify chữ ký.
    assert_eq!(g.recover(&nid(1)).unwrap(), NodeState::Attested);
    assert_eq!(g.node(&nid(1)).unwrap().isolated_until_mono_ms, None);
}

#[test]
fn test_02_illegal_transitions_rejected() {
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap(); // Discovered

    // M-PLAN §6.3: Discovered → Suspect là CHIỀU XẤU HƠN (probation sau cách
    // ly) nên ĐƯỢC phép — không phải nhảy cóc nâng trust.
    g.transition(&nid(1), NodeState::Suspect).unwrap();
    // ... nhưng Isolated vẫn không thể từ Discovered/Suspect mới vào (qua
    // bảng §3 isolate phải đi từ Suspect với TTL).
    let mut g2 = MeshGraph::new();
    g2.observe(nid(1), 1000).unwrap();
    assert!(matches!(
        g2.transition(&nid(1), NodeState::Isolated),
        Err(MeshError::IllegalTransition { .. })
    ));

    // Đi đúng từng nấc, thử lùi/nhảy sai ở mỗi nấc.
    g.transition(&nid(1), NodeState::Attested).unwrap();
    assert!(matches!(
        g.transition(&nid(1), NodeState::Discovered),
        Err(MeshError::IllegalTransition { .. })
    ));
    assert!(matches!(
        g.transition(&nid(1), NodeState::Isolated),
        Err(MeshError::IllegalTransition { .. })
    ));
    g.transition(&nid(1), NodeState::Suspect).unwrap();
    assert!(matches!(
        g.transition(&nid(1), NodeState::Discovered),
        Err(MeshError::IllegalTransition { .. })
    ));
    assert!(matches!(
        g.transition(&nid(1), NodeState::Unknown),
        Err(MeshError::IllegalTransition { .. })
    ));
    g.isolate_with_ttl(&nid(1), 2000, ISOLATION_TTL_MS).unwrap();
    assert!(matches!(
        g.transition(&nid(1), NodeState::Discovered),
        Err(MeshError::IllegalTransition { .. })
    ));
    // Node ma không tồn tại trong đồ thị.
    assert!(matches!(
        g.transition(&nid(0x99), NodeState::Attested),
        Err(MeshError::UnknownNode(_))
    ));

    // Node rơi về Unknown qua stale-GC không được nhảy lên lại — phải đi lại
    // full Discovered → Attested.
    g.observe(nid(2), 0).unwrap();
    g.tick_gc(EDGE_STALE_MS + 1);
    assert_eq!(g.node(&nid(2)).unwrap().state, NodeState::Unknown);
    assert!(matches!(
        g.transition(&nid(2), NodeState::Attested),
        Err(MeshError::IllegalTransition { .. })
    ));
    assert!(matches!(
        g.transition(&nid(2), NodeState::Suspect),
        Err(MeshError::IllegalTransition { .. })
    ));
    assert!(matches!(
        g.transition(&nid(2), NodeState::Isolated),
        Err(MeshError::IllegalTransition { .. })
    ));
}

// ====================================================================
// Nhóm 2: Giới hạn cứng + accounting (INV-015 planned)
// ====================================================================

#[test]
fn test_03_node_limit_enforced_with_accounting() {
    let mut g = MeshGraph::new();
    // nid(i as u8) cho i = 0..256 phủ đúng 256 id phân biệt.
    for i in 0..MAX_NODES {
        g.observe(nid(i as u8), i as u64).unwrap();
    }
    assert_eq!(g.node_count(), MAX_NODES);
    // Node thứ 257 phải bị từ chối VÀ được đếm — không drop âm thầm.
    let mut extra = [0u8; 32];
    extra[1] = 0x99; // phân biệt với mọi nid(byte0)
    let err = g.observe(extra, 10_000).unwrap_err();
    assert!(matches!(err, MeshError::LimitExceeded { kind: "node", dropped: 1 }));
    assert_eq!(g.dropped_node_count(), 1);
    assert_eq!(g.node_count(), MAX_NODES);
}

#[test]
fn test_04_edge_limit_enforced_with_accounting() {
    let mut g = MeshGraph::new();
    // 65 node, nối đầy đủ 64 node đầu (C(64,2) = 2016 cạnh).
    for i in 1..=65u8 {
        g.observe(nid(i), i as u64).unwrap();
    }
    let target_before_final = MAX_EDGES - 32;
    'outer: for a in 1..=64u8 {
        for b in (a + 1)..=64u8 {
            g.link(nid(a), nid(b), 10_000).unwrap();
            if g.edge_count() == target_before_final {
                break 'outer;
            }
        }
    }
    // Thêm cạnh từ node 65 cho tới khi đầy (32 cạnh còn lại).
    for b in 1..=32u8 {
        g.link(nid(65), nid(b), 10_000).unwrap();
    }
    assert_eq!(g.edge_count(), MAX_EDGES);
    // Cạnh 2049 bị từ chối + đếm.
    let err = g.link(nid(65), nid(33), 10_000).unwrap_err();
    assert!(matches!(err, MeshError::LimitExceeded { kind: "edge", dropped: 1 }));
    assert_eq!(g.dropped_edge_count(), 1);
}

#[test]
fn test_05_self_edge_rejected_and_pair_normalized() {
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.observe(nid(2), 1000).unwrap();

    assert!(matches!(
        g.link(nid(1), nid(1), 1000),
        Err(MeshError::InvalidEdge(_))
    ));
    assert!(matches!(
        g.link(nid(1), nid(0xAA), 1000),
        Err(MeshError::UnknownNode(_))
    ));

    // (a,b) và (b,a) là MỘT cạnh — không nhân đôi bằng đổi thứ tự tham số.
    g.link(nid(1), nid(2), 1000).unwrap();
    g.link(nid(2), nid(1), 2000).unwrap();
    assert_eq!(g.edge_count(), 1);
    assert_eq!(g.edge(&nid(1), &nid(2)).unwrap().last_heartbeat_mono_ms, 2000);
}

// ====================================================================
// Nhóm 3: GC + TTL isolation (plan §9)
// ====================================================================

#[test]
fn test_06_gc_stales_nodes_edges_and_counts() {
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.observe(nid(2), 1000).unwrap();
    g.link(nid(1), nid(2), 1000).unwrap();

    let report = g.tick_gc(1000 + EDGE_STALE_MS + 1);
    assert_eq!(report.staled_nodes, 2);
    assert_eq!(report.staled_edges, 1);
    assert_eq!(g.node(&nid(1)).unwrap().state, NodeState::Unknown);
    assert_eq!(g.edge(&nid(1), &nid(2)).unwrap().state, EdgeState::Stale);
}

#[test]
fn test_07_heartbeat_prevents_stale() {
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.transition(&nid(1), NodeState::Attested).unwrap();

    // Heartbeat mỗi 60s trong 3 phút — không bao giờ stale.
    let mut t = 1000u64;
    while t < 1000 + EDGE_STALE_MS {
        t += 60_000;
        g.heartbeat(&nid(1), t).unwrap();
    }
    let report = g.tick_gc(t);
    assert_eq!(report.staled_nodes, 0);
    assert_eq!(g.node(&nid(1)).unwrap().state, NodeState::Attested);
}

#[test]
fn test_08_isolation_ttl_inclusive_deadline_auto_lift() {
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.transition(&nid(1), NodeState::Attested).unwrap();
    g.transition(&nid(1), NodeState::Suspect).unwrap();
    g.isolate_with_ttl(&nid(1), 1000, 5000).unwrap();
    assert_eq!(g.node(&nid(1)).unwrap().isolated_until_mono_ms, Some(6000));

    // Trước deadline: GC chạy bao nhiêu lần cũng không lift sớm.
    for t in [2000u64, 4000, 5999] {
        let report = g.tick_gc(t);
        assert_eq!(report.lifted_isolations, 0);
        assert_eq!(g.node(&nid(1)).unwrap().state, NodeState::Isolated);
    }

    // Tại ĐÚNG deadline: auto-lift về Unknown (INV-014 — không khóa vĩnh viễn).
    let report = g.tick_gc(6000);
    assert_eq!(report.lifted_isolations, 1);
    assert_eq!(g.node(&nid(1)).unwrap().state, NodeState::Unknown);
    assert_eq!(g.node(&nid(1)).unwrap().isolated_until_mono_ms, None);

    // Sau auto-lift phải tái attestation mới được tin trở lại — không đường tắt.
    assert!(matches!(
        g.transition(&nid(1), NodeState::Attested),
        Err(MeshError::IllegalTransition { .. })
    ));
}

#[test]
fn test_09_isolated_node_survives_its_own_silence_until_ttl() {
    // Node isolated mất dấu lâu hơn EDGE_STALE — vẫn phải chờ đúng TTL của nó,
    // stale-GC không được lift sớm (tách bạch hai vòng đời).
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.transition(&nid(1), NodeState::Attested).unwrap();
    g.transition(&nid(1), NodeState::Suspect).unwrap();
    g.isolate_with_ttl(&nid(1), 1000, ISOLATION_TTL_MS).unwrap();

    let report = g.tick_gc(1000 + EDGE_STALE_MS + 1);
    assert_eq!(report.staled_nodes, 0, "isolated node không bị stale-GC đụng tới");
    assert_eq!(g.node(&nid(1)).unwrap().state, NodeState::Isolated);
}

// ====================================================================
// Nhóm 4: Chống node ma / cạnh ma
// ====================================================================

#[test]
fn test_10_heartbeat_for_unknown_node_rejected() {
    let mut g = MeshGraph::new();
    // Heartbeat từ node chưa từng thấy — không tạo node ngầm.
    assert!(matches!(
        g.heartbeat(&nid(1), 1000),
        Err(MeshError::UnknownNode(_))
    ));
    assert_eq!(g.node_count(), 0);
}

#[test]
fn test_11_isolated_to_suspect_is_the_only_downgrade_path() {
    // Merge reconcile (plan §6.2b) là đường hạ cấp duy nhất từ Isolated.
    let mut g = MeshGraph::new();
    g.observe(nid(1), 1000).unwrap();
    g.transition(&nid(1), NodeState::Attested).unwrap();
    g.transition(&nid(1), NodeState::Suspect).unwrap();
    g.isolate_with_ttl(&nid(1), 1000, ISOLATION_TTL_MS).unwrap();

    assert_eq!(g.transition(&nid(1), NodeState::Suspect).unwrap(), NodeState::Suspect);
    // Từ Suspect có thể quay về Attested khi corroboration gỡ nghi.
    assert_eq!(g.transition(&nid(1), NodeState::Attested).unwrap(), NodeState::Attested);
}
