//! CyberV Phase 10: Hardware Evidence Engine Tests (HCE-1 -> HCE-3)
//!
//! Ref: Docs/rv9.md:
//! HCE-1: Physical Constraint Engine (VALID / INVALID / UNKNOWN, Virtual Nodes, Virtual Points)
//! HCE-2: Hardware Topology Engine (PCIe Fabric, Memory Channels, Topology Hash)
//! HCE-3: Merkle Evidence Engine (Subtree Commitments, Selective Inclusion Proofs O(log N))

use cyberv_agent::evidence::constraints::{ConstraintResult, PhysicalConstraintEngine};
use cyberv_agent::evidence::merkle::{generate_inclusion_proof, MerkleEvidenceTree};
use cyberv_agent::evidence::topology::{HardwareTopologyEngine, MemoryChannelMode, PciLocation};
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::models::{ComponentType, HardwareSnapshot, NormalizedComponent};
use std::collections::BTreeMap;

// Helper: Creates an AMD AM5 + DDR5 Platform
fn create_valid_amd_platform_snapshot() -> HardwareSnapshot {
    let mut snapshot = HardwareSnapshot::new(Vec::new(), "1.0.0");

    let mut cpu_attrs = BTreeMap::new();
    cpu_attrs.insert("vendor".to_string(), "amd".to_string());
    cpu_attrs.insert("model".to_string(), "amd ryzen 9 7950x".to_string());
    cpu_attrs.insert("socket".to_string(), "am5".to_string());
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Cpu,
        canonical_id: "cpu:amd:amd ryzen 9 7950x".to_string(),
        attributes: cpu_attrs,
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Complete,
        confidence: cyberv_agent::hardware::models::Confidence::High,
    });

    let mut board_attrs = BTreeMap::new();
    board_attrs.insert("vendor".to_string(), "msi".to_string());
    board_attrs.insert("product".to_string(), "mag b650 tomahawk wifi".to_string());
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Motherboard,
        canonical_id: "board:msi:mag b650 tomahawk wifi".to_string(),
        attributes: board_attrs,
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Complete,
        confidence: cyberv_agent::hardware::models::Confidence::High,
    });

    let mut ram_attrs = BTreeMap::new();
    ram_attrs.insert(
        "part_number".to_string(),
        "f5-6000j3038f16gx2-tz5n (ddr5)".to_string(),
    );
    ram_attrs.insert("speed_mhz".to_string(), "6000".to_string());
    ram_attrs.insert("bank_label".to_string(), "bank 0".to_string());
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Memory,
        canonical_id: "ram:bank 0:17179869184".to_string(),
        attributes: ram_attrs,
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Complete,
        confidence: cyberv_agent::hardware::models::Confidence::High,
    });

    let mut disk_attrs = BTreeMap::new();
    disk_attrs.insert("model".to_string(), "samsung ssd 990 pro 2tb".to_string());
    disk_attrs.insert("interface".to_string(), "nvme".to_string());
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Storage,
        canonical_id: "disk:samsung ssd 990 pro 2tb:s6z2nj0w123456:2000398934016".to_string(),
        attributes: disk_attrs,
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Complete,
        confidence: cyberv_agent::hardware::models::Confidence::High,
    });

    snapshot
}

// ====================================================================
// HCE-1: PHYSICAL CONSTRAINT ENGINE TESTS
// ====================================================================

#[test]
fn test_01_constraint_valid_intel_platform() {
    // Kịch bản: Nền tảng Intel chuẩn (Core i7-13700K + ROG STRIX Z790 + Corsair DDR5 + Samsung NVMe)
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    assert!(
        report.is_physically_valid,
        "Nền tảng Intel hợp lệ phải đạt Valid"
    );
    assert!(!report.has_invalid_conflicts);

    // Mọi đánh giá luật phải là Valid
    for eval in &report.evaluations {
        assert_eq!(
            eval.result,
            ConstraintResult::Valid,
            "Luật {} phải trả về Valid",
            eval.rule_id
        );
        assert_eq!(eval.penalty, 0);
    }

    // Điểm platform_consistency phải đạt tối đa 10000 / 10000
    let point = report
        .virtual_points
        .iter()
        .find(|p| p.id == "point:platform_consistency")
        .expect("Phải có virtual point platform_consistency");
    assert_eq!(point.value, 10000);
    assert_eq!(point.scale, 10000);
}

#[test]
fn test_02_constraint_valid_amd_platform() {
    // Kịch bản: Nền tảng AMD chuẩn (Ryzen 9 7950X + B650 + DDR5 6000MHz)
    let snapshot = create_valid_amd_platform_snapshot();
    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    assert!(
        report.is_physically_valid,
        "Nền tảng AMD hợp lệ phải đạt Valid"
    );
    assert!(!report.has_invalid_conflicts);
}

#[test]
fn test_03_constraint_impossible_cpu_board_invalid() {
    // Kịch bản: Kẻ tấn công dùng tool fake HWID: CPU Intel Core i7-13700K cắm trên Motherboard AMD B650
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut snapshot = collector.collect().unwrap();

    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Motherboard {
            comp.canonical_id = "board:msi:mag b650 tomahawk wifi".to_string();
            comp.attributes
                .insert("product".to_string(), "mag b650 tomahawk wifi".to_string());
        }
    }

    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    assert!(!report.is_physically_valid);
    assert!(report.has_invalid_conflicts);

    let cpu_board_eval = report
        .evaluations
        .iter()
        .find(|e| e.rule_id == "HCE-R01-CPU-BOARD")
        .unwrap();

    match &cpu_board_eval.result {
        ConstraintResult::Invalid { reason } => {
            assert!(reason.contains("Intel") && reason.contains("AMD"));
        }
        _ => panic!("Expected Invalid result for Intel CPU on AMD board"),
    }
    assert!(cpu_board_eval.penalty > 0);

    // Điểm platform_consistency bị trừ điểm
    let point = report
        .virtual_points
        .iter()
        .find(|p| p.id == "point:platform_consistency")
        .unwrap();
    assert!(point.value < 10000);
}

#[test]
fn test_04_constraint_impossible_ddr_generation_invalid() {
    // Kịch bản: Bo mạch chủ DDR4 (ví dụ: ASUS TUF GAMING B660-PLUS WIFI D4)
    // nhưng kẻ tấn công khai báo thanh RAM DDR5 5600MHz
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut snapshot = collector.collect().unwrap();

    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Motherboard {
            comp.canonical_id = "board:asus:tuf gaming b660-plus wifi d4".to_string();
            comp.attributes.insert(
                "product".to_string(),
                "tuf gaming b660-plus wifi d4".to_string(),
            );
        }
    }

    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    assert!(!report.is_physically_valid);

    let mem_eval = report
        .evaluations
        .iter()
        .find(|e| e.rule_id == "HCE-R03-BOARD-MEMORY")
        .unwrap();

    match &mem_eval.result {
        ConstraintResult::Invalid { reason } => {
            assert!(reason.contains("DDR4") && reason.contains("DDR5"));
        }
        _ => panic!("Expected Invalid result for DDR5 RAM on DDR4 board"),
    }
}

#[test]
fn test_05_constraint_missing_attributes_returns_unknown() {
    // Kịch bản: WMI bị thiếu thông số hoặc OEM giấu trường:
    // Hệ thống PHẢI trả về Unknown, TUYỆT ĐỐI KHÔNG coi là Invalid (Ref: rv9.md & Rule.md Điều 23)
    let mut snapshot = HardwareSnapshot::new(Vec::new(), "1.0.0");

    // CPU không có thông số model/vendor
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Cpu,
        canonical_id: "cpu:unknown".to_string(),
        attributes: BTreeMap::new(),
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Partial,
        confidence: cyberv_agent::hardware::models::Confidence::Low,
    });

    // Motherboard thiếu product/model
    snapshot.components.push(NormalizedComponent {
        component_type: ComponentType::Motherboard,
        canonical_id: "board:unknown".to_string(),
        attributes: BTreeMap::new(),
        source: cyberv_agent::hardware::models::CollectionSource::Mock,
        status: cyberv_agent::hardware::models::ComponentStatus::Partial,
        confidence: cyberv_agent::hardware::models::Confidence::Low,
    });

    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    // Không bị xung đột Invalid (chỉ là Unknown)
    assert!(!report.has_invalid_conflicts);

    let cpu_board_eval = report
        .evaluations
        .iter()
        .find(|e| e.rule_id == "HCE-R01-CPU-BOARD")
        .unwrap();

    match &cpu_board_eval.result {
        ConstraintResult::Unknown { missing_field } => {
            assert!(missing_field.contains("cpu") || missing_field.contains("board"));
        }
        _ => panic!("Expected Unknown result when attributes are missing"),
    }
    assert_eq!(cpu_board_eval.penalty, 0, "Unknown không bị phạt điểm");
}

#[test]
fn test_06_virtual_nodes_generated_from_constraints() {
    // Kiểm tra sinh các Virtual Nodes: vnode:cpu_board_consistency, vnode:platform_consistency
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let engine = PhysicalConstraintEngine::new();
    let report = engine.evaluate(&snapshot);

    let vnode_ids: Vec<_> = report.virtual_nodes.iter().map(|n| n.id.as_str()).collect();
    assert!(vnode_ids.contains(&"vnode:hce_r01_cpu_board"));
    assert!(vnode_ids.contains(&"vnode:hce_r02_cpu_memory"));
    assert!(vnode_ids.contains(&"vnode:hce_r03_board_memory"));
    assert!(vnode_ids.contains(&"vnode:hce_r04_storage_platform"));
    assert!(vnode_ids.contains(&"vnode:platform_consistency"));

    for vn in &report.virtual_nodes {
        assert!(!vn.virtual_hash.is_empty());
        assert_eq!(vn.virtual_hash.len(), 128); // SHA-512 hex
    }
}

// ====================================================================
// HCE-2: HARDWARE TOPOLOGY ENGINE TESTS
// ====================================================================

#[test]
fn test_07_topology_pcie_routing_tree_constructed() {
    // Kiểm tra cây phân cấp PCIe Bus Fabric: Root -> Bridge -> Host Controller -> Disks
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let topo_engine = HardwareTopologyEngine::new();
    let report = topo_engine.build_topology(&snapshot);

    assert!(!report.pci_nodes.is_empty());

    let root = report
        .pci_nodes
        .iter()
        .find(|n| n.id == "pci:root:0000")
        .unwrap();
    assert_eq!(root.bus_type, "PCIe_Root_Complex");
    assert_eq!(root.location, Some(PciLocation::new(0, 0, 0, 0)));

    let bridge = report
        .pci_nodes
        .iter()
        .find(|n| n.id == "pci:bridge:0000:00:01.0")
        .unwrap();
    assert_eq!(bridge.location, Some(PciLocation::new(0, 0, 1, 0)));

    let controller = report
        .pci_nodes
        .iter()
        .find(|n| n.id == "pci:controller:0000:01:00.0")
        .unwrap();
    assert_eq!(controller.bus_type, "NVMe_Host_Controller");
}

#[test]
fn test_08_topology_memory_channels_dual_channel() {
    // Máy có 2 thanh RAM ở Bank 0 và Bank 1 -> Phải nhận diện cấu hình Dual-Channel
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let topo_engine = HardwareTopologyEngine::new();
    let report = topo_engine.build_topology(&snapshot);

    assert_eq!(
        report.memory_topology.channel_mode,
        MemoryChannelMode::DualChannel
    );
    assert_eq!(report.memory_topology.populated_slots, 2);
    assert!(report.memory_topology.total_slots >= 2);
    assert!(!report.memory_topology.commitment_hash.is_empty());
}

#[test]
fn test_09_topology_commitment_hash_deterministic() {
    // Hai lần phân tích cùng 1 snapshot phải sinh ra Topology Hash hoàn toàn trùng khớp 100%
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let topo_engine = HardwareTopologyEngine::new();
    let rep1 = topo_engine.build_topology(&snapshot);
    let rep2 = topo_engine.build_topology(&snapshot);

    assert_eq!(rep1.topology_hash, rep2.topology_hash);
    assert_eq!(rep1.topology_hash.len(), 128); // SHA-512 hex
}

#[test]
fn test_10_topology_tampered_bus_detected() {
    // Kịch bản: Bổ sung một ổ cứng SSD phụ làm mở rộng thêm cổng PCI bus
    let snap1 = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let snap2 = MockHardwareCollector::disk_replace()
        .unwrap()
        .collect()
        .unwrap();

    let topo_engine = HardwareTopologyEngine::new();
    let rep1 = topo_engine.build_topology(&snap1);
    let rep2 = topo_engine.build_topology(&snap2);

    assert_ne!(
        rep1.topology_hash, rep2.topology_hash,
        "Thay đổi ổ đĩa / giao tiếp PCI phải thay đổi Topology Hash"
    );
}

// ====================================================================
// HCE-3: MERKLE EVIDENCE ENGINE & SELECTIVE DISCLOSURE TESTS
// ====================================================================

#[test]
fn test_11_merkle_tree_construction_subtrees() {
    // Kiểm tra cấu trúc cây Merkle-DAG 3 nhánh con cam kết:
    // component_subtree + topology_subtree + evidence_subtree -> root
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let constraint_engine = PhysicalConstraintEngine::new();
    let topo_engine = HardwareTopologyEngine::new();

    let c_report = constraint_engine.evaluate(&snapshot);
    let t_report = topo_engine.build_topology(&snapshot);

    let merkle_tree = MerkleEvidenceTree::build(&snapshot, &c_report, &t_report);

    assert_eq!(merkle_tree.component_subtree.label, "component_root");
    assert_eq!(merkle_tree.topology_subtree.label, "topology_root");
    assert_eq!(merkle_tree.evidence_subtree.label, "evidence_root");
    assert_eq!(merkle_tree.root.label, "device_evidence_root");

    assert_eq!(merkle_tree.root_hash_hex().len(), 128);
}

#[test]
fn test_12_merkle_inclusion_proof_valid_component() {
    // Kịch bản: Client chỉ cần chứng minh ổ cứng NVMe "samsung ssd 980 pro 1tb"
    // nằm trong Merkle Root của thiết bị mà không cần gửi CPU hay Motherboard
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let c_report = PhysicalConstraintEngine::new().evaluate(&snapshot);
    let t_report = HardwareTopologyEngine::new().build_topology(&snapshot);
    let merkle_tree = MerkleEvidenceTree::build(&snapshot, &c_report, &t_report);

    // Tìm nhãn lá của linh kiện ổ đĩa
    let disk_label = "comp:disk:samsung ssd 980 pro 1tb:s5p2nf0r123456:1000204886016";
    let proof = generate_inclusion_proof(&merkle_tree.root, disk_label)
        .expect("Phải sinh được Merkle Inclusion Proof cho ổ cứng hợp lệ");

    assert_eq!(proof.leaf_label, disk_label);
    assert_eq!(proof.root_hash_hex, merkle_tree.root_hash_hex());
    assert!(!proof.path.is_empty(), "Merkle path không được rỗng");

    // Xác minh bằng chứng phía Server (độ phức tạp O(log N))
    assert!(
        proof.verify(),
        "Bằng chứng Merkle Inclusion Proof phải hợp lệ"
    );
}

#[test]
fn test_13_merkle_inclusion_proof_forged_leaf_rejected() {
    // Kịch bản: Kẻ tấn công sửa đổi 1 ký tự trong leaf_hash_hex
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let c_report = PhysicalConstraintEngine::new().evaluate(&snapshot);
    let t_report = HardwareTopologyEngine::new().build_topology(&snapshot);
    let merkle_tree = MerkleEvidenceTree::build(&snapshot, &c_report, &t_report);

    let disk_label = "comp:disk:samsung ssd 980 pro 1tb:s5p2nf0r123456:1000204886016";
    let mut proof = generate_inclusion_proof(&merkle_tree.root, disk_label).unwrap();

    // Sửa 1 ký tự trong leaf hash
    let mut mutated_leaf = proof.leaf_hash_hex.clone();
    let last_char = if mutated_leaf.ends_with('0') {
        '1'
    } else {
        '0'
    };
    mutated_leaf.pop();
    mutated_leaf.push(last_char);
    proof.leaf_hash_hex = mutated_leaf;

    assert!(
        !proof.verify(),
        "Bằng chứng có leaf hash bị giả mạo phải bị từ chối dứt khoát"
    );
}

#[test]
fn test_14_merkle_inclusion_proof_tampered_sibling_rejected() {
    // Kịch bản: Kẻ tấn công can thiệp vào đường đi Merkle path (sửa sibling hash)
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let c_report = PhysicalConstraintEngine::new().evaluate(&snapshot);
    let t_report = HardwareTopologyEngine::new().build_topology(&snapshot);
    let merkle_tree = MerkleEvidenceTree::build(&snapshot, &c_report, &t_report);

    let disk_label = "comp:disk:samsung ssd 980 pro 1tb:s5p2nf0r123456:1000204886016";
    let mut proof = generate_inclusion_proof(&merkle_tree.root, disk_label).unwrap();

    // Sửa 1 ký tự trong bước đầu tiên của Merkle path
    let mut bad_sibling = proof.path[0].sibling_hash_hex.clone();
    bad_sibling.pop();
    bad_sibling.push('a');
    proof.path[0].sibling_hash_hex = bad_sibling;

    assert!(
        !proof.verify(),
        "Bằng chứng có sibling hash trong path bị sửa đổi phải bị từ chối dứt khoát"
    );
}

#[test]
fn test_15_end_to_end_evidence_engine_integration() {
    // Toàn bộ quy trình tích hợp khép kín:
    // Snapshot -> Constraint Engine -> Topology Engine -> Merkle Tree -> Selective Disclosure Proof
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    // 1. Chạy HCE-1
    let c_engine = PhysicalConstraintEngine::new();
    let c_report = c_engine.evaluate(&snapshot);
    assert!(c_report.is_physically_valid);
    assert_eq!(c_report.virtual_points[0].value, 10000);

    // 2. Chạy HCE-2
    let t_engine = HardwareTopologyEngine::new();
    let t_report = t_engine.build_topology(&snapshot);
    assert_eq!(
        t_report.memory_topology.channel_mode,
        MemoryChannelMode::DualChannel
    );

    // 3. Chạy HCE-3
    let merkle_tree = MerkleEvidenceTree::build(&snapshot, &c_report, &t_report);
    let evidence_root = merkle_tree.root_hash_hex();
    assert_eq!(evidence_root.len(), 128);

    // 4. Sinh bằng chứng cho CPU
    let cpu_label = "comp:cpu:intel:intel core i7-13700k";
    let cpu_proof = generate_inclusion_proof(&merkle_tree.root, cpu_label)
        .expect("Phải sinh được bằng chứng bao hàm cho CPU");
    assert!(
        cpu_proof.verify(),
        "Xác minh bằng chứng bao hàm CPU thành công"
    );

    // 5. Sinh bằng chứng cho Topology Node
    let topo_label = "topo:pci:pci:root:0000";
    let topo_proof = generate_inclusion_proof(&merkle_tree.root, topo_label)
        .expect("Phải sinh được bằng chứng bao hàm cho Root PCI");
    assert!(
        topo_proof.verify(),
        "Xác minh bằng chứng bao hàm Topology thành công"
    );
}
