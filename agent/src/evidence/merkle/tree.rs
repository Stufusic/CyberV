//! Merkle-DAG Evidence Tree with Subtree Commitments (HCE-3)
//!
//! Ref: Docs/rv9.md HCE-3:
//! "device_root: component_root + topology_root + evidence_root."

use super::node::MerkleNode;
use crate::evidence::constraints::PhysicalConstraintReport;
use crate::evidence::topology::HardwareTopologyReport;
use crate::fingerprint::component_hasher::hash_snapshot;
use crate::hardware::models::HardwareSnapshot;

/// Cây Merkle Bằng chứng Toàn diện chia theo Subtree Commitments
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleEvidenceTree {
    pub root: MerkleNode,
    pub component_subtree: MerkleNode,
    pub topology_subtree: MerkleNode,
    pub evidence_subtree: MerkleNode,
}

impl MerkleEvidenceTree {
    /// Xây dựng cây Merkle hoàn chỉnh từ các báo cáo thành phần
    pub fn build(
        snapshot: &HardwareSnapshot,
        constraint_report: &PhysicalConstraintReport,
        topology_report: &HardwareTopologyReport,
    ) -> Self {
        // 1. Nhánh Component Subtree: CPU, RAM, Board, Storage
        let hashed_components = hash_snapshot(snapshot);
        let mut comp_leaves = Vec::new();
        for hc in hashed_components {
            let label = format!("comp:{}", hc.canonical_id);
            comp_leaves.push(MerkleNode::new_leaf(label, hc.component_hash.as_bytes()));
        }
        let component_subtree = build_balanced_tree("component_root", comp_leaves);

        // 2. Nhánh Topology Subtree: PCIe fabric & Memory channels
        let mut topo_leaves = Vec::new();
        for bus_node in &topology_report.pci_nodes {
            let label = format!("topo:pci:{}", bus_node.id);
            topo_leaves.push(MerkleNode::new_leaf(
                label,
                bus_node.commitment_hash.as_bytes(),
            ));
        }
        let mem_label = format!("topo:mem:{}", topology_report.memory_topology.controller_id);
        topo_leaves.push(MerkleNode::new_leaf(
            mem_label,
            topology_report.memory_topology.commitment_hash.as_bytes(),
        ));
        let topology_subtree = build_balanced_tree("topology_root", topo_leaves);

        // 3. Nhánh Evidence Subtree: Virtual Nodes & Virtual Points
        let mut evidence_leaves = Vec::new();
        for vn in &constraint_report.virtual_nodes {
            let label = format!("vnode:{}", vn.id);
            evidence_leaves.push(MerkleNode::new_leaf(label, vn.virtual_hash.as_bytes()));
        }
        for vp in &constraint_report.virtual_points {
            let label = format!("vpoint:{}", vp.id);
            let point_data = format!("{}/{}", vp.value, vp.scale);
            evidence_leaves.push(MerkleNode::new_leaf(label, point_data.as_bytes()));
        }
        for vn in &topology_report.virtual_nodes {
            let label = format!("vnode:{}", vn.id);
            evidence_leaves.push(MerkleNode::new_leaf(label, vn.virtual_hash.as_bytes()));
        }
        let evidence_subtree = build_balanced_tree("evidence_root", evidence_leaves);

        // 4. Hợp nhất thành Root duy nhất
        let sub1_and_2 = MerkleNode::new_internal(
            "comp_and_topo_subroot",
            component_subtree.clone(),
            topology_subtree.clone(),
        );
        let root =
            MerkleNode::new_internal("device_evidence_root", sub1_and_2, evidence_subtree.clone());

        Self {
            root,
            component_subtree,
            topology_subtree,
            evidence_subtree,
        }
    }

    /// Trả về chuỗi hex 128 ký tự của Evidence Root Hash
    pub fn root_hash_hex(&self) -> String {
        self.root.hash_hex()
    }
}

/// Dựng cây nhị phân cân bằng từ danh sách các nút lá
pub fn build_balanced_tree(label: &str, mut nodes: Vec<MerkleNode>) -> MerkleNode {
    if nodes.is_empty() {
        return MerkleNode::new_leaf(label, b"EMPTY_SUBTREE");
    }

    // Sắp xếp các lá tăng dần theo nhãn để bảo đảm tính tất định
    nodes.sort_by(|a, b| a.label.cmp(&b.label));

    if nodes.len() == 1 {
        let only = nodes.pop().unwrap();
        return MerkleNode::new_internal(label, only.clone(), only);
    }

    let mut current_level = nodes;
    let mut round = 0;
    while current_level.len() > 1 {
        let is_last_round = current_level.len() <= 2;
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let left = current_level[i].clone();
                let right = current_level[i + 1].clone();
                let parent_label = if is_last_round {
                    label.to_string()
                } else {
                    format!("{}_r{}_b{}", label, round, next_level.len())
                };
                next_level.push(MerkleNode::new_internal(parent_label, left, right));
                i += 2;
            } else {
                // Nút lẻ được nhân bản làm lá kép (RFC 6962 standard)
                let left = current_level[i].clone();
                let right = current_level[i].clone();
                let parent_label = if is_last_round {
                    label.to_string()
                } else {
                    format!("{}_r{}_b_dup{}", label, round, next_level.len())
                };
                next_level.push(MerkleNode::new_internal(parent_label, left, right));
                i += 1;
            }
        }
        current_level = next_level;
        round += 1;
    }

    current_level.pop().unwrap()
}
