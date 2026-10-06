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
///
/// RFC 6962 SPLIT-NODE RULE (L7 fix): nút lẻ KHÔNG còn được nhân bản.
/// Cây n phần tử được chia tại lớn nhất power-of-two < n rồi hợp nhất —
/// loại bỏ root-equivalence giữa [.., X] và [.., X, X] cũng như sibling
/// tự trỏ trong proof. Cây một lá: root chính là hash của lá (RFC 6962).
pub fn build_balanced_tree(label: &str, mut nodes: Vec<MerkleNode>) -> MerkleNode {
    if nodes.is_empty() {
        return MerkleNode::new_leaf(label, b"EMPTY_SUBTREE");
    }

    // Sắp xếp các lá tăng dần theo nhãn để bảo đảm tính tất định
    nodes.sort_by(|a, b| a.label.cmp(&b.label));

    build_subtree(label, &nodes)
}

/// Lớn nhất power-of-two nhỏ hơn n (n >= 2)
fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n >= 2);
    usize::next_power_of_two(n) >> 1
}

fn build_subtree(label: &str, nodes: &[MerkleNode]) -> MerkleNode {
    if nodes.len() == 1 {
        // Cây một lá: root = hash lá. Nhãn nhánh của caller chỉ dùng khi
        // cần internal node; MerkleEvidenceTree luôn có >= 1 lá nên root
        // của subtree nhiều lá vẫn mang label của nhánh (xem build()).
        return nodes[0].clone();
    }

    let split = largest_power_of_two_below(nodes.len());
    let left = build_subtree(&format!("{}_l", label), &nodes[..split]);
    let right = build_subtree(&format!("{}_r", label), &nodes[split..]);
    MerkleNode::new_internal(label.to_string(), left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(label: &str) -> MerkleNode {
        MerkleNode::new_leaf(label, label.as_bytes())
    }

    /// REGRESSION L7: root([X]) KHÔNG được bằng root([X, X]) như quy tắc
    /// nhân bản cũ (internal(X, X)).
    #[test]
    fn single_leaf_root_differs_from_duplicated_pair_root() {
        let one = build_balanced_tree("t", vec![leaf("X")]);
        let two = build_balanced_tree("t", vec![leaf("X"), leaf("X")]);
        assert_ne!(one.hash_hex(), two.hash_hex());
    }

    #[test]
    fn split_node_rule_deterministic_and_order_insensitive() {
        let labels = ["A", "B", "C", "D", "E"];
        let t1 = build_balanced_tree("r", labels.iter().map(|l| leaf(l)).collect());
        let t2 = build_balanced_tree("r", labels.iter().rev().map(|l| leaf(l)).collect());
        assert_eq!(t1.hash_hex(), t2.hash_hex());

        // Nhiều hơn power-of-two: 5 lá (split 4 + 1)
        let t3 = build_balanced_tree("r", vec![leaf("A"), leaf("B"), leaf("C"), leaf("D"), leaf("E")]);
        assert_eq!(t3.hash_hex(), t1.hash_hex());
    }

    /// Nhiều lá: root node mang label của subtree (hợp đồng của MerkleEvidenceTree)
    #[test]
    fn multi_leaf_root_keeps_subtree_label() {
        let t = build_balanced_tree("component_root", vec![leaf("a"), leaf("b")]);
        assert_eq!(t.label, "component_root");
    }
}
