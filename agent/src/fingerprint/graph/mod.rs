//! CyberV Device Evidence Graph Subsystem
//!
//! Ref: rv p3.md: Real Nodes, Virtual Nodes, Virtual Points, 5-Tier Hash Hierarchy & GraphDiff.

pub mod builder;
pub mod diff;
pub mod models;

pub use builder::{
    build_evidence_graph, compute_evidence_root, compute_graph_hash, compute_node_commitment,
    compute_verification_hash, compute_virtual_node_hash, encode_canonical_evidence_graph,
};
pub use diff::{diff_evidence_graphs, EvidenceGraphDiff, GraphChangeItem, GraphChangeOp};
pub use models::{DeviceEvidenceGraph, GraphEdge, GraphNode, NodeKind, VirtualNode, VirtualPoint};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::component_hasher::hash_snapshot;
    use crate::hardware::collector::HardwareCollector;
    use crate::hardware::mock::MockHardwareCollector;

    #[test]
    fn test_device_evidence_graph_construction() {
        let baseline = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();
        let hashed = hash_snapshot(&baseline);
        let graph = build_evidence_graph(&hashed, 1);

        // 1 root node + 5 real components = 6 nodes
        assert_eq!(graph.nodes.len(), 6);
        // Edges: root -> MB, MB -> CPU, MB -> RAM1, MB -> RAM2, MB -> Disk = 5 edges
        assert_eq!(graph.edges.len(), 5);
        // Virtual nodes: PlatformConsistency, MemoryTopology, StorageTopology
        assert_eq!(graph.virtual_nodes.len(), 3);
        // Virtual points: 3 points
        assert_eq!(graph.virtual_points.len(), 3);

        // Các hash SHA-512 phải đúng 128 ký tự hex
        assert_eq!(graph.evidence_root.len(), 128);
        assert_eq!(graph.graph_hash.len(), 128);
        assert_eq!(graph.verification_hash.len(), 128);
    }

    #[test]
    fn test_graph_determinism_given_identical_input() {
        let baseline1 = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();
        let baseline2 = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();

        let hashed1 = hash_snapshot(&baseline1);
        let hashed2 = hash_snapshot(&baseline2);

        let graph1 = build_evidence_graph(&hashed1, 1);
        let graph2 = build_evidence_graph(&hashed2, 1);

        assert_eq!(graph1.evidence_root, graph2.evidence_root);
        assert_eq!(graph1.graph_hash, graph2.graph_hash);
        assert_eq!(graph1.verification_hash, graph2.verification_hash);
    }

    #[test]
    fn test_graph_diff_propagation_ram_upgrade() {
        let baseline = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();
        let ram_up = MockHardwareCollector::ram_upgrade()
            .unwrap()
            .collect()
            .unwrap();

        let hashed_base = hash_snapshot(&baseline);
        let hashed_ram = hash_snapshot(&ram_up);

        let graph_base = build_evidence_graph(&hashed_base, 1);
        let graph_ram = build_evidence_graph(&hashed_ram, 2);

        let diff = diff_evidence_graphs(&graph_base, &graph_ram);

        assert!(diff.has_hardware_mutation);
        assert!(diff.has_verification_mutation);

        // Biến động linh kiện: RAM thay đổi
        assert!(diff.changes.iter().any(|c| c.target_id.starts_with("ram:")));
        // CPU, Disk, Motherboard KHÔNG được xuất hiện trong các thay đổi node
        assert!(!diff.changes.iter().any(|c| c.target_id.starts_with("cpu:")));
        assert!(!diff
            .changes
            .iter()
            .any(|c| c.target_id.starts_with("disk:")));
        assert!(!diff
            .changes
            .iter()
            .any(|c| c.target_id.starts_with("board:")));

        // Virtual node & Verification changed
        assert!(diff
            .changes
            .iter()
            .any(|c| c.target_id == "vnode:memory_topology"));
        assert!(diff
            .changes
            .iter()
            .any(|c| c.target_id == "verification_hash"));
    }

    #[test]
    fn test_graph_diff_propagation_disk_replace() {
        let baseline = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();
        let disk_rep = MockHardwareCollector::disk_replace()
            .unwrap()
            .collect()
            .unwrap();

        let hashed_base = hash_snapshot(&baseline);
        let hashed_disk = hash_snapshot(&disk_rep);

        let graph_base = build_evidence_graph(&hashed_base, 1);
        let graph_disk = build_evidence_graph(&hashed_disk, 2);

        let diff = diff_evidence_graphs(&graph_base, &graph_disk);

        assert!(diff.has_hardware_mutation);
        assert!(diff.has_verification_mutation);

        // Storage node thay đổi
        assert!(diff
            .changes
            .iter()
            .any(|c| c.target_id.starts_with("disk:")));
        // RAM, CPU, Motherboard không thay đổi
        assert!(!diff.changes.iter().any(|c| c.target_id.starts_with("cpu:")));
        assert!(!diff.changes.iter().any(|c| c.target_id.starts_with("ram:")));
        assert!(!diff
            .changes
            .iter()
            .any(|c| c.target_id.starts_with("board:")));

        // Virtual node changed
        assert!(diff
            .changes
            .iter()
            .any(|c| c.target_id == "vnode:storage_topology"));
        assert!(diff
            .changes
            .iter()
            .any(|c| c.target_id == "verification_hash"));
    }
}
