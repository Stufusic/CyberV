//! CyberV Enhanced GraphDiff
//!
//! So sánh biến động giữa hai đồ thị bằng chứng thiết bị (G1 vs G2).
//! Ref: rv p3.md #13 và Pipeline.md Section 20.

use super::models::DeviceEvidenceGraph;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Loại biến động đồ thị chi tiết
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphChangeOp {
    NodeAdded,
    NodeRemoved,
    NodeModified, // Thay đổi component_hash hoặc node_commitment
    EdgeAdded,
    EdgeRemoved,
    VirtualNodeChanged,  // Thay đổi cấu trúc hoặc giá trị suy diễn ảo
    VirtualPointChanged, // Thay đổi điểm bằng chứng
    VerificationChanged, // Thay đổi verification_hash
}

/// Một mục biến động phát hiện được
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphChangeItem {
    pub target_id: String,
    pub operation: GraphChangeOp,
    pub details: String,
}

/// Kết quả so sánh đồ thị toàn diện
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphDiff {
    pub changes: Vec<GraphChangeItem>,
    pub has_hardware_mutation: bool,
    pub has_verification_mutation: bool,
}

/// So sánh hai đồ thị bằng chứng thiết bị G_old và G_new
pub fn diff_evidence_graphs(
    old_graph: &DeviceEvidenceGraph,
    new_graph: &DeviceEvidenceGraph,
) -> EvidenceGraphDiff {
    let mut changes = Vec::new();
    let mut has_hardware_mutation = false;

    // 1. So sánh Real Nodes
    let old_nodes: HashMap<&str, &crate::fingerprint::graph::models::GraphNode> =
        old_graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let new_nodes: HashMap<&str, &crate::fingerprint::graph::models::GraphNode> =
        new_graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    for (id, new_n) in &new_nodes {
        if let Some(old_n) = old_nodes.get(id) {
            if old_n.node_commitment != new_n.node_commitment {
                has_hardware_mutation = true;
                changes.push(GraphChangeItem {
                    target_id: (*id).to_string(),
                    operation: GraphChangeOp::NodeModified,
                    details: format!(
                        "Component {} modified: hash changed from {}.. to {}..",
                        new_n.component_type,
                        &old_n.component_hash[..8],
                        &new_n.component_hash[..8]
                    ),
                });
            }
        } else {
            has_hardware_mutation = true;
            changes.push(GraphChangeItem {
                target_id: (*id).to_string(),
                operation: GraphChangeOp::NodeAdded,
                details: format!("Added new component: {}", new_n.component_type),
            });
        }
    }

    for (id, old_n) in &old_nodes {
        if !new_nodes.contains_key(id) {
            has_hardware_mutation = true;
            changes.push(GraphChangeItem {
                target_id: (*id).to_string(),
                operation: GraphChangeOp::NodeRemoved,
                details: format!("Removed component: {}", old_n.component_type),
            });
        }
    }

    // 2. So sánh Edges
    let old_edges: HashSet<String> = old_graph
        .edges
        .iter()
        .map(|e| format!("{}|{}|{}", e.source, e.relation, e.target))
        .collect();
    let new_edges: HashSet<String> = new_graph
        .edges
        .iter()
        .map(|e| format!("{}|{}|{}", e.source, e.relation, e.target))
        .collect();

    for edge in &new_edges {
        if !old_edges.contains(edge) {
            changes.push(GraphChangeItem {
                target_id: format!("edge:{}", edge),
                operation: GraphChangeOp::EdgeAdded,
                details: format!("Added topology edge: {}", edge),
            });
        }
    }

    for edge in &old_edges {
        if !new_edges.contains(edge) {
            changes.push(GraphChangeItem {
                target_id: format!("edge:{}", edge),
                operation: GraphChangeOp::EdgeRemoved,
                details: format!("Removed topology edge: {}", edge),
            });
        }
    }

    // 3. So sánh Virtual Nodes
    let old_vnodes: HashMap<&str, &crate::fingerprint::graph::models::VirtualNode> = old_graph
        .virtual_nodes
        .iter()
        .map(|v| (v.id.as_str(), v))
        .collect();
    for new_v in &new_graph.virtual_nodes {
        if let Some(old_v) = old_vnodes.get(new_v.id.as_str()) {
            if old_v.virtual_hash != new_v.virtual_hash {
                changes.push(GraphChangeItem {
                    target_id: new_v.id.clone(),
                    operation: GraphChangeOp::VirtualNodeChanged,
                    details: format!("Virtual node {} hash mutated", new_v.virtual_type),
                });
            }
        }
    }

    // 4. So sánh Virtual Points
    let old_points: HashMap<&str, &crate::fingerprint::graph::models::VirtualPoint> = old_graph
        .virtual_points
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();
    for new_p in &new_graph.virtual_points {
        if let Some(old_p) = old_points.get(new_p.id.as_str()) {
            if old_p.value != new_p.value || old_p.scale != new_p.scale {
                changes.push(GraphChangeItem {
                    target_id: new_p.id.clone(),
                    operation: GraphChangeOp::VirtualPointChanged,
                    details: format!(
                        "Virtual point {} score changed from {}/{} to {}/{}",
                        new_p.id, old_p.value, old_p.scale, new_p.value, new_p.scale
                    ),
                });
            }
        }
    }

    // 5. So sánh Verification Hash
    let has_verification_mutation = old_graph.verification_hash != new_graph.verification_hash;
    if has_verification_mutation {
        changes.push(GraphChangeItem {
            target_id: "verification_hash".to_string(),
            operation: GraphChangeOp::VerificationChanged,
            details: format!(
                "Verification hash changed: {}.. -> {}..",
                &old_graph.verification_hash[..8],
                &new_graph.verification_hash[..8]
            ),
        });
    }

    EvidenceGraphDiff {
        changes,
        has_hardware_mutation,
        has_verification_mutation,
    }
}
