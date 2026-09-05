//! CyberV Device Evidence Graph Builder
//!
//! Triển khai quy trình xây dựng Đồ thị Bằng chứng Thiết bị và cây cam kết 5 tầng mật mã học.
//! Ref: rv p3.md #7, #8, #9, #10, #11, #12 và Rule.md Điều 1, 2, 20.

use super::models::{
    DeviceEvidenceGraph, GraphEdge, GraphNode, NodeKind, VirtualNode, VirtualPoint,
};
use crate::fingerprint::canonical::CanonicalEncoder;
use crate::fingerprint::component_hasher::HashedComponent;
use crate::hardware::models::{CollectionSource, ComponentStatus, ComponentType, Confidence};
use crate::protocol::constants::{
    DERIVATION_VERSION, DOMAIN_EVIDENCE, DOMAIN_GRAPH, DOMAIN_NODE, DOMAIN_VERIFICATION,
    DOMAIN_VIRTUAL_NODE, PROTOCOL_VERSION, SCHEMA_VERSION,
};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

/// Tính Tier 2: Node Commitment ràng buộc hash của linh kiện với ngữ cảnh cấu trúc
pub fn compute_node_commitment(
    schema_version: u32,
    node_type: &str,
    canonical_id: &str,
    component_hash: &str,
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_NODE);
    hasher.update([0x00]);
    hasher.update(schema_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(node_type.as_bytes());
    hasher.update([0x00]);
    hasher.update(canonical_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(component_hash.as_bytes());

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Tính Tier 3: Virtual Node Hash ràng buộc các input commitments và thuộc tính suy diễn
pub fn compute_virtual_node_hash(
    derivation_version: u32,
    virtual_type: &str,
    sorted_input_commitments: &[String],
    canonical_vattrs: &[u8],
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_VIRTUAL_NODE);
    hasher.update([0x00]);
    hasher.update(derivation_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(virtual_type.as_bytes());
    hasher.update([0x00]);
    for commit in sorted_input_commitments {
        hasher.update(commit.as_bytes());
        hasher.update([0x1f]); // Unit separator byte
    }
    hasher.update([0x00]);
    hasher.update(canonical_vattrs);

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Tính Tier 4: Evidence Root từ danh sách Virtual Points và Virtual Nodes
pub fn compute_evidence_root(
    derivation_version: u32,
    virtual_nodes: &[VirtualNode],
    virtual_points: &[VirtualPoint],
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_EVIDENCE);
    hasher.update([0x00]);
    hasher.update(derivation_version.to_be_bytes());
    hasher.update([0x00]);

    // Băm các virtual node hash đã sắp xếp theo id
    let mut sorted_vnodes = virtual_nodes.to_vec();
    sorted_vnodes.sort_by(|a, b| a.id.cmp(&b.id));
    for v in sorted_vnodes {
        hasher.update(v.id.as_bytes());
        hasher.update(b"=");
        hasher.update(v.virtual_hash.as_bytes());
        hasher.update([0x0a]); // '\n'
    }

    hasher.update([0x00]);

    // Băm các virtual point đã sắp xếp theo id
    let mut sorted_points = virtual_points.to_vec();
    sorted_points.sort_by(|a, b| a.id.cmp(&b.id));
    for p in sorted_points {
        let line = format!("id={}|val={}|scale={}\n", p.id, p.value, p.scale);
        hasher.update(line.as_bytes());
    }

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Tính Tier 5: Graph Hash từ toàn bộ cấu trúc topo canonical
pub fn compute_graph_hash(
    protocol_version: u32,
    graph_version: u32,
    schema_version: u32,
    canonical_graph_bytes: &[u8],
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_GRAPH);
    hasher.update([0x00]);
    hasher.update(protocol_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(schema_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(graph_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(canonical_graph_bytes);

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Tính Tier 5: Verification Hash - Cam kết tối cao kết hợp Graph Hash và Evidence Root
pub fn compute_verification_hash(
    protocol_version: u32,
    graph_version: u32,
    graph_hash: &str,
    evidence_root: &str,
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_VERIFICATION);
    hasher.update([0x00]);
    hasher.update(protocol_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(graph_version.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(graph_hash.as_bytes());
    hasher.update([0x00]);
    hasher.update(evidence_root.as_bytes());

    let digest = hasher.finalize();
    format!("{:x}", digest)
}

/// Xây dựng Đồ thị Bằng chứng Thiết bị toàn diện (Device Evidence Graph) từ danh sách HashedComponent
pub fn build_evidence_graph(
    hashed_components: &[HashedComponent],
    graph_version: u32,
) -> DeviceEvidenceGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // 1. Tạo Root Node
    let root_id = "root:device".to_string();
    let root_type = "ROOT".to_string();
    let root_hash = "0".repeat(128); // 128 ký tự 0
    let root_commitment = compute_node_commitment(SCHEMA_VERSION, &root_type, &root_id, &root_hash);

    nodes.push(GraphNode {
        id: root_id.clone(),
        node_kind: NodeKind::Root,
        component_type: root_type,
        component_hash: root_hash,
        node_commitment: root_commitment,
        schema_version: SCHEMA_VERSION,
        source: CollectionSource::Mock,
        status: ComponentStatus::Complete,
        confidence: Confidence::High,
    });

    // 2. Tạo Real Nodes & Tính Tier 2 Node Commitment
    let mut mb_id: Option<String> = None;

    for comp in hashed_components {
        let type_str = comp.component_type.to_string().to_uppercase();
        let commitment = compute_node_commitment(
            comp.schema_version,
            &type_str,
            &comp.canonical_id,
            &comp.component_hash,
        );

        if comp.component_type == ComponentType::Motherboard {
            mb_id = Some(comp.canonical_id.clone());
        }

        nodes.push(GraphNode {
            id: comp.canonical_id.clone(),
            node_kind: NodeKind::RealComponent,
            component_type: type_str,
            component_hash: comp.component_hash.clone(),
            node_commitment: commitment,
            schema_version: comp.schema_version,
            source: comp.source,
            status: comp.status,
            confidence: comp.confidence,
        });
    }

    // 3. Xây dựng Topology Edges
    let parent_id = if let Some(ref board) = mb_id {
        // device -> motherboard
        edges.push(GraphEdge {
            source: root_id.clone(),
            relation: "contains".to_string(),
            target: board.clone(),
        });
        board.clone()
    } else {
        root_id.clone()
    };

    for comp in hashed_components {
        if comp.component_type == ComponentType::Motherboard {
            continue; // Đã liên kết ở trên
        }

        let rel = match comp.component_type {
            ComponentType::Cpu => "hosts",
            ComponentType::Memory => "contains",
            ComponentType::Storage => "contains",
            ComponentType::Motherboard => "contains",
        };

        edges.push(GraphEdge {
            source: parent_id.clone(),
            relation: rel.to_string(),
            target: comp.canonical_id.clone(),
        });
    }

    // 4. Suy diễn Tier 3: Virtual Nodes (rv p3.md #3, #4)
    let mut virtual_nodes = Vec::new();
    let mut virtual_points = Vec::new();

    // Thu thập các commitments theo loại
    let cpu_commits: Vec<String> = nodes
        .iter()
        .filter(|n| n.component_type == "CPU")
        .map(|n| n.node_commitment.clone())
        .collect();
    let mem_commits: Vec<String> = nodes
        .iter()
        .filter(|n| n.component_type == "MEMORY")
        .map(|n| n.node_commitment.clone())
        .collect();
    let disk_commits: Vec<String> = nodes
        .iter()
        .filter(|n| n.component_type == "STORAGE")
        .map(|n| n.node_commitment.clone())
        .collect();
    let mb_commits: Vec<String> = nodes
        .iter()
        .filter(|n| n.component_type == "MOTHERBOARD")
        .map(|n| n.node_commitment.clone())
        .collect();

    // a) PlatformConsistency Virtual Node
    let mut platform_inputs = Vec::new();
    platform_inputs.extend_from_slice(&cpu_commits);
    platform_inputs.extend_from_slice(&mb_commits);
    platform_inputs.extend_from_slice(&mem_commits);
    platform_inputs.extend_from_slice(&disk_commits);
    platform_inputs.sort();

    let mut platform_attrs = BTreeMap::new();
    platform_attrs.insert("cpu_nodes".to_string(), cpu_commits.len().to_string());
    platform_attrs.insert("memory_nodes".to_string(), mem_commits.len().to_string());
    platform_attrs.insert("storage_nodes".to_string(), disk_commits.len().to_string());
    platform_attrs.insert("board_nodes".to_string(), mb_commits.len().to_string());

    let mut plat_enc = CanonicalEncoder::new();
    for (k, v) in &platform_attrs {
        plat_enc.add_field(k, v);
    }
    let plat_bytes = plat_enc.to_canonical_bytes();
    let plat_hash = compute_virtual_node_hash(
        DERIVATION_VERSION,
        "PLATFORM_CONSISTENCY",
        &platform_inputs,
        &plat_bytes,
    );

    virtual_nodes.push(VirtualNode {
        id: "vnode:platform_consistency".to_string(),
        virtual_type: "PLATFORM_CONSISTENCY".to_string(),
        derivation_version: DERIVATION_VERSION,
        input_commitments: platform_inputs,
        virtual_hash: plat_hash,
        attributes: platform_attrs,
    });

    // Virtual Point cho Platform Consistency (9800/10000 nếu đủ 4 nhóm, trừ điểm nếu thiếu MB)
    let plat_score: i64 = if !mb_commits.is_empty() && !cpu_commits.is_empty() {
        10000
    } else {
        8500
    };
    virtual_points.push(VirtualPoint::new(
        "point:platform_consistency",
        plat_score,
        10000,
        DERIVATION_VERSION,
    ));

    // b) MemoryTopology Virtual Node
    let mut mem_inputs = mem_commits.clone();
    mem_inputs.sort();

    let mut mem_attrs = BTreeMap::new();
    mem_attrs.insert("module_count".to_string(), mem_commits.len().to_string());
    let mut mem_enc = CanonicalEncoder::new();
    for (k, v) in &mem_attrs {
        mem_enc.add_field(k, v);
    }
    let mem_bytes = mem_enc.to_canonical_bytes();
    let mem_hash = compute_virtual_node_hash(
        DERIVATION_VERSION,
        "MEMORY_TOPOLOGY",
        &mem_inputs,
        &mem_bytes,
    );

    virtual_nodes.push(VirtualNode {
        id: "vnode:memory_topology".to_string(),
        virtual_type: "MEMORY_TOPOLOGY".to_string(),
        derivation_version: DERIVATION_VERSION,
        input_commitments: mem_inputs,
        virtual_hash: mem_hash,
        attributes: mem_attrs,
    });

    virtual_points.push(VirtualPoint::new(
        "point:memory_topology",
        10000,
        10000,
        DERIVATION_VERSION,
    ));

    // c) StorageTopology Virtual Node
    let mut disk_inputs = disk_commits.clone();
    disk_inputs.sort();

    let mut disk_attrs = BTreeMap::new();
    disk_attrs.insert("disk_count".to_string(), disk_commits.len().to_string());
    let mut disk_enc = CanonicalEncoder::new();
    for (k, v) in &disk_attrs {
        disk_enc.add_field(k, v);
    }
    let disk_bytes = disk_enc.to_canonical_bytes();
    let disk_hash = compute_virtual_node_hash(
        DERIVATION_VERSION,
        "STORAGE_TOPOLOGY",
        &disk_inputs,
        &disk_bytes,
    );

    virtual_nodes.push(VirtualNode {
        id: "vnode:storage_topology".to_string(),
        virtual_type: "STORAGE_TOPOLOGY".to_string(),
        derivation_version: DERIVATION_VERSION,
        input_commitments: disk_inputs,
        virtual_hash: disk_hash,
        attributes: disk_attrs,
    });

    // Nếu có disk Partial (thiếu serial) hạ score
    let has_partial_disk = nodes
        .iter()
        .any(|n| n.component_type == "STORAGE" && n.status == ComponentStatus::Partial);
    let disk_score = if has_partial_disk { 8000 } else { 10000 };
    virtual_points.push(VirtualPoint::new(
        "point:storage_identity",
        disk_score,
        10000,
        DERIVATION_VERSION,
    ));

    // 5. Tính Tier 4: Evidence Root
    let evidence_root = compute_evidence_root(DERIVATION_VERSION, &virtual_nodes, &virtual_points);

    // 6. Sắp xếp chính tắc (Canonical Sorting) và Mã hóa byte toàn bộ Graph
    let canonical_graph_bytes = encode_canonical_evidence_graph(&nodes, &edges, &virtual_nodes);

    // 7. Tính Tier 5: Graph Hash & Verification Hash
    let graph_hash = compute_graph_hash(
        PROTOCOL_VERSION,
        graph_version,
        SCHEMA_VERSION,
        &canonical_graph_bytes,
    );
    let verification_hash =
        compute_verification_hash(PROTOCOL_VERSION, graph_version, &graph_hash, &evidence_root);

    DeviceEvidenceGraph {
        nodes,
        edges,
        virtual_nodes,
        virtual_points,
        evidence_root,
        graph_hash,
        verification_hash,
        graph_version,
        schema_version: SCHEMA_VERSION,
        derivation_version: DERIVATION_VERSION,
    }
}

/// Sắp xếp chính tắc toàn bộ Nodes, Edges và Virtual Nodes thành byte stream xác định
pub fn encode_canonical_evidence_graph(
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    vnodes: &[VirtualNode],
) -> Vec<u8> {
    let mut sorted_nodes = nodes.to_vec();
    // Sắp xếp Nodes theo (ComponentType ASC, id ASC)
    sorted_nodes.sort_by(|a, b| {
        a.component_type
            .cmp(&b.component_type)
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut sorted_edges = edges.to_vec();
    // Sắp xếp Edges theo (source ASC, relation ASC, target ASC)
    sorted_edges.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then_with(|| a.relation.cmp(&b.relation))
            .then_with(|| a.target.cmp(&b.target))
    });

    let mut sorted_vnodes = vnodes.to_vec();
    // Sắp xếp Virtual Nodes theo id ASC
    sorted_vnodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"NODES:\n");
    for n in sorted_nodes {
        let line = format!(
            "type={}|id={}|hash={}|commit={}\n",
            n.component_type, n.id, n.component_hash, n.node_commitment
        );
        buffer.extend_from_slice(line.as_bytes());
    }

    buffer.extend_from_slice(b"EDGES:\n");
    for e in sorted_edges {
        let line = format!("src={}|rel={}|dst={}\n", e.source, e.relation, e.target);
        buffer.extend_from_slice(line.as_bytes());
    }

    buffer.extend_from_slice(b"VNODES:\n");
    for v in sorted_vnodes {
        let line = format!(
            "type={}|id={}|vhash={}\n",
            v.virtual_type, v.id, v.virtual_hash
        );
        buffer.extend_from_slice(line.as_bytes());
    }

    buffer
}
