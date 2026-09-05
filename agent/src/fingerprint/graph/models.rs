//! CyberV Device Evidence Graph Models
//!
//! Khai báo các mô hình dữ liệu cho Đồ thị Bằng chứng Thiết bị.
//! Ref: rv p3.md #1, #2, #3, #4, #5, #11, #12 và Rule.md Điều 4.

use crate::hardware::models::{CollectionSource, ComponentStatus, Confidence};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Phân loại tính chất đỉnh đồ thị
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeKind {
    Root,
    RealComponent,
    Virtual,
}

/// Đỉnh Đồ Thị (Graph Node)
///
/// Đại diện cho đỉnh gốc (Root) hoặc linh kiện vật lý (RealComponent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String, // Định danh tham chiếu topo (vd: "root:device", "cpu:intel:...")
    pub node_kind: NodeKind,
    pub component_type: String, // "ROOT", "CPU", "MEMORY", "STORAGE", "MOTHERBOARD"
    pub component_hash: String, // SHA-512 (Tier 1 Component Hash từ Phase 2)
    pub node_commitment: String, // SHA-512 (Tier 2 Node Commitment ràng buộc ngữ cảnh)
    pub schema_version: u32,
    pub source: CollectionSource,
    pub status: ComponentStatus,
    pub confidence: Confidence,
}

/// Cạnh Quan Hệ (Graph Edge)
///
/// Thể hiện quan hệ topo học giữa các đỉnh trong hệ thống.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub relation: String, // "contains", "hosts"
    pub target: String,
}

/// Đỉnh Bằng Chứng Ảo (Virtual Node)
///
/// Các đỉnh suy diễn mang tính đặc trưng cấu trúc topo và độ nhất quán.
/// Ref: rv p3.md #3, #4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualNode {
    pub id: String,                     // vd: "vnode:platform_consistency"
    pub virtual_type: String,           // "PLATFORM_CONSISTENCY", "MEMORY_TOPOLOGY", v.v.
    pub derivation_version: u32,        // 1
    pub input_commitments: Vec<String>, // Danh sách node_commitment đầu vào đã sinh ra node này (minh bạch provenance)
    pub virtual_hash: String,           // SHA-512 (Tier 3 Virtual Node Hash)
    pub attributes: BTreeMap<String, String>,
}

/// Điểm Bằng Chứng Ảo (Virtual Point / Evidence Point)
///
/// Điểm suy diễn được biểu diễn bằng tỷ lệ số nguyên deterministic (value / scale).
/// Ref: rv p3.md #5, #6: Tuyệt đối không dùng float; không tự ý cấp quyền (Point ≠ Credential).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualPoint {
    pub id: String, // vd: "point:platform_consistency"
    pub value: i64, // vd: 9800
    pub scale: u32, // vd: 10000 (tức 9800 / 10000 = 0.98)
    pub derivation_version: u32,
}

impl VirtualPoint {
    pub fn new(id: impl Into<String>, value: i64, scale: u32, derivation_version: u32) -> Self {
        Self {
            id: id.into(),
            value,
            scale,
            derivation_version,
        }
    }

    /// Định dạng hiển thị dưới dạng chuỗi thập phân an toàn
    pub fn to_display_string(&self) -> String {
        let val_f = self.value as f64 / self.scale as f64;
        format!("{:.2} ({}/{})", val_f, self.value, self.scale)
    }

    /// Trả về tỷ lệ chuẩn hóa trên thang 10000 bằng toán số nguyên xác định
    pub fn normalized_ratio(&self) -> i64 {
        if self.scale == 0 {
            0
        } else {
            (self.value * 10000) / (self.scale as i64)
        }
    }
}

/// Đồ Thị Bằng Chứng Thiết Bị Toàn Diện (Device Evidence Graph)
///
/// Chứa toàn bộ cây topo, đỉnh thật, đỉnh ảo, điểm bằng chứng và các cam kết băm đa tầng.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEvidenceGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub evidence_root: String,     // SHA-512 (Tier 4 Evidence Root)
    pub graph_hash: String,        // SHA-512 (Tier 5 Graph Hash đại diện cấu trúc topo)
    pub verification_hash: String, // SHA-512 (Tier 5 Verification Hash - Cam kết tối cao)
    pub graph_version: u32,
    pub schema_version: u32,
    pub derivation_version: u32,
}

impl DeviceEvidenceGraph {
    /// Trích xuất danh sách node theo loại linh kiện
    pub fn get_nodes_by_type(&self, c_type: &str) -> Vec<&GraphNode> {
        self.nodes
            .iter()
            .filter(|n| n.component_type.eq_ignore_ascii_case(c_type))
            .collect()
    }

    /// Xuất ra định dạng JSON Value phục vụ lưu DB (cột canonical_graph_json JSONB) và hiển thị Web UI
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}
