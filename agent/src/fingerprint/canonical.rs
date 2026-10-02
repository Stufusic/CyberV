//! CyberV Canonical Byte Encoding Specification
//!
//! Định nghĩa thuật toán chuyển đổi đối tượng phần cứng và đồ thị thành
//! chuỗi byte xác định (deterministic canonical bytes) trước khi băm SHA-256.
//! Tuân thủ nghiêm ngặt rv.md #9: KHÔNG dựa vào database JSONB hay sort JSON keys tùy tiện.

use std::collections::BTreeMap;

/// Chuẩn hóa chuỗi văn bản: loại bỏ khoảng trắng thừa ở đầu/cuối, chuyển thành chữ thường.
pub fn normalize_string(input: &str) -> String {
    input.trim().to_lowercase()
}

/// Bộ mã hóa chính tắc (Canonical Encoder) cho một tập thuộc tính dạng Key-Value
#[derive(Debug, Default, Clone)]
pub struct CanonicalEncoder {
    /// Sử dụng BTreeMap để tự động đảm bảo các trường luôn được sắp xếp tăng dần theo Key (lexicographical order)
    fields: BTreeMap<String, String>,
}

impl CanonicalEncoder {
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    /// Thêm một cặp key-value đã được chuẩn hóa
    pub fn add_field(&mut self, key: &str, value: &str) -> &mut Self {
        let normalized_key = normalize_string(key);
        let normalized_val = normalize_string(value);
        self.fields.insert(normalized_key, normalized_val);
        self
    }

    /// Xuất ra chuỗi byte chính tắc (Canonical Byte Stream)
    ///
    /// Định dạng: mỗi dòng gồm `key=value\n`. Các key luôn được sắp xếp thứ tự từ điển tăng dần.
    /// Key và value được ESCAPE (`\\`, `=`, `\n`, `\r`) để encoding là INJECTIVE:
    /// hai tập trường khác nhau không thể tạo cùng byte stream
    /// (M1: `("a","b\nc=1")` cũ từng trùng với `("a","b")+("c","1")`).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for (key, value) in &self.fields {
            buffer.extend_from_slice(escape_canonical_field(key).as_bytes());
            buffer.push(b'=');
            buffer.extend_from_slice(escape_canonical_field(value).as_bytes());
            buffer.push(b'\n');
        }
        buffer
    }
}

/// Escape một trường cho canonical `k=v\n` encoding (backslash-first).
pub fn escape_canonical_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// Cấu trúc đại diện cho một Node trong Hardware Graph
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalGraphNode {
    pub component_type: String,
    pub stable_id: String,
    pub component_hash: String,
    pub schema_version: u32,
}

/// Cấu trúc đại diện cho một Edge trong Hardware Graph
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalGraphEdge {
    pub source: String,
    pub relation: String,
    pub target: String,
}

/// Mã hóa toàn bộ đồ thị phần cứng thành byte stream chính tắc
pub fn encode_canonical_graph(
    mut nodes: Vec<CanonicalGraphNode>,
    mut edges: Vec<CanonicalGraphEdge>,
) -> Vec<u8> {
    // 1. Sắp xếp danh sách nodes ổn định theo (component_type ASC, stable_id ASC)
    nodes.sort_by(|a, b| {
        a.component_type
            .cmp(&b.component_type)
            .then_with(|| a.stable_id.cmp(&b.stable_id))
    });

    // 2. Sắp xếp danh sách edges ổn định theo (source ASC, relation ASC, target ASC)
    edges.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then_with(|| a.relation.cmp(&b.relation))
            .then_with(|| a.target.cmp(&b.target))
    });

    // M1: escape mọi trường cho encoding injective — giá trị chứa `|`, `=`
    // hay `\n` không thể giả làm ranh giới trường/dòng.
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"NODES:\n");
    for node in nodes {
        let line = format!(
            "type={}|id={}|hash={}|v={}\n",
            escape_graph_field(&node.component_type),
            escape_graph_field(&node.stable_id),
            escape_graph_field(&node.component_hash),
            node.schema_version
        );
        buffer.extend_from_slice(line.as_bytes());
    }

    buffer.extend_from_slice(b"EDGES:\n");
    for edge in edges {
        let line = format!(
            "src={}|rel={}|dst={}\n",
            escape_graph_field(&edge.source),
            escape_graph_field(&edge.relation),
            escape_graph_field(&edge.target)
        );
        buffer.extend_from_slice(line.as_bytes());
    }

    buffer
}

/// Escape một trường cho graph line encoding `k=v|...\n`.
pub fn escape_graph_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_encoder_deterministic_ordering() {
        // Cho dù thêm các trường theo thứ tự nào, output byte stream phải đồng nhất 100%
        let mut enc1 = CanonicalEncoder::new();
        enc1.add_field("vendor", "INTEL  ")
            .add_field("cores", "8")
            .add_field("model", "Core i7");

        let mut enc2 = CanonicalEncoder::new();
        enc2.add_field("model", "core i7")
            .add_field("vendor", "intel")
            .add_field("cores", "8  ");

        assert_eq!(enc1.to_canonical_bytes(), enc2.to_canonical_bytes());
        assert_eq!(
            String::from_utf8(enc1.to_canonical_bytes()).unwrap(),
            "cores=8\nmodel=core i7\nvendor=intel\n"
        );
    }

    #[test]
    fn test_canonical_graph_ordering() {
        let node_a = CanonicalGraphNode {
            component_type: "RAM".to_string(),
            stable_id: "slot1".to_string(),
            component_hash: "hash_ram_1".to_string(),
            schema_version: 1,
        };
        let node_b = CanonicalGraphNode {
            component_type: "CPU".to_string(),
            stable_id: "cpu0".to_string(),
            component_hash: "hash_cpu_0".to_string(),
            schema_version: 1,
        };

        let edge1 = CanonicalGraphEdge {
            source: "device".to_string(),
            relation: "contains".to_string(),
            target: "RAM".to_string(),
        };
        let edge2 = CanonicalGraphEdge {
            source: "device".to_string(),
            relation: "contains".to_string(),
            target: "CPU".to_string(),
        };

        // Đưa vào thứ tự RAM trước CPU
        let bytes1 = encode_canonical_graph(
            vec![node_a.clone(), node_b.clone()],
            vec![edge1.clone(), edge2.clone()],
        );
        // Đưa vào thứ tự CPU trước RAM
        let bytes2 = encode_canonical_graph(vec![node_b, node_a], vec![edge2, edge1]);

        // Cả 2 phải cho ra cùng 1 chuỗi byte chính xác
        assert_eq!(bytes1, bytes2);
    }

    /// M1 REGRESSION: encoding phải injective — giá trị chứa ký tự ranh giới
    /// không được tạo byte stream trùng với một tập trường khác.
    #[test]
    fn test_canonical_encoder_injective_over_separator_chars() {
        // ("a","b\nc=1") phải khác ("a","b") + ("c","1")
        let mut enc1 = CanonicalEncoder::new();
        enc1.add_field("a", "b\nc=1");

        let mut enc2 = CanonicalEncoder::new();
        enc2.add_field("a", "b").add_field("c", "1");

        assert_ne!(enc1.to_canonical_bytes(), enc2.to_canonical_bytes());

        // Graph encoding: giá trị chứa `|` không giả được ranh giới trường
        let g1 = encode_canonical_graph(
            vec![CanonicalGraphNode {
                component_type: "cpu|x=1".to_string(),
                stable_id: "s".to_string(),
                component_hash: "h".to_string(),
                schema_version: 1,
            }],
            vec![],
        );
        let g2 = encode_canonical_graph(
            vec![CanonicalGraphNode {
                component_type: "cpu".to_string(),
                stable_id: "s".to_string(),
                component_hash: "h".to_string(),
                schema_version: 1,
            }],
            vec![CanonicalGraphEdge {
                source: "x=1".to_string(),
                relation: "r".to_string(),
                target: "t".to_string(),
            }],
        );
        assert_ne!(g1, g2);
    }
}
