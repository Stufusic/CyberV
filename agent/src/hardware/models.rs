//! CyberV Hardware Models & Type-Safe Abstractions
//!
//! Định nghĩa các cấu trúc dữ liệu cho quá trình thu thập và chuẩn hóa phần cứng.
//! Ref: rv plan1.md #1, #4, #8, #9 và Rule.md Điều 4.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Nhóm loại linh kiện phần cứng được quan sát
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ComponentType {
    Cpu,
    Memory,
    Storage,
    Motherboard,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::Cpu => write!(f, "CPU"),
            ComponentType::Memory => write!(f, "Memory"),
            ComponentType::Storage => write!(f, "Storage"),
            ComponentType::Motherboard => write!(f, "Motherboard"),
        }
    }
}

/// Nguồn gốc dữ liệu thu thập (rv plan1.md #1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionSource {
    WindowsWmi,
    Sysinfo,
    Mock,
}

/// Mức độ tin cậy của dữ liệu linh kiện (rv plan1.md #1, #7)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Trạng thái thu thập linh kiện (rv plan1.md #9)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Complete,
    Partial,
    Unavailable,
}

/// Giá trị thô đa kiểu (rv plan1.md #4: Strong typing thay vì ép chuỗi sớm)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawValue {
    String(String),
    Integer(u64),
    Boolean(bool),
    Bytes(Vec<u8>),
    Missing,
}

impl RawValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            RawValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            RawValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn is_missing(&self) -> bool {
        matches!(self, RawValue::Missing)
    }
}

/// Linh kiện ở tầng dữ liệu thô (Raw Component)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawComponent {
    pub component_type: ComponentType,
    pub local_id: String,
    pub attributes: BTreeMap<String, RawValue>,
    pub source: CollectionSource,
    pub status: ComponentStatus,
}

/// Linh kiện đã qua chuẩn hóa xác định (Normalized Component)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedComponent {
    pub component_type: ComponentType,
    pub canonical_id: String,
    pub attributes: BTreeMap<String, String>,
    pub source: CollectionSource,
    pub status: ComponentStatus,
    pub confidence: Confidence,
}

/// Ảnh chụp trạng thái toàn bộ phần cứng thiết bị (Hardware Snapshot)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareSnapshot {
    pub components: Vec<NormalizedComponent>,
    pub collected_at: u64,
    pub collector_version: String,
}

impl HardwareSnapshot {
    pub fn new(components: Vec<NormalizedComponent>, collector_version: impl Into<String>) -> Self {
        let collected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            components,
            collected_at,
            collector_version: collector_version.into(),
        }
    }

    /// Lấy danh sách linh kiện theo loại
    pub fn get_components_by_type(&self, c_type: ComponentType) -> Vec<&NormalizedComponent> {
        self.components
            .iter()
            .filter(|c| c.component_type == c_type)
            .collect()
    }
}
