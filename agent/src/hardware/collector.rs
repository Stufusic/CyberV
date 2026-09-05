//! CyberV Hardware Collector Trait & Error Handling
//!
//! Ref: rv plan1.md #11 và Rule.md Điều 18, 23.

use super::models::{ComponentType, HardwareSnapshot};
use thiserror::Error;

/// Các lỗi có thể phát sinh trong quá trình thu thập phần cứng
#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("WMI connection or query failed: {0}")]
    WmiError(String),

    #[error("Sysinfo collection failed: {0}")]
    SysinfoError(String),

    #[error("Mock fixture error: {0}")]
    MockError(String),

    #[error("No usable hardware components could be collected")]
    EmptySnapshot,
}

/// Interface trừu tượng cho mọi bộ thu thập phần cứng (WMI, Sysinfo, Mock)
pub trait HardwareCollector: Send + Sync {
    /// Thu thập ảnh chụp phần cứng đã được chuẩn hóa
    fn collect(&self) -> Result<HardwareSnapshot, HardwareError>;
}

/// Báo cáo phần cứng an toàn (Sanitized Hardware Report)
///
/// Phục vụ việc hiển thị console / log mà không để lộ các giá trị nhạy cảm như Serial Number.
#[derive(Debug, Clone)]
pub struct ComponentSummary {
    pub component_type: ComponentType,
    pub count: usize,
    pub status: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct HardwareReport {
    pub collector_source: String,
    pub total_components: usize,
    pub summaries: Vec<ComponentSummary>,
    pub collected_at: u64,
}

impl HardwareReport {
    pub fn from_snapshot(snapshot: &HardwareSnapshot) -> Self {
        let mut summaries = Vec::new();

        for c_type in [
            ComponentType::Cpu,
            ComponentType::Memory,
            ComponentType::Storage,
            ComponentType::Motherboard,
        ] {
            let matching = snapshot.get_components_by_type(c_type);
            if !matching.is_empty() {
                let description = match c_type {
                    ComponentType::Cpu => {
                        let cores = matching[0]
                            .attributes
                            .get("logical_cores")
                            .cloned()
                            .unwrap_or_else(|| "?".to_string());
                        let model = matching[0]
                            .attributes
                            .get("model")
                            .cloned()
                            .unwrap_or_else(|| "Unknown CPU".to_string());
                        format!("{} ({} cores)", model, cores)
                    }
                    ComponentType::Memory => {
                        let mut total_bytes: u64 = 0;
                        for m in &matching {
                            if let Some(cap) = m.attributes.get("capacity_bytes") {
                                if let Ok(bytes) = cap.parse::<u64>() {
                                    total_bytes += bytes;
                                }
                            }
                        }
                        let gb = total_bytes / (1024 * 1024 * 1024);
                        format!("{} physical module(s), ~{} GB total", matching.len(), gb)
                    }
                    ComponentType::Storage => {
                        format!("{} physical drive(s)", matching.len())
                    }
                    ComponentType::Motherboard => {
                        let mfg = matching[0]
                            .attributes
                            .get("manufacturer")
                            .cloned()
                            .unwrap_or_else(|| "Unknown".to_string());
                        let prod = matching[0]
                            .attributes
                            .get("product")
                            .cloned()
                            .unwrap_or_default();
                        format!("{} {}", mfg, prod).trim().to_string()
                    }
                };

                summaries.push(ComponentSummary {
                    component_type: c_type,
                    count: matching.len(),
                    status: format!("{:?}", matching[0].status),
                    description,
                });
            }
        }

        let collector_source = if let Some(first) = snapshot.components.first() {
            format!("{:?}", first.source)
        } else {
            "None".to_string()
        };

        Self {
            collector_source,
            total_components: snapshot.components.len(),
            summaries,
            collected_at: snapshot.collected_at,
        }
    }
}
