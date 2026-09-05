//! CyberV Hardware Collection Subsystem
//!
//! Layer A — Device Observation & Layer B — Device State Normalization
//! Ref: rv.md #12, rv plan1.md, và Rule.md Điều 4, 18, 23.

pub mod collector;
pub mod mock;
pub mod models;
pub mod normalizer;
pub mod windows;

pub use collector::{ComponentSummary, HardwareCollector, HardwareError, HardwareReport};
pub use mock::MockHardwareCollector;
pub use models::{
    CollectionSource, ComponentStatus, ComponentType, Confidence, HardwareSnapshot,
    NormalizedComponent, RawComponent, RawValue,
};
pub use normalizer::normalize_component;
pub use windows::{SysinfoFallbackCollector, WindowsWmiCollector};

/// Thu thập ảnh chụp phần cứng hệ thống tự động
///
/// Thử nghiệm thu thập qua WMI trước; nếu WMI bị lỗi hoặc không khả dụng,
/// tự động suy thoái êm thuận (graceful degradation) sang sysinfo fallback.
pub fn collect_hardware_snapshot() -> Result<HardwareSnapshot, HardwareError> {
    tracing::info!("Bắt đầu quan sát phần cứng qua Windows WMI...");
    let wmi_collector = WindowsWmiCollector::new();

    match wmi_collector.collect() {
        Ok(snapshot) => {
            tracing::info!(
                components_count = snapshot.components.len(),
                "Thu thập WMI thành công (High Confidence)"
            );
            Ok(snapshot)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "WMI không khả dụng hoặc lỗi quyền. Chuyển sang Sysinfo Fallback..."
            );
            let fallback = SysinfoFallbackCollector::new();
            fallback.collect()
        }
    }
}
