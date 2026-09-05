//! CyberV Mock Hardware Collector (Reference Simulator)
//!
//! Ref: rv plan1.md #10: Mock collector đóng vai trò reference simulator
//! nạp các golden test fixtures phục vụ kiểm thử và mô phỏng thay linh kiện.

use super::collector::{HardwareCollector, HardwareError};
use super::models::{ComponentStatus, ComponentType, Confidence, HardwareSnapshot};

pub const FIXTURE_BASELINE: &str = include_str!("fixtures/baseline.json");
pub const FIXTURE_RAM_UPGRADE: &str = include_str!("fixtures/ram_upgrade.json");
pub const FIXTURE_DISK_REPLACE: &str = include_str!("fixtures/disk_replace.json");
pub const FIXTURE_INCOMPLETE_WMI: &str = include_str!("fixtures/incomplete_wmi.json");

/// Bộ giả lập phần cứng theo kịch bản
#[derive(Debug, Clone)]
pub struct MockHardwareCollector {
    snapshot: HardwareSnapshot,
}

impl MockHardwareCollector {
    /// Khởi tạo với kịch bản Baseline (máy gốc)
    pub fn baseline() -> Result<Self, HardwareError> {
        Self::from_json_str(FIXTURE_BASELINE)
    }

    /// Khởi tạo với kịch bản RAM Upgrade (nâng cấp dung lượng RAM)
    pub fn ram_upgrade() -> Result<Self, HardwareError> {
        Self::from_json_str(FIXTURE_RAM_UPGRADE)
    }

    /// Khởi tạo với kịch bản Disk Replace (thay ổ SSD)
    pub fn disk_replace() -> Result<Self, HardwareError> {
        Self::from_json_str(FIXTURE_DISK_REPLACE)
    }

    /// Khởi tạo với kịch bản Incomplete WMI (VM / OEM thiếu serial)
    pub fn incomplete_wmi() -> Result<Self, HardwareError> {
        Self::from_json_str(FIXTURE_INCOMPLETE_WMI)
    }

    /// Khởi tạo với kịch bản Giả mạo WMI (WMI serial hooking/junk: "To Be Filled By O.E.M.")
    pub fn wmi_spoofed_profile() -> Result<Self, HardwareError> {
        let mut baseline = Self::baseline()?.snapshot;
        for c in &mut baseline.components {
            c.attributes
                .insert("serial".to_string(), "To Be Filled By O.E.M.".to_string());
            c.status = ComponentStatus::Partial;
            c.confidence = Confidence::Low;
        }
        Ok(Self { snapshot: baseline })
    }

    /// Khởi tạo với kịch bản Máy ảo Hyper-V (VMware/Hyper-V virtualized)
    pub fn vm_hyperv_profile() -> Result<Self, HardwareError> {
        let mut baseline = Self::baseline()?.snapshot;
        for c in &mut baseline.components {
            if c.component_type == ComponentType::Motherboard {
                c.canonical_id = "board:microsoft corporation:virtual machine".to_string();
                c.attributes
                    .insert("vendor".to_string(), "microsoft corporation".to_string());
                c.attributes
                    .insert("product".to_string(), "virtual machine".to_string());
            } else if c.component_type == ComponentType::Storage {
                c.canonical_id = "disk:msft virtual disk:virtual-0001:107374182400".to_string();
                c.attributes
                    .insert("model".to_string(), "msft virtual disk".to_string());
                c.attributes
                    .insert("serial".to_string(), "virtual-0001".to_string());
            }
        }
        Ok(Self { snapshot: baseline })
    }

    /// Khởi tạo với kịch bản Máy ảo nhân bản (VM Clone với Disk ảo cloned)
    pub fn vm_cloned_profile() -> Result<Self, HardwareError> {
        let mut vm = Self::vm_hyperv_profile()?.snapshot;
        for c in &mut vm.components {
            if c.component_type == ComponentType::Storage {
                c.canonical_id =
                    "disk:msft virtual disk:virtual-0002-cloned:107374182400".to_string();
                c.attributes
                    .insert("serial".to_string(), "virtual-0002-cloned".to_string());
            }
        }
        Ok(Self { snapshot: vm })
    }

    /// Khởi tạo từ chuỗi JSON bất kỳ
    pub fn from_json_str(json: &str) -> Result<Self, HardwareError> {
        let snapshot: HardwareSnapshot = serde_json::from_str(json).map_err(|e| {
            HardwareError::MockError(format!("Failed to parse fixture JSON: {}", e))
        })?;
        Ok(Self { snapshot })
    }

    /// Khởi tạo trực tiếp từ đối tượng HardwareSnapshot
    pub fn from_snapshot(snapshot: HardwareSnapshot) -> Self {
        Self { snapshot }
    }
}

impl HardwareCollector for MockHardwareCollector {
    fn collect(&self) -> Result<HardwareSnapshot, HardwareError> {
        Ok(self.snapshot.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::models::ComponentType;

    #[test]
    fn test_mock_collector_baseline() {
        let collector = MockHardwareCollector::baseline().unwrap();
        let snapshot = collector.collect().unwrap();

        assert_eq!(snapshot.components.len(), 5);
        assert_eq!(snapshot.get_components_by_type(ComponentType::Cpu).len(), 1);
        assert_eq!(
            snapshot.get_components_by_type(ComponentType::Memory).len(),
            2
        );
        assert_eq!(
            snapshot
                .get_components_by_type(ComponentType::Storage)
                .len(),
            1
        );
        assert_eq!(
            snapshot
                .get_components_by_type(ComponentType::Motherboard)
                .len(),
            1
        );
    }

    #[test]
    fn test_mock_collector_incomplete_wmi() {
        let collector = MockHardwareCollector::incomplete_wmi().unwrap();
        let snapshot = collector.collect().unwrap();

        // Kiểm tra disk có partial status
        let disks = snapshot.get_components_by_type(ComponentType::Storage);
        assert_eq!(disks.len(), 1);
        assert_eq!(
            disks[0].status,
            crate::hardware::models::ComponentStatus::Partial
        );
    }
}
