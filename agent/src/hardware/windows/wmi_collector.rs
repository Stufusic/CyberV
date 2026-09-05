//! CyberV Windows WMI Collector
//!
//! Thu thập thông tin phần cứng vật lý qua Windows Management Instrumentation (WMI).
//! Ref: rv plan1.md #1, #7, #8, #9, #13 và Rule.md Điều 4, 18, 23.

use super::wmi_dto::{Win32BaseBoard, Win32DiskDrive, Win32PhysicalMemory, Win32Processor};
use crate::hardware::collector::{HardwareCollector, HardwareError};
use crate::hardware::models::{
    CollectionSource, ComponentStatus, ComponentType, HardwareSnapshot, RawComponent, RawValue,
};
use crate::hardware::normalizer::normalize_component;
use std::collections::BTreeMap;
use wmi::WMIConnection;

pub struct WindowsWmiCollector;

impl WindowsWmiCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsWmiCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareCollector for WindowsWmiCollector {
    fn collect(&self) -> Result<HardwareSnapshot, HardwareError> {
        // Mở kết nối WMI (wmi 0.18+ tự động quản lý COM context)
        let wmi_con = WMIConnection::new().map_err(|e| {
            HardwareError::WmiError(format!("Failed to connect to WMI provider: {}", e))
        })?;

        let mut normalized_components = Vec::new();

        // 1. Thu thập CPU (Win32_Processor)
        match wmi_con.query::<Win32Processor>() {
            Ok(processors) => {
                for (idx, proc) in processors.into_iter().enumerate() {
                    let mut attrs = BTreeMap::new();
                    if let Some(mfg) = proc.manufacturer {
                        attrs.insert("vendor".to_string(), RawValue::String(mfg));
                    }
                    if let Some(name) = proc.name {
                        attrs.insert("model".to_string(), RawValue::String(name));
                    }
                    if let Some(cores) = proc.number_of_logical_processors {
                        attrs.insert("logical_cores".to_string(), RawValue::Integer(cores as u64));
                    }
                    if let Some(fam) = proc.family {
                        attrs.insert("family".to_string(), RawValue::String(fam.to_string()));
                    }
                    if let Some(pid) = proc.processor_id {
                        attrs.insert("processor_id".to_string(), RawValue::String(pid));
                    }

                    let raw = RawComponent {
                        component_type: ComponentType::Cpu,
                        local_id: format!("cpu-{}", idx),
                        attributes: attrs,
                        source: CollectionSource::WindowsWmi,
                        status: ComponentStatus::Complete,
                    };
                    normalized_components
                        .push(normalize_component(&raw, CollectionSource::WindowsWmi));
                }
            }
            Err(e) => {
                tracing::warn!("WMI Win32_Processor query failed: {}", e);
            }
        }

        // 2. Thu thập RAM vật lý (Win32_PhysicalMemory)
        match wmi_con.query::<Win32PhysicalMemory>() {
            Ok(memories) => {
                for (idx, mem) in memories.into_iter().enumerate() {
                    let mut attrs = BTreeMap::new();
                    if let Some(bytes) = mem.capacity {
                        attrs.insert("capacity_bytes".to_string(), RawValue::Integer(bytes));
                    }
                    if let Some(mfg) = mem.manufacturer {
                        attrs.insert("manufacturer".to_string(), RawValue::String(mfg));
                    }
                    if let Some(part) = mem.part_number {
                        attrs.insert("part_number".to_string(), RawValue::String(part));
                    }
                    if let Some(speed) = mem.configured_clock_speed {
                        attrs.insert("speed_mhz".to_string(), RawValue::Integer(speed as u64));
                    }
                    if let Some(bank) = mem.bank_label {
                        attrs.insert("bank_label".to_string(), RawValue::String(bank));
                    }

                    let raw = RawComponent {
                        component_type: ComponentType::Memory,
                        local_id: format!("ram-{}", idx),
                        attributes: attrs,
                        source: CollectionSource::WindowsWmi,
                        status: ComponentStatus::Complete,
                    };
                    normalized_components
                        .push(normalize_component(&raw, CollectionSource::WindowsWmi));
                }
            }
            Err(e) => {
                tracing::warn!("WMI Win32_PhysicalMemory query failed: {}", e);
            }
        }

        // 3. Thu thập Ổ Đĩa Vật Lý (Win32_DiskDrive) - rv plan1.md #6: physical disk, not drive letters
        match wmi_con.query::<Win32DiskDrive>() {
            Ok(disks) => {
                for (idx, disk) in disks.into_iter().enumerate() {
                    let mut attrs = BTreeMap::new();
                    let mut status = ComponentStatus::Complete;

                    if let Some(model) = disk.model {
                        attrs.insert("model".to_string(), RawValue::String(model));
                    }
                    if let Some(serial) = disk.serial_number {
                        attrs.insert("serial".to_string(), RawValue::String(serial));
                    } else {
                        // rv plan1.md #7: serial thiếu ghi nhận Partial, không crash
                        status = ComponentStatus::Partial;
                    }
                    if let Some(sz) = disk.size {
                        attrs.insert("size_bytes".to_string(), RawValue::Integer(sz));
                    }
                    if let Some(iface) = disk.interface_type {
                        attrs.insert("interface".to_string(), RawValue::String(iface));
                    }

                    let raw = RawComponent {
                        component_type: ComponentType::Storage,
                        local_id: format!("disk-{}", idx),
                        attributes: attrs,
                        source: CollectionSource::WindowsWmi,
                        status,
                    };
                    normalized_components
                        .push(normalize_component(&raw, CollectionSource::WindowsWmi));
                }
            }
            Err(e) => {
                tracing::warn!("WMI Win32_DiskDrive query failed: {}", e);
            }
        }

        // 4. Thu thập Bo Mạch Chủ (Win32_BaseBoard)
        match wmi_con.query::<Win32BaseBoard>() {
            Ok(boards) => {
                for (idx, board) in boards.into_iter().enumerate() {
                    let mut attrs = BTreeMap::new();
                    let mut status = ComponentStatus::Complete;

                    if let Some(mfg) = board.manufacturer {
                        attrs.insert("manufacturer".to_string(), RawValue::String(mfg));
                    }
                    if let Some(prod) = board.product {
                        attrs.insert("product".to_string(), RawValue::String(prod));
                    }
                    if let Some(serial) = board.serial_number {
                        attrs.insert("serial".to_string(), RawValue::String(serial));
                    } else {
                        status = ComponentStatus::Partial;
                    }

                    let raw = RawComponent {
                        component_type: ComponentType::Motherboard,
                        local_id: format!("board-{}", idx),
                        attributes: attrs,
                        source: CollectionSource::WindowsWmi,
                        status,
                    };
                    normalized_components
                        .push(normalize_component(&raw, CollectionSource::WindowsWmi));
                }
            }
            Err(e) => {
                // rv plan1.md #9: Lỗi đọc motherboard trên VM không làm fail cả snapshot
                tracing::warn!("WMI Win32_BaseBoard query failed (non-fatal): {}", e);
            }
        }

        if normalized_components.is_empty() {
            return Err(HardwareError::EmptySnapshot);
        }

        Ok(HardwareSnapshot::new(
            normalized_components,
            "cyberv-wmi-v0.1",
        ))
    }
}
