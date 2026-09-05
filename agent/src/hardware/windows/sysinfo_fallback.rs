//! CyberV Sysinfo Fallback Collector
//!
//! Thu thập thông tin phần cứng qua System API khi WMI không khả dụng hoặc bị chặn quyền.
//! Ref: rv plan1.md #1: Gắn đúng CollectionSource::Sysinfo và Confidence::Medium.

use crate::hardware::collector::{HardwareCollector, HardwareError};
use crate::hardware::models::{
    CollectionSource, ComponentStatus, ComponentType, HardwareSnapshot, RawComponent, RawValue,
};
use crate::hardware::normalizer::normalize_component;
use std::collections::BTreeMap;
use sysinfo::{Disks, System};

pub struct SysinfoFallbackCollector;

impl SysinfoFallbackCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SysinfoFallbackCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareCollector for SysinfoFallbackCollector {
    fn collect(&self) -> Result<HardwareSnapshot, HardwareError> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut normalized_components = Vec::new();

        // 1. Thu thập CPU
        let cpus = sys.cpus();
        if !cpus.is_empty() {
            let first_cpu = &cpus[0];
            let mut attrs = BTreeMap::new();
            attrs.insert(
                "vendor".to_string(),
                RawValue::String(first_cpu.vendor_id().to_string()),
            );
            attrs.insert(
                "model".to_string(),
                RawValue::String(first_cpu.brand().to_string()),
            );
            attrs.insert(
                "logical_cores".to_string(),
                RawValue::Integer(cpus.len() as u64),
            );

            let raw = RawComponent {
                component_type: ComponentType::Cpu,
                local_id: "cpu-0".to_string(),
                attributes: attrs,
                source: CollectionSource::Sysinfo,
                status: ComponentStatus::Complete,
            };
            normalized_components.push(normalize_component(&raw, CollectionSource::Sysinfo));
        }

        // 2. Thu thập Memory (RAM tổng thể mức OS)
        let total_mem = sys.total_memory();
        if total_mem > 0 {
            let mut attrs = BTreeMap::new();
            attrs.insert("capacity_bytes".to_string(), RawValue::Integer(total_mem));
            attrs.insert(
                "bank_label".to_string(),
                RawValue::String("system_memory".to_string()),
            );

            let raw = RawComponent {
                component_type: ComponentType::Memory,
                local_id: "ram-system".to_string(),
                attributes: attrs,
                source: CollectionSource::Sysinfo,
                status: ComponentStatus::Complete,
            };
            normalized_components.push(normalize_component(&raw, CollectionSource::Sysinfo));
        }

        // 3. Thu thập Ổ đĩa qua sysinfo Disks
        let disks = Disks::new_with_refreshed_list();
        for (idx, disk) in disks.list().iter().enumerate() {
            let mut attrs = BTreeMap::new();
            let name = disk.name().to_string_lossy().to_string();
            attrs.insert("model".to_string(), RawValue::String(name));
            attrs.insert(
                "size_bytes".to_string(),
                RawValue::Integer(disk.total_space()),
            );

            let raw = RawComponent {
                component_type: ComponentType::Storage,
                local_id: format!("disk-{}", idx),
                attributes: attrs,
                source: CollectionSource::Sysinfo,
                status: ComponentStatus::Partial, // sysinfo không trích xuất được physical serial
            };
            normalized_components.push(normalize_component(&raw, CollectionSource::Sysinfo));
        }

        if normalized_components.is_empty() {
            return Err(HardwareError::EmptySnapshot);
        }

        Ok(HardwareSnapshot::new(
            normalized_components,
            "cyberv-sysinfo-v0.1",
        ))
    }
}
