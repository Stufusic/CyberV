//! CyberV Component Hasher
//!
//! Tính toán băm mật mã học cho linh kiện bằng chuẩn SHA-512 (FIPS 180-4 / NSA CNSA Suite).
//! Ref: Pipeline.md Section 7, rv.md #1, #9 và Rule.md Điều 2, 4, 20.

use crate::fingerprint::canonical::CanonicalEncoder;
use crate::hardware::models::{
    CollectionSource, ComponentStatus, ComponentType, Confidence, HardwareSnapshot,
    NormalizedComponent,
};
use crate::protocol::constants::{DOMAIN_COMPONENT, PROTOCOL_VERSION, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Thực thể linh kiện sau khi băm mật mã học (Hashed Component)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedComponent {
    pub component_type: ComponentType,
    pub canonical_id: String,
    pub component_hash: String, // Chuỗi Hexadecimal chữ thường đúng 128 ký tự (512-bit)
    pub schema_version: u32,
    pub source: CollectionSource,
    pub status: ComponentStatus,
    pub confidence: Confidence,
    pub canonical_bytes: Vec<u8>,
}

/// Tính toán mã băm SHA-512 cho một linh kiện đã được chuẩn hóa với Domain Separation
pub fn hash_component(component: &NormalizedComponent) -> HashedComponent {
    // 1. Tạo chuỗi byte chính tắc từ các thuộc tính đã chuẩn hóa
    let mut encoder = CanonicalEncoder::new();
    for (k, v) in &component.attributes {
        encoder.add_field(k, v);
    }
    let canonical_bytes = encoder.to_canonical_bytes();

    // 2. Tính toán SHA-512 với Domain Separator và Byte Delimiters (0x00)
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_COMPONENT);
    hasher.update([0x00]);
    hasher.update(PROTOCOL_VERSION.to_be_bytes());
    hasher.update([0x00]);
    hasher.update(
        component
            .component_type
            .to_string()
            .to_uppercase()
            .as_bytes(),
    );
    hasher.update([0x00]);
    hasher.update(&canonical_bytes);

    let digest = hasher.finalize();
    // Chuyển 64 bytes thành 128 ký tự hex chữ thường
    let component_hash = format!("{:x}", digest);

    HashedComponent {
        component_type: component.component_type,
        canonical_id: component.canonical_id.clone(),
        component_hash,
        schema_version: SCHEMA_VERSION,
        source: component.source,
        status: component.status,
        confidence: component.confidence,
        canonical_bytes,
    }
}

/// Băm toàn bộ các linh kiện trong một HardwareSnapshot
pub fn hash_snapshot(snapshot: &HardwareSnapshot) -> Vec<HashedComponent> {
    snapshot.components.iter().map(hash_component).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::collector::HardwareCollector;
    use crate::hardware::mock::MockHardwareCollector;
    use crate::hardware::models::RawComponent;
    use crate::hardware::models::RawValue;
    use crate::hardware::normalizer::normalize_component;
    use std::collections::BTreeMap;

    #[test]
    fn test_sha512_hash_length_and_determinism() {
        let mut attrs = BTreeMap::new();
        attrs.insert("vendor".to_string(), RawValue::String("intel".to_string()));
        attrs.insert("model".to_string(), RawValue::String("core i7".to_string()));
        attrs.insert("logical_cores".to_string(), RawValue::Integer(16));

        let raw = RawComponent {
            component_type: ComponentType::Cpu,
            local_id: "cpu-0".to_string(),
            attributes: attrs,
            source: CollectionSource::WindowsWmi,
            status: ComponentStatus::Complete,
        };

        let norm = normalize_component(&raw, CollectionSource::WindowsWmi);
        let hashed1 = hash_component(&norm);
        let hashed2 = hash_component(&norm);

        // Chuẩn SHA-512 bắt buộc phải là 128 ký tự hex (64 bytes)
        assert_eq!(hashed1.component_hash.len(), 128);
        // Tính xác định: 2 lần băm cùng dữ liệu phải cho kết quả giống nhau 100%
        assert_eq!(hashed1.component_hash, hashed2.component_hash);
        assert_eq!(hashed1.schema_version, 1);
    }

    #[test]
    fn test_domain_separation() {
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "model".to_string(),
            RawValue::String("generic device".to_string()),
        );

        let raw_cpu = RawComponent {
            component_type: ComponentType::Cpu,
            local_id: "dev-0".to_string(),
            attributes: attrs.clone(),
            source: CollectionSource::WindowsWmi,
            status: ComponentStatus::Complete,
        };

        let raw_mem = RawComponent {
            component_type: ComponentType::Memory,
            local_id: "dev-0".to_string(),
            attributes: attrs,
            source: CollectionSource::WindowsWmi,
            status: ComponentStatus::Complete,
        };

        let norm_cpu = normalize_component(&raw_cpu, CollectionSource::WindowsWmi);
        let norm_mem = normalize_component(&raw_mem, CollectionSource::WindowsWmi);

        let hashed_cpu = hash_component(&norm_cpu);
        let hashed_mem = hash_component(&norm_mem);

        // Do có domain separation với COMPONENT_TYPE, 2 hash phải hoàn toàn khác nhau
        assert_ne!(hashed_cpu.component_hash, hashed_mem.component_hash);
    }

    #[test]
    fn test_golden_fixtures_mutation_diff() {
        let baseline = MockHardwareCollector::baseline()
            .unwrap()
            .collect()
            .unwrap();
        let ram_up = MockHardwareCollector::ram_upgrade()
            .unwrap()
            .collect()
            .unwrap();
        let disk_rep = MockHardwareCollector::disk_replace()
            .unwrap()
            .collect()
            .unwrap();

        let hashed_baseline = hash_snapshot(&baseline);
        let hashed_ram_up = hash_snapshot(&ram_up);
        let hashed_disk_rep = hash_snapshot(&disk_rep);

        // 1. So sánh Baseline vs RAM Upgrade
        // CPU, Storage, Motherboard phải GIỐNG NHAU 100%
        assert_eq!(
            hashed_baseline[0].component_hash, // CPU
            hashed_ram_up[0].component_hash
        );
        assert_eq!(
            hashed_baseline[3].component_hash, // Storage
            hashed_ram_up[3].component_hash
        );
        assert_eq!(
            hashed_baseline[4].component_hash, // Motherboard
            hashed_ram_up[4].component_hash
        );
        // Chỉ duy nhất Memory thay đổi
        assert_ne!(
            hashed_baseline[1].component_hash, // RAM Slot 0
            hashed_ram_up[1].component_hash
        );
        assert_ne!(
            hashed_baseline[2].component_hash, // RAM Slot 1
            hashed_ram_up[2].component_hash
        );

        // 2. So sánh Baseline vs Disk Replace
        // CPU, Memory, Motherboard phải GIỐNG NHAU 100%
        assert_eq!(
            hashed_baseline[0].component_hash, // CPU
            hashed_disk_rep[0].component_hash
        );
        assert_eq!(
            hashed_baseline[1].component_hash, // RAM Slot 0
            hashed_disk_rep[1].component_hash
        );
        assert_eq!(
            hashed_baseline[2].component_hash, // RAM Slot 1
            hashed_disk_rep[2].component_hash
        );
        assert_eq!(
            hashed_baseline[4].component_hash, // Motherboard
            hashed_disk_rep[4].component_hash
        );
        // Chỉ duy nhất Storage thay đổi
        assert_ne!(
            hashed_baseline[3].component_hash, // Storage
            hashed_disk_rep[3].component_hash
        );
    }
}
