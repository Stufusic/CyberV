//! CyberV Hardware Normalizer
//!
//! Thực hiện chuẩn hóa hai tầng (Transport Normalization & Identity Normalization)
//! Ref: rv plan1.md #5, #6, #7 và Rule.md Điều 4.

use super::models::{
    CollectionSource, ComponentType, Confidence, NormalizedComponent, RawComponent,
};
use std::collections::BTreeMap;

/// Kiểm tra xem một chuỗi có phải là giá trị rác thường gặp từ BIOS/OEM hay không
pub fn is_oem_junk_value(val: &str) -> bool {
    let lower = val.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "" | "to be filled by o.e.m."
            | "to be filled by oem"
            | "default string"
            | "none"
            | "null"
            | "unknown"
            | "n/a"
            | "not specified"
            | "system manufacturer"
            | "system product name"
            | "chassis serial number"
            | "00000000"
            | "ffffffff"
    )
}

/// Tầng 1: Transport Normalization
///
/// Loại bỏ ký tự điều khiển ASCII, thu gọn khoảng trắng liên tiếp và chuyển về chữ thường.
/// Không tự ý xóa dấu câu (punctuation) có ý nghĩa trong tên linh kiện.
pub fn normalize_transport_string(val: &str) -> String {
    let without_control: String = val.chars().filter(|c| !c.is_ascii_control()).collect();

    let mut words = without_control.split_whitespace();
    let mut result = String::new();

    if let Some(first) = words.next() {
        result.push_str(first);
        for word in words {
            result.push(' ');
            result.push_str(word);
        }
    }

    result.to_lowercase()
}

/// Tầng 2: Identity Normalization cho CPU
pub fn normalize_cpu(raw: &RawComponent, source: CollectionSource) -> NormalizedComponent {
    let mut attrs = BTreeMap::new();
    let mut confidence = match source {
        CollectionSource::WindowsWmi => Confidence::High,
        CollectionSource::Sysinfo => Confidence::Medium,
        CollectionSource::Mock => Confidence::High,
    };

    // 1. Vendor
    if let Some(v) = raw.attributes.get("vendor").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(v);
        let canonical_vendor = if norm.contains("intel") {
            "intel".to_string()
        } else if norm.contains("amd") {
            "amd".to_string()
        } else {
            norm
        };
        attrs.insert("vendor".to_string(), canonical_vendor);
    }

    // 2. Model / Name
    if let Some(m) = raw.attributes.get("model").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(m);
        if !is_oem_junk_value(&norm) {
            attrs.insert("model".to_string(), norm);
        }
    }

    // 3. Logical Cores
    if let Some(cores) = raw.attributes.get("logical_cores").and_then(|v| v.as_u64()) {
        attrs.insert("logical_cores".to_string(), cores.to_string());
    }

    // 4. Family / Architecture
    if let Some(fam) = raw.attributes.get("family").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(fam);
        if !is_oem_junk_value(&norm) {
            attrs.insert("family".to_string(), norm);
        }
    }

    // 5. ProcessorId (SMBIOS/CPUID observation signal - rv plan1.md #3)
    if let Some(pid) = raw.attributes.get("processor_id").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(pid);
        if !is_oem_junk_value(&norm) {
            attrs.insert("processor_id".to_string(), norm);
        } else {
            confidence = Confidence::Medium;
        }
    }

    let vendor = attrs
        .get("vendor")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let model = attrs
        .get("model")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let canonical_id = format!("cpu:{}:{}", vendor, model);

    NormalizedComponent {
        component_type: ComponentType::Cpu,
        canonical_id,
        attributes: attrs,
        source,
        status: raw.status,
        confidence,
    }
}

/// Tầng 2: Identity Normalization cho Memory (RAM)
pub fn normalize_memory(raw: &RawComponent, source: CollectionSource) -> NormalizedComponent {
    let mut attrs = BTreeMap::new();
    let mut confidence = match source {
        CollectionSource::WindowsWmi => Confidence::High,
        CollectionSource::Sysinfo => Confidence::Medium,
        CollectionSource::Mock => Confidence::High,
    };

    // 1. Capacity in Bytes
    if let Some(cap) = raw
        .attributes
        .get("capacity_bytes")
        .and_then(|v| v.as_u64())
    {
        attrs.insert("capacity_bytes".to_string(), cap.to_string());
    } else {
        confidence = Confidence::Low;
    }

    // 2. Bank / Slot Label
    let bank_label = raw
        .attributes
        .get("bank_label")
        .and_then(|v| v.as_str())
        .map(normalize_transport_string)
        .filter(|s| !is_oem_junk_value(s))
        .unwrap_or_else(|| raw.local_id.clone());
    attrs.insert("bank_label".to_string(), bank_label.clone());

    // 3. Manufacturer
    if let Some(mfg) = raw.attributes.get("manufacturer").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(mfg);
        if !is_oem_junk_value(&norm) {
            attrs.insert("manufacturer".to_string(), norm);
        }
    }

    // 4. Part Number
    if let Some(pn) = raw.attributes.get("part_number").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(pn);
        if !is_oem_junk_value(&norm) {
            attrs.insert("part_number".to_string(), norm);
        }
    }

    // 5. Speed
    if let Some(speed) = raw.attributes.get("speed_mhz").and_then(|v| v.as_u64()) {
        attrs.insert("speed_mhz".to_string(), speed.to_string());
    }

    let cap_str = attrs
        .get("capacity_bytes")
        .cloned()
        .unwrap_or_else(|| "0".to_string());
    let canonical_id = format!("ram:{}:{}", bank_label, cap_str);

    NormalizedComponent {
        component_type: ComponentType::Memory,
        canonical_id,
        attributes: attrs,
        source,
        status: raw.status,
        confidence,
    }
}

/// Tầng 2: Identity Normalization cho Storage (Physical Disks - rv plan1.md #6)
pub fn normalize_storage(raw: &RawComponent, source: CollectionSource) -> NormalizedComponent {
    let mut attrs = BTreeMap::new();
    let mut confidence = match source {
        CollectionSource::WindowsWmi => Confidence::High,
        CollectionSource::Sysinfo => Confidence::Medium,
        CollectionSource::Mock => Confidence::High,
    };

    // 1. Model
    let model = raw
        .attributes
        .get("model")
        .and_then(|v| v.as_str())
        .map(normalize_transport_string)
        .unwrap_or_else(|| "unknown_disk".to_string());
    attrs.insert("model".to_string(), model.clone());

    // 2. Serial Number (rv plan1.md #7: nếu thiếu thì hạ confidence, không crash)
    let serial = raw
        .attributes
        .get("serial")
        .and_then(|v| v.as_str())
        .map(normalize_transport_string)
        .filter(|s| !is_oem_junk_value(s));

    let canonical_serial_part = if let Some(s) = serial {
        attrs.insert("serial".to_string(), s.clone());
        s
    } else {
        // Serial không khả dụng (vd: trong VM hoặc đĩa ảo)
        confidence = Confidence::Medium;
        "noserial".to_string()
    };

    // 3. Size in Bytes
    let size_str = if let Some(sz) = raw.attributes.get("size_bytes").and_then(|v| v.as_u64()) {
        attrs.insert("size_bytes".to_string(), sz.to_string());
        sz.to_string()
    } else {
        "0".to_string()
    };

    // 4. Interface / Bus Type
    if let Some(iface) = raw.attributes.get("interface").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(iface);
        if !is_oem_junk_value(&norm) {
            attrs.insert("interface".to_string(), norm);
        }
    }

    // rv plan1.md #2: canonical_id không dựa vào index của OS (disk-0)
    let canonical_id = format!("disk:{}:{}:{}", model, canonical_serial_part, size_str);

    NormalizedComponent {
        component_type: ComponentType::Storage,
        canonical_id,
        attributes: attrs,
        source,
        status: raw.status,
        confidence,
    }
}

/// Tầng 2: Identity Normalization cho Motherboard
pub fn normalize_motherboard(raw: &RawComponent, source: CollectionSource) -> NormalizedComponent {
    let mut attrs = BTreeMap::new();
    let mut confidence = match source {
        CollectionSource::WindowsWmi => Confidence::High,
        CollectionSource::Sysinfo => Confidence::Medium,
        CollectionSource::Mock => Confidence::High,
    };

    // 1. Manufacturer
    let mfg = raw
        .attributes
        .get("manufacturer")
        .and_then(|v| v.as_str())
        .map(normalize_transport_string)
        .unwrap_or_else(|| "unknown".to_string());
    attrs.insert("manufacturer".to_string(), mfg.clone());

    // 2. Product Name
    let prod = raw
        .attributes
        .get("product")
        .and_then(|v| v.as_str())
        .map(normalize_transport_string)
        .unwrap_or_else(|| "unknown".to_string());
    attrs.insert("product".to_string(), prod.clone());

    // 3. Serial Number
    if let Some(sn) = raw.attributes.get("serial").and_then(|v| v.as_str()) {
        let norm = normalize_transport_string(sn);
        if !is_oem_junk_value(&norm) {
            attrs.insert("serial".to_string(), norm);
        } else {
            confidence = Confidence::Medium;
        }
    } else {
        confidence = Confidence::Medium;
    }

    let canonical_id = format!("board:{}:{}", mfg, prod);

    NormalizedComponent {
        component_type: ComponentType::Motherboard,
        canonical_id,
        attributes: attrs,
        source,
        status: raw.status,
        confidence,
    }
}

/// Điều phối chuẩn hóa linh kiện theo loại
pub fn normalize_component(raw: &RawComponent, source: CollectionSource) -> NormalizedComponent {
    match raw.component_type {
        ComponentType::Cpu => normalize_cpu(raw, source),
        ComponentType::Memory => normalize_memory(raw, source),
        ComponentType::Storage => normalize_storage(raw, source),
        ComponentType::Motherboard => normalize_motherboard(raw, source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::models::{ComponentStatus, RawValue};

    #[test]
    fn test_transport_normalization() {
        let dirty = "  Samsung   SSD  980  PRO \r\n ";
        let clean = normalize_transport_string(dirty);
        assert_eq!(clean, "samsung ssd 980 pro");
    }

    #[test]
    fn test_oem_junk_filtering() {
        assert!(is_oem_junk_value("To be filled by O.E.M."));
        assert!(is_oem_junk_value("Default String"));
        assert!(is_oem_junk_value("None"));
        assert!(is_oem_junk_value("   "));
        assert!(!is_oem_junk_value("ASUS ROG STRIX"));
    }

    #[test]
    fn test_storage_normalization_without_os_index() {
        let mut raw_attrs = BTreeMap::new();
        raw_attrs.insert(
            "model".to_string(),
            RawValue::String("SAMSUNG 980 PRO".to_string()),
        );
        raw_attrs.insert(
            "serial".to_string(),
            RawValue::String("S5P2NF0R123456 ".to_string()),
        );
        raw_attrs.insert("size_bytes".to_string(), RawValue::Integer(1000204886016));

        let raw = RawComponent {
            component_type: ComponentType::Storage,
            local_id: "disk-3".to_string(), // Giả sử OS gán index 3
            attributes: raw_attrs,
            source: CollectionSource::WindowsWmi,
            status: ComponentStatus::Complete,
        };

        let norm = normalize_storage(&raw, CollectionSource::WindowsWmi);
        // Canonical ID không được chứa "disk-3"
        assert_eq!(
            norm.canonical_id,
            "disk:samsung 980 pro:s5p2nf0r123456:1000204886016"
        );
        assert_eq!(norm.confidence, Confidence::High);
    }

    #[test]
    fn test_missing_serial_degrades_confidence_without_crash() {
        let mut raw_attrs = BTreeMap::new();
        raw_attrs.insert(
            "model".to_string(),
            RawValue::String("Virtual Disk".to_string()),
        );
        raw_attrs.insert("serial".to_string(), RawValue::String("None".to_string())); // Junk OEM

        let raw = RawComponent {
            component_type: ComponentType::Storage,
            local_id: "disk-0".to_string(),
            attributes: raw_attrs,
            source: CollectionSource::WindowsWmi,
            status: ComponentStatus::Complete,
        };

        let norm = normalize_storage(&raw, CollectionSource::WindowsWmi);
        // Confidence phải bị hạ xuống Medium
        assert_eq!(norm.confidence, Confidence::Medium);
        assert!(!norm.attributes.contains_key("serial"));
    }
}
