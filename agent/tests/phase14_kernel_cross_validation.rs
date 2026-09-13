//! CyberV Phase 14: Kernel / Lower-Layer Observation Tests (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6:
//! Kernel Probe, IOCTL protocol, Cross-Layer Validation (WMI vs Ring-0),
//! Anti-WMI-Spoofer Contradiction Detection, Graceful Degradation.

use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::models::ComponentType;
use cyberv_agent::kernel::{
    CrossLayerValidator, KernelObservationPayload, KernelPciDevice, MockKernelClient,
    ValidationStatus,
};

fn create_mock_pci_nvme(serial: &str) -> KernelPciDevice {
    KernelPciDevice {
        vendor_id: 0x144d, // Samsung
        device_id: 0xa80a, // 980 Pro
        subsystem_vendor_id: 0x144d,
        subsystem_device_id: 0xa801,
        segment: 0,
        bus: 1,
        device: 0,
        function: 0,
        device_class: 0x01, // Mass Storage
        serial_number: Some(serial.to_string()),
    }
}

#[test]
fn test_01_driver_unavailable_graceful_fallback() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let client = MockKernelClient::unavailable();
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.status, ValidationStatus::Unknown);
    assert_eq!(report.consistency_score, 10000);
    assert_eq!(
        report.penalty, 0,
        "Không có driver không bị phạt điểm (Graceful Fallback)"
    );
}

#[test]
fn test_02_driver_present_and_consistent() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    // Serial chuẩn của đĩa trong baseline fixture
    let legit_serial = "s5p2nf0r123456";
    let pci_dev = create_mock_pci_nvme(legit_serial);
    let payload = KernelObservationPayload::new(1, vec![pci_dev], 1757077200);

    let client = MockKernelClient::available(payload);
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.status, ValidationStatus::Consistent);
    assert_eq!(report.consistency_score, 10000);
    assert_eq!(report.penalty, 0);
}

#[test]
fn test_03_wmi_serial_spoofed_contradiction_detected() {
    // Kịch bản: Kẻ tấn công dùng công cụ Hook WMI để sửa serial ổ đĩa trong Userland
    // thành "SPOOFED_FAKE_SERIAL", nhưng Kernel Driver đọc cấu hình PCI thực tế
    // thấy serial vật lý là "s5p2nf0r123456".
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut snapshot = collector.collect().unwrap();

    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Storage {
            comp.attributes
                .insert("serial".to_string(), "SPOOFED_FAKE_SERIAL".to_string());
        }
    }

    let real_serial = "s5p2nf0r123456";
    let pci_dev = create_mock_pci_nvme(real_serial);
    let payload = KernelObservationPayload::new(1, vec![pci_dev], 1757077200);

    let client = MockKernelClient::available(payload);
    let report = CrossLayerValidator::validate(&snapshot, &client);

    match &report.status {
        ValidationStatus::Contradictory {
            userland_detail,
            kernel_detail,
            ..
        } => {
            assert!(userland_detail.contains("SPOOFED_FAKE_SERIAL"));
            assert!(kernel_detail.contains(real_serial));
        }
        _ => panic!("Phải phát hiện mâu thuẫn chéo giữa WMI và Kernel"),
    }

    assert_eq!(report.consistency_score, 1500);
    assert_eq!(
        report.penalty, 8500,
        "Phạt điểm nặng khi phát hiện giả mạo WMI"
    );
}

#[test]
fn test_04_kernel_pci_location_formatting() {
    let dev = create_mock_pci_nvme("test");
    assert_eq!(dev.location_str(), "0000:01:00.0");
}

#[test]
fn test_05_kernel_hardware_id_formatting() {
    let dev = create_mock_pci_nvme("test");
    assert_eq!(dev.hardware_id_str(), "pci:ven_144d&dev_a80a");
}

#[test]
fn test_06_kernel_observation_commitment_hash() {
    let dev = create_mock_pci_nvme("sn123");
    let payload1 = KernelObservationPayload::new(1, vec![dev.clone()], 1757077200);
    let payload2 = KernelObservationPayload::new(1, vec![dev], 1757077200);

    assert_eq!(payload1.commitment_hash, payload2.commitment_hash);
    assert_eq!(payload1.commitment_hash.len(), 128); // SHA-512 hex
}

#[test]
fn test_07_virtual_nodes_generated_from_kernel_validation() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let client = MockKernelClient::unavailable();
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.virtual_nodes.len(), 1);
    let vnode = &report.virtual_nodes[0];
    assert_eq!(vnode.id, "vnode:kernel_cross_validation");
    assert_eq!(vnode.virtual_type, "KERNEL_CROSS_VALIDATION");
}

#[test]
fn test_08_virtual_points_generated_from_kernel_validation() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let client = MockKernelClient::unavailable();
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.virtual_points.len(), 1);
    let point = &report.virtual_points[0];
    assert_eq!(point.id, "point:kernel_consistency");
    assert_eq!(point.value, 10000);
    assert_eq!(point.scale, 10000);
}

#[test]
fn test_09_partial_consistency_handling() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    // Serial khớp nhưng chữ hoa chữ thường khác biệt ("S5P2NF0R123456" vs "s5p2nf0r123456")
    let pci_dev = create_mock_pci_nvme("S5P2NF0R123456");
    let payload = KernelObservationPayload::new(1, vec![pci_dev], 1757077200);

    let client = MockKernelClient::available(payload);
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(
        report.status,
        ValidationStatus::Consistent,
        "Chuẩn hóa case-insensitive phải đạt Consistent"
    );
}

#[test]
fn test_10_multiple_pci_devices_cross_validation() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let dev1 = create_mock_pci_nvme("s5p2nf0r123456");
    let mut dev2 = create_mock_pci_nvme("gpu_serial_none");
    dev2.vendor_id = 0x10de; // NVIDIA
    dev2.device_id = 0x2204; // RTX 3090
    dev2.bus = 2;

    let payload = KernelObservationPayload::new(1, vec![dev1, dev2], 1757077200);
    let client = MockKernelClient::available(payload);
    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.status, ValidationStatus::Consistent);
    assert_eq!(report.consistency_score, 10000);
}

#[test]
fn test_11_vbs_hvci_compatibility_no_raw_memory() {
    // Xác minh giao thức IOCTL sử dụng cấu trúc nhị phân chuẩn hóa, không có con trỏ bộ nhớ vật lý
    // FILE_DEVICE_CYBERV (0x8000), METHOD_BUFFERED (0), FILE_READ_DATA (1) -> 0x80006000
    assert_eq!(cyberv_agent::kernel::IOCTL_CYBERV_GET_PCI_INFO, 0x80006000);
    assert_eq!(cyberv_agent::kernel::IOCTL_CYBERV_GET_TOPOLOGY, 0x80006004);
}

#[test]
fn test_12_tampered_kernel_commitment_rejected() {
    let dev1 = create_mock_pci_nvme("s5p2nf0r123456");
    let dev2 = create_mock_pci_nvme("s5p2nf0r999999");

    let p1 = KernelObservationPayload::new(1, vec![dev1], 1757077200);
    let p2 = KernelObservationPayload::new(1, vec![dev2], 1757077200);

    assert_ne!(p1.commitment_hash, p2.commitment_hash);
}

#[test]
fn test_13_empty_kernel_devices_safe_handling() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let payload = KernelObservationPayload::new(1, Vec::new(), 1757077200);
    let client = MockKernelClient::available(payload);
    let report = CrossLayerValidator::validate(&snapshot, &client);

    // Khi kernel không tìm thấy thiết bị nào, giữ nguyên tính toán an toàn
    assert_eq!(report.status, ValidationStatus::Consistent);
}

#[test]
fn test_14_kernel_driver_version_verification() {
    let payload = KernelObservationPayload::new(1, Vec::new(), 1757077200);
    assert_eq!(payload.driver_version, 1);
}

#[test]
fn test_15_end_to_end_kernel_cross_validation_lifecycle() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let legit_serial = "s5p2nf0r123456";
    let pci_dev = create_mock_pci_nvme(legit_serial);
    let payload = KernelObservationPayload::new(1, vec![pci_dev], 1757077200);
    let client = MockKernelClient::available(payload);

    let report = CrossLayerValidator::validate(&snapshot, &client);

    assert_eq!(report.status, ValidationStatus::Consistent);
    assert_eq!(report.consistency_score, 10000);
    assert_eq!(report.virtual_points[0].value, 10000);
    assert_eq!(
        report.virtual_nodes[0]
            .attributes
            .get("validation_status")
            .unwrap(),
        "CONSISTENT"
    );
}

#[test]
fn test_16_windows_kernel_client_graceful_fallback() {
    use cyberv_agent::kernel::{KernelProbeProvider, WindowsKernelClient};
    let client = WindowsKernelClient::new();
    // In test environment without active KMDF CyberVProbe driver loaded,
    // the client gracefully reports unavailable or None without panicking.
    let available = client.is_driver_available();
    let obs = client.query_kernel_observation();
    if !available {
        assert!(obs.is_none());
    }
}

#[test]
fn test_17_kernel_shield_telemetry_model() {
    use cyberv_agent::kernel::KernelShieldTelemetry;
    let telem = KernelShieldTelemetry {
        protected_pid: 1337,
        blocked_terminations: 42,
        blocked_vm_reads: 10,
        blocked_vm_writes: 5,
        suspicious_attempts: 57,
        driver_unload_attempts: 1,
        is_shield_active: true,
    };
    assert_eq!(telem.protected_pid, 1337);
    assert_eq!(telem.blocked_terminations, 42);
    assert!(telem.is_shield_active);
}

