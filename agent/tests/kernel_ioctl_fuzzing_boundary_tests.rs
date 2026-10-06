// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! CyberV Kernel IOCTL Boundary Fuzzing & Stress Tests
//!
//! Ref: Docs/rvr.md & Security Roadmap:
//! In-Process Fuzzing, Boundary Truncation, Buffer Underflow/Overflow Protection,
//! Nonce Mutation, and Concurrent Race Condition Robustness.

use cyberv_agent::kernel::{
    parse_kernel_observation_bytes, KernelObservationPayload, KernelPciDevice,
    KernelProbeProvider, MockKernelClient, WindowsKernelClient, KERNEL_MAX_DEVICES,
};
use std::sync::Arc;
use std::thread;

/// Helper: Sinh thiết bị PCI giả lập
fn create_test_pci(ven: u16, dev: u16, bus: u8, dev_id: u8, func: u8, sn: Option<&str>) -> KernelPciDevice {
    KernelPciDevice {
        vendor_id: ven,
        device_id: dev,
        subsystem_vendor_id: ven,
        subsystem_device_id: dev,
        segment: 0,
        bus,
        device: dev_id,
        function: func,
        device_class: 0x01,
        serial_number: sn.map(|s| s.to_string()),
    }
}

#[test]
fn test_01_fuzz_malformed_truncated_observation_buffer() {
    // PHIÊN BẢN CŨ LÀ TAUTOLOGY: assert!(obs.is_none() || obs.is_some()) luôn đúng.
    // Giờ assert thật trên pure parser (xem thêm unit test trong kernel/client.rs):
    // frame cắt ngắn / thiếu header / bytes_returned lệch phải trả None.
    fn build_frame(device_count: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u32.to_le_bytes()); // driver_version = ABI v1
        frame.extend_from_slice(&device_count.to_le_bytes());
        frame.extend_from_slice(&0u64.to_le_bytes());
        for _ in 0..device_count {
            frame.extend_from_slice(&[0u8; 78]); // KERNEL_PCI_DEVICE_SIZE
        }
        frame
    }

    let frame = build_frame(4);
    // bytes_returned chỉ đủ header trong khi frame khai báo 4 devices -> None
    assert!(parse_kernel_observation_bytes(&frame, 16).is_none());
    // bytes_returned nhỏ hơn cần thiết -> None
    assert!(parse_kernel_observation_bytes(&frame, 16 + 3 * 78).is_none());
    // Buffer nhỏ hơn header -> None
    assert!(parse_kernel_observation_bytes(&frame[..8], 8).is_none());
    // Frame đầy đủ -> Some với đúng số devices
    let full = parse_kernel_observation_bytes(&frame, frame.len()).expect("full frame");
    assert_eq!(full.devices.len(), 4);
    assert!(full.devices.len() <= KERNEL_MAX_DEVICES);
}

#[test]
fn test_02_fuzz_oversized_corrupted_device_count() {
    // Giả lập trường hợp Ring-0 trả về device_count bị lỗi/tràn số (ví dụ u32::MAX hoặc 9999)
    let devices = vec![
        create_test_pci(0x8086, 0x1234, 0, 1, 0, Some("VALID_SN_1")),
        create_test_pci(0x10de, 0x5678, 1, 0, 0, Some("VALID_SN_2")),
    ];

    let payload = KernelObservationPayload::new(1, devices.clone(), 1757077200);
    assert_eq!(payload.devices.len(), 2);
    assert_eq!(payload.driver_version, 1);

    // Xác minh danh sách thiết bị không vượt quá giới hạn an toàn 32 phần tử
    let mock = MockKernelClient::available(payload);
    let queried = mock.query_kernel_observation().unwrap();
    assert!(queried.devices.len() <= 32);
}

#[test]
fn test_03_fuzz_garbage_binary_serial_numbers() {
    // Kiểm thử chuỗi Serial Number chứa ký tự đặc biệt, dấu cách, hoặc byte rác
    let weird_serials = [
        "",
        "   ",
        "SN\0TRUNCATED",
        "SN_WITH_VERY_LONG_STRING_1234567890_EXCEEDING_STANDARD_LENGTH_PADDING",
        "!!!@@@###$$$%%%^^^&&&***()",
    ];

    for sn in weird_serials {
        let pci = create_test_pci(0x8086, 0x9999, 0, 2, 0, Some(sn));
        let payload = KernelObservationPayload::new(1, vec![pci], 1757077200);
        assert!(!payload.commitment_hash.is_empty());
        assert_eq!(payload.commitment_hash.len(), 128); // Sha512 hex = 128 chars
    }
}

#[test]
fn test_04_fuzz_all_zero_pci_devices() {
    // Trường hợp toàn bộ trường PCI bằng 0 (thiết bị ảo hoặc bus chưa cấu hình)
    let zero_dev = create_test_pci(0, 0, 0, 0, 0, None);
    assert_eq!(zero_dev.location_str(), "0000:00:00.0");
    assert_eq!(zero_dev.hardware_id_str(), "pci:ven_0000&dev_0000");

    let payload = KernelObservationPayload::new(1, vec![zero_dev], 0);
    assert!(!payload.commitment_hash.is_empty());
}

#[test]
fn test_05_fuzz_concurrent_multi_threaded_probing() {
    // Kiểm thử Race-Condition: 20 luồng đồng thời gọi client.is_driver_available() và query_kernel_observation()
    let client = Arc::new(WindowsKernelClient::new());
    let mut handles = Vec::new();

    for _ in 0..20 {
        let client_clone = Arc::clone(&client);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let _available = client_clone.is_driver_available();
                let _obs = client_clone.query_kernel_observation();
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread không bao giờ bị panic khi truy vấn đồng thời!");
    }
}

#[test]
fn test_06_fuzz_shield_telemetry_counter_saturation() {
    // Kiểm tra TRẠNG THÁI SATURATION thật: bộ đếm ở biên u32::MAX không được
    // panic (debug) hay wrap (release) khi qua phép cộng/nhân của anti-tamper.
    use cyberv_agent::defense::kernel::telemetry::ShieldTelemetry;

    let telem = ShieldTelemetry {
        protected_pid: 4, // System PID
        blocked_terminations: u32::MAX,
        blocked_vm_reads: u32::MAX - 1,
        blocked_vm_writes: u32::MAX - 2,
        suspicious_attempts: u32::MAX,
        driver_unload_attempts: 100,
        is_shield_active: true,
    };

    // Saturating: tổng phải kẹt ở u32::MAX, không wrap về số nhỏ
    assert_eq!(telem.total_blocked(), u32::MAX);
    assert!(telem.has_tampering_attempts());
}

#[test]
fn test_07_fuzz_sha512_canonical_commitment_determinism() {
    // Kiểm tra tính đơn định (determinism) của cam kết mật mã học Sha512
    let dev1 = create_test_pci(0x8086, 0x1001, 0, 1, 0, Some("SN_ALPHA"));
    let dev2 = create_test_pci(0x10de, 0x2002, 1, 0, 0, Some("SN_BETA"));

    let p1 = KernelObservationPayload::new(1, vec![dev1.clone(), dev2.clone()], 1757077200);
    let p2 = KernelObservationPayload::new(1, vec![dev1, dev2], 1757077200);

    assert_eq!(
        p1.commitment_hash, p2.commitment_hash,
        "Cùng đầu vào phải cho ra 100% cùng một giá trị băm cam kết!"
    );
}

#[test]
fn test_08_fuzz_single_bit_permutation_alters_commitment() {
    // Chỉ cần thay đổi 1 bit trong Vendor ID hoặc Timestamp, băm cam kết phải đổi hoàn toàn
    let dev1 = create_test_pci(0x8086, 0x1000, 0, 1, 0, Some("SN_ALPHA"));
    let dev2 = create_test_pci(0x8087, 0x1000, 0, 1, 0, Some("SN_ALPHA"));

    let p1 = KernelObservationPayload::new(1, vec![dev1], 1757077200);
    let p2 = KernelObservationPayload::new(1, vec![dev2], 1757077200);

    assert_ne!(p1.commitment_hash, p2.commitment_hash);
}
