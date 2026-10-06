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
//! Kernel ABI Synchronization Tests (Phase 3 - CI Quality)
//!
//! Ref: Docs/PHASE1_2_IMPLEMENTATION_PLAN.md P3:
//! "Test đồng bộ ABI: parse ioctl.h và so khớp CTL_CODE + ABI version với Rust protocol.rs.
//!  Fail CI khi C và Rust lệch nhau."
//!
//! Các CTL_CODE được tính tay theo công thức Win32:
//! `CTL_CODE(DeviceType, Function, Method, Access) =
//!     (DeviceType << 16) | (Access << 14) | (Function << 2) | Method`
//! với METHOD_BUFFERED = 0, FILE_READ_DATA = 0x1, FILE_WRITE_DATA = 0x2.

use cyberv_agent::kernel::protocol::{
    IOCTL_CYBERV_GET_PCI_INFO, IOCTL_CYBERV_GET_SHIELD_TELEMETRY,
    IOCTL_CYBERV_GET_TOPOLOGY, IOCTL_CYBERV_REGISTER_PROTECTED_PID, CYBERV_ABI_MAGIC,
    CYBERV_ABI_VERSION,
};


const IOCTL_H_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../driver/CyberVProbe/ioctl.h");

fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Trích các macro `#define IOCTL_...` và `#define CYBERV_ABI_VERSION` từ ioctl.h
fn parse_ioctl_header(source: &str) -> std::collections::HashMap<String, String> {
    let mut macros = std::collections::HashMap::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with("#define") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // "#define"
        if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
            macros.insert(name.to_string(), value.to_string());
        }
    }
    macros
}

#[test]
fn ioctl_header_exists_and_is_readable() {
    let source = std::fs::read_to_string(IOCTL_H_PATH)
        .expect("Không đọc được driver/CyberVProbe/ioctl.h — kiểm tra layout repo");
    assert!(source.contains("CYBERV_ABI_VERSION"));
}

#[test]
fn ctl_codes_match_between_c_and_rust() {
    let source = std::fs::read_to_string(IOCTL_H_PATH).expect("ioctl.h");
    let macros = parse_ioctl_header(&source);

    // FILE_DEVICE_CYBERV phải là 0x8000 trên cả hai phía
    assert_eq!(
        macros.get("FILE_DEVICE_CYBERV").map(String::as_str),
        Some("0x8000"),
        "FILE_DEVICE_CYBERV trong ioctl.h phải là 0x8000"
    );

    // Tính CTL_CODE theo đúng tham số khai báo trong ioctl.h (đọc tay từng dòng)
    let expected_get_pci_info = ctl_code(0x8000, 0x800, 0, 0x1); // METHOD_BUFFERED, FILE_READ_DATA
    let expected_get_topology = ctl_code(0x8000, 0x801, 0, 0x1);
    let expected_register = ctl_code(0x8000, 0x802, 0, 0x1 | 0x2);
    let expected_telemetry = ctl_code(0x8000, 0x803, 0, 0x1);

    // Guard: nếu ai đó đổi tham số CTL_CODE trong ioctl.h mà không đổi Rust,
    // đoạn assert sau đây buộc phải cập nhật — đây chính là mục đích của test.
    assert!(source.contains("CTL_CODE(FILE_DEVICE_CYBERV, 0x800, METHOD_BUFFERED, FILE_READ_DATA)"));
    assert!(source.contains("CTL_CODE(FILE_DEVICE_CYBERV, 0x801, METHOD_BUFFERED, FILE_READ_DATA)"));
    assert!(source
        .contains("CTL_CODE(FILE_DEVICE_CYBERV, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)"));
    assert!(source.contains("CTL_CODE(FILE_DEVICE_CYBERV, 0x803, METHOD_BUFFERED, FILE_READ_DATA)"));

    assert_eq!(IOCTL_CYBERV_GET_PCI_INFO, expected_get_pci_info);
    assert_eq!(IOCTL_CYBERV_GET_TOPOLOGY, expected_get_topology);
    assert_eq!(IOCTL_CYBERV_REGISTER_PROTECTED_PID, expected_register);
    assert_eq!(IOCTL_CYBERV_GET_SHIELD_TELEMETRY, expected_telemetry);
}

#[test]
fn abi_version_matches_between_c_and_rust() {
    let source = std::fs::read_to_string(IOCTL_H_PATH).expect("ioctl.h");
    let macros = parse_ioctl_header(&source);
    let c_version: u32 = macros
        .get("CYBERV_ABI_VERSION")
        .expect("ioctl.h phải khai báo CYBERV_ABI_VERSION")
        .parse()
        .expect("CYBERV_ABI_VERSION phải là số nguyên");

    assert_eq!(
        c_version, CYBERV_ABI_VERSION,
        "CYBERV_ABI_VERSION lệch giữa ioctl.h và kernel/protocol.rs — cập nhật cả hai phía cùng lúc"
    );
}

#[test]
fn registration_struct_contains_client_abi_version_on_both_sides() {
    let c_header = std::fs::read_to_string(IOCTL_H_PATH).expect("ioctl.h");
    let rust_client = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/kernel/client.rs"
    ))
    .expect("kernel/client.rs");

    assert!(
        c_header.contains("ClientAbiVersion"),
        "ioctl.h thiếu ClientAbiVersion (anti ABI drift field)"
    );
    assert!(
        rust_client.contains("client_abi_version"),
        "client.rs thiếu client_abi_version (anti ABI drift field)"
    );
}

#[test]
fn abi_magic_matches_between_c_and_rust() {
    let source = std::fs::read_to_string(IOCTL_H_PATH).expect("ioctl.h");
    let macros = parse_ioctl_header(&source);
    let c_magic_str = macros
        .get("CYBERV_ABI_MAGIC")
        .expect("ioctl.h phải khai báo CYBERV_ABI_MAGIC");
    let c_magic = u32::from_str_radix(c_magic_str.trim_start_matches("0x"), 16)
        .expect("CYBERV_ABI_MAGIC phải là hex u32");

    assert_eq!(
        c_magic, CYBERV_ABI_MAGIC,
        "CYBERV_ABI_MAGIC lệch giữa ioctl.h và protocol.rs"
    );
}

#[test]
fn abi_header_struct_defined_on_both_sides() {
    let c_header = std::fs::read_to_string(IOCTL_H_PATH).expect("ioctl.h");
    let rust_protocol = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/kernel/protocol.rs"
    ))
    .expect("kernel/protocol.rs");
    let rust_client = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/kernel/client.rs"
    ))
    .expect("kernel/client.rs");

    assert!(c_header.contains("CYBERV_ABI_HEADER"), "ioctl.h thiếu CYBERV_ABI_HEADER");
    assert!(rust_protocol.contains("CybervAbiHeader"), "protocol.rs thiếu CybervAbiHeader");
    assert!(rust_client.contains("RawCybervAbiHeader"), "client.rs thiếu RawCybervAbiHeader");
}

