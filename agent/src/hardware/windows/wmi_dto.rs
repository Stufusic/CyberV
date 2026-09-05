//! Strongly-Typed WMI DTOs
//!
//! Khai báo các struct tương ứng với lớp WMI trên Windows (root\cimv2).
//! Ref: rv plan1.md #13 và Microsoft Learn documentation.

use serde::Deserialize;

/// Win32_Processor: Đại diện cho vi xử lý hệ thống
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_Processor")]
#[serde(rename_all = "PascalCase")]
pub struct Win32Processor {
    pub manufacturer: Option<String>,
    pub name: Option<String>,
    pub number_of_logical_processors: Option<u32>,
    pub family: Option<u16>,
    pub processor_id: Option<String>,
}

/// Win32_PhysicalMemory: Đại diện cho thanh RAM vật lý
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_PhysicalMemory")]
#[serde(rename_all = "PascalCase")]
pub struct Win32PhysicalMemory {
    pub capacity: Option<u64>,
    pub manufacturer: Option<String>,
    pub part_number: Option<String>,
    pub configured_clock_speed: Option<u32>,
    pub bank_label: Option<String>,
    pub tag: Option<String>,
}

/// Win32_DiskDrive: Đại diện cho ổ đĩa lưu trữ vật lý (rv plan1.md #6: physical disk, not drive letter)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
pub struct Win32DiskDrive {
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub size: Option<u64>,
    pub interface_type: Option<String>,
    pub index: Option<u32>,
    pub device_id: Option<String>,
}

/// Win32_BaseBoard: Đại diện cho bo mạch chủ máy tính
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "Win32_BaseBoard")]
#[serde(rename_all = "PascalCase")]
pub struct Win32BaseBoard {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub tag: Option<String>,
}
