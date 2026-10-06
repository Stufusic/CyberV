// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
