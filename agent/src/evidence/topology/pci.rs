//! PCIe & Bus Topology Representation (HCE-2)
//!
//! Ref: Docs/rv9.md HCE-2:
//! "PCIe Root Complex -> PCIe Bridge -> Bus/Device/Function -> NVMe Controller -> Disk.
//! Topology observed by current execution environment."

use serde::{Deserialize, Serialize};

/// Tọa độ bus PCIe chuẩn BDF (Bus / Device / Function)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PciLocation {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciLocation {
    pub fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    pub fn to_bdf_string(&self) -> String {
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.segment, self.bus, self.device, self.function
        )
    }
}

/// Nút đại diện cho một cổng giao tiếp hoặc bộ định tuyến Bus trên bo mạch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusNode {
    pub id: String,
    pub bus_type: String, // "PCIe_Root", "PCIe_Bridge", "NVMe_Host", "SATA_AHCI", "Memory_Bus"
    pub location: Option<PciLocation>,
    pub children: Vec<String>,
    pub commitment_hash: String, // SHA-512 cam kết của nút này
}
