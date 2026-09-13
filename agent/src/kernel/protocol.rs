//! Kernel Probe IOCTL Protocol & Data Contracts (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6 Section 26, 27, 28:
//! "Supported Windows driver interface. Minimal attack surface: PCI device identity, location, topology."

use crate::fingerprint::canonical::CanonicalEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_KERNEL_PROBE: &[u8] = b"CYBERV/DBS/KERNEL_PROBE/v1\0";

// Standardized ABI IOCTL Codes (FILE_DEVICE_CYBERV = 0x8000, METHOD_BUFFERED = 0)
// Matches driver/CyberVProbe/ioctl.h exactly
pub const IOCTL_CYBERV_GET_PCI_INFO: u32 = 0x80006000;
pub const IOCTL_CYBERV_GET_TOPOLOGY: u32 = 0x80006004;
pub const IOCTL_CYBERV_REGISTER_PROTECTED_PID: u32 = 0x8000E008;
pub const IOCTL_CYBERV_GET_SHIELD_TELEMETRY: u32 = 0x8000600C;
pub const CYBERV_ABI_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelPciDevice {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub device_class: u8,
    pub serial_number: Option<String>,
}

impl KernelPciDevice {
    pub fn location_str(&self) -> String {
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.segment, self.bus, self.device, self.function
        )
    }

    pub fn hardware_id_str(&self) -> String {
        format!("pci:ven_{:04x}&dev_{:04x}", self.vendor_id, self.device_id)
    }
}

/// Gói tin quan sát phần cứng độc lập từ tầng Kernel Ring-0
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelObservationPayload {
    pub driver_version: u32,
    pub devices: Vec<KernelPciDevice>,
    pub observed_at: u64,
    pub commitment_hash: String,
}

impl KernelObservationPayload {
    pub fn new(driver_version: u32, devices: Vec<KernelPciDevice>, observed_at: u64) -> Self {
        let commitment_hash = compute_kernel_commitment(driver_version, &devices, observed_at);
        Self {
            driver_version,
            devices,
            observed_at,
            commitment_hash,
        }
    }
}

fn compute_kernel_commitment(
    driver_version: u32,
    devices: &[KernelPciDevice],
    observed_at: u64,
) -> String {
    let mut encoder = CanonicalEncoder::new();
    encoder.add_field("driver_version", &driver_version.to_string());
    encoder.add_field("observed_at", &observed_at.to_string());

    for (idx, dev) in devices.iter().enumerate() {
        encoder.add_field(&format!("dev_{}_hwid", idx), &dev.hardware_id_str());
        encoder.add_field(&format!("dev_{}_loc", idx), &dev.location_str());
        if let Some(sn) = &dev.serial_number {
            encoder.add_field(&format!("dev_{}_sn", idx), sn);
        }
    }

    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_KERNEL_PROBE);
    hasher.update(encoder.to_canonical_bytes());
    format!("{:x}", hasher.finalize())
}

/// Telemetry từ Shield Driver (Ring-0)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KernelShieldTelemetry {
    pub protected_pid: u32,
    pub blocked_terminations: u32,
    pub blocked_vm_reads: u32,
    pub blocked_vm_writes: u32,
    pub suspicious_attempts: u32,
    pub driver_unload_attempts: u32,
    pub is_shield_active: bool,
}

