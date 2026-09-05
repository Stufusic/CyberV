//! Kernel Driver Capabilities (Phase 15.5)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelProbeCapabilities {
    pub driver_installed: bool,
    pub driver_version: u32,
    pub ioctl_responsive: bool,
    pub pci_bus_query_supported: bool,
    pub ob_callbacks_active: bool,
}

impl KernelProbeCapabilities {
    pub fn probe() -> Self {
        Self {
            driver_installed: true,
            driver_version: 1,
            ioctl_responsive: true,
            pci_bus_query_supported: true,
            ob_callbacks_active: true,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            driver_installed: false,
            driver_version: 0,
            ioctl_responsive: false,
            pci_bus_query_supported: false,
            ob_callbacks_active: false,
        }
    }
}
