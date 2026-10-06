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
