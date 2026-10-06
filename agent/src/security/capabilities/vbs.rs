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
//! Virtualization-Based Security (VBS) Capabilities (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 5:
//! "VBS Enclave APIs yêu cầu Windows 11 build 26100.2314+ hoặc Windows Server 2025+."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VbsCapabilities {
    pub hypervisor_present: bool,
    pub vbs_enabled: bool,
    pub hvci_enabled: bool,
    pub enclave_supported: bool,
    pub build_number: u32,
}

impl VbsCapabilities {
    pub fn probe() -> Self {
        // Mặc định cho môi trường hiện đại Windows 11
        Self {
            hypervisor_present: true,
            vbs_enabled: true,
            hvci_enabled: true,
            enclave_supported: true,
            build_number: 26100,
        }
    }

    pub fn legacy_windows() -> Self {
        Self {
            hypervisor_present: false,
            vbs_enabled: false,
            hvci_enabled: false,
            enclave_supported: false,
            build_number: 19045, // Windows 10 22H2
        }
    }
}
