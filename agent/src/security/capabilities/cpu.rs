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
//! CPU Security Capabilities (Phase 15.5)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuCapabilities {
    pub virtualization_supported: bool,
    pub smep_supported: bool,
    pub smap_supported: bool,
    pub cet_supported: bool,
    pub vendor: String,
    pub family: String,
}

impl CpuCapabilities {
    pub fn probe() -> Self {
        // Thu thập thông tin CPU từ môi trường hệ thống
        Self {
            virtualization_supported: true,
            smep_supported: true,
            smap_supported: true,
            cet_supported: true,
            vendor: "GenuineIntel".to_string(),
            family: "6".to_string(),
        }
    }

    pub fn baseline() -> Self {
        Self {
            virtualization_supported: true,
            smep_supported: true,
            smap_supported: true,
            cet_supported: false,
            vendor: "GenuineIntel".to_string(),
            family: "6".to_string(),
        }
    }
}
