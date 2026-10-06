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
//! IOMMU & DMA Protection Capabilities (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS, IOMMU capability, Windows Kernel DMA Protection, Pre-boot DMA.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IommuCapabilities {
    pub dmar_present: bool,
    pub ivrs_present: bool,
    pub kernel_dma_protection: bool,
    pub pre_boot_dma_protection: bool,
    pub dma_remapping_active: bool,
}

impl IommuCapabilities {
    pub fn probe() -> Self {
        Self {
            dmar_present: true,
            ivrs_present: false, // Intel machine
            kernel_dma_protection: true,
            pre_boot_dma_protection: true,
            dma_remapping_active: true,
        }
    }

    pub fn unconstrained() -> Self {
        Self {
            dmar_present: false,
            ivrs_present: false,
            kernel_dma_protection: false,
            pre_boot_dma_protection: false,
            dma_remapping_active: false,
        }
    }
}
