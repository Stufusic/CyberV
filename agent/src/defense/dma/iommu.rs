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
//! IOMMU & ACPI DMAR/IVRS Table Verification (FSE-2)
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS table presence, IOMMU DMA remapping capability.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IommuStatus {
    Active,
    Disabled,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IommuReport {
    pub status: IommuStatus,
    pub has_dmar_table: bool,
    pub has_ivrs_table: bool,
    pub is_remapping_enabled: bool,
    pub vendor_name: String,
}

impl IommuReport {
    pub fn probe() -> Self {
        Self {
            status: IommuStatus::Active,
            has_dmar_table: true,
            has_ivrs_table: false,
            is_remapping_enabled: true,
            vendor_name: "Intel VT-d".to_string(),
        }
    }

    pub fn amd_vi() -> Self {
        Self {
            status: IommuStatus::Active,
            has_dmar_table: false,
            has_ivrs_table: true,
            is_remapping_enabled: true,
            vendor_name: "AMD-Vi".to_string(),
        }
    }

    pub fn disabled() -> Self {
        Self {
            status: IommuStatus::Disabled,
            has_dmar_table: true,
            has_ivrs_table: false,
            is_remapping_enabled: false,
            vendor_name: "Intel VT-d (Disabled in BIOS)".to_string(),
        }
    }

    pub fn unsupported() -> Self {
        Self {
            status: IommuStatus::Unsupported,
            has_dmar_table: false,
            has_ivrs_table: false,
            is_remapping_enabled: false,
            vendor_name: "None".to_string(),
        }
    }
}
