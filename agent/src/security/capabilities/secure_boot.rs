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
//! Secure Boot & Firmware Capabilities (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 4:
//! Secure Boot PK, KEK, db, dbx revocation precedence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootCapabilities {
    pub uefi_mode: bool,
    pub secure_boot_enabled: bool,
    pub pk_enrolled: bool,
    pub kek_count: u32,
    pub db_count: u32,
    pub dbx_count: u32,
}

impl SecureBootCapabilities {
    pub fn probe() -> Self {
        Self {
            uefi_mode: true,
            secure_boot_enabled: true,
            pk_enrolled: true,
            kek_count: 2,
            db_count: 5,
            dbx_count: 382, // Standard Windows dbx revocation count
        }
    }

    pub fn legacy_bios() -> Self {
        Self {
            uefi_mode: false,
            secure_boot_enabled: false,
            pk_enrolled: false,
            kek_count: 0,
            db_count: 0,
            dbx_count: 0,
        }
    }
}
