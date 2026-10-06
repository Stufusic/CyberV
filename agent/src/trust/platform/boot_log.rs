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
//! Measured Boot Configuration Log Processing (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 7:
//! "Measured Boot: UEFI -> Bootloader -> TPM PCR -> Boot Configuration Log."

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_BOOT_LOG: &[u8] = b"CYBERV/DBS/BOOT_LOG/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootLogEntry {
    pub pcr_index: u32,
    pub event_type: String,
    pub digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfigurationLog {
    pub entries: Vec<BootLogEntry>,
    pub composite_digest: String,
}

impl BootConfigurationLog {
    pub fn new(entries: Vec<BootLogEntry>) -> Self {
        let composite_digest = compute_boot_log_digest(&entries);
        Self {
            entries,
            composite_digest,
        }
    }
}

fn compute_boot_log_digest(entries: &[BootLogEntry]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_BOOT_LOG);
    hasher.update((entries.len() as u32).to_be_bytes());

    for entry in entries {
        hasher.update(entry.pcr_index.to_be_bytes());
        hasher.update((entry.event_type.len() as u32).to_be_bytes());
        hasher.update(entry.event_type.as_bytes());
        hasher.update((entry.digest_hex.len() as u32).to_be_bytes());
        hasher.update(entry.digest_hex.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}
