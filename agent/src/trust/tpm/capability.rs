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
//! TPM 2.0 Capabilities & Status (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! "TPM_PRESENT, TPM_UNAVAILABLE, TPM_DEGRADED.
//! Consumer mode fallback to software."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TpmStatus {
    TpmPresent,
    TpmUnavailable,
    TpmDegraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmCapabilities {
    pub present: bool,
    pub status: TpmStatus,
    pub version: Option<String>,
    pub manufacturer: Option<String>,
    pub supports_key_storage: bool,
    pub supports_attestation: bool,
    pub supports_pcr_quote: bool,
}

impl Default for TpmCapabilities {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl TpmCapabilities {
    pub fn unavailable() -> Self {
        Self {
            present: false,
            status: TpmStatus::TpmUnavailable,
            version: None,
            manufacturer: None,
            supports_key_storage: false,
            supports_attestation: false,
            supports_pcr_quote: false,
        }
    }

    pub fn standard_tpm2(manufacturer: impl Into<String>) -> Self {
        Self {
            present: true,
            status: TpmStatus::TpmPresent,
            version: Some("2.0".to_string()),
            manufacturer: Some(manufacturer.into()),
            supports_key_storage: true,
            supports_attestation: true,
            supports_pcr_quote: true,
        }
    }

    pub fn degraded(manufacturer: impl Into<String>, reason: &str) -> Self {
        let _ = reason;
        Self {
            present: true,
            status: TpmStatus::TpmDegraded,
            version: Some("2.0".to_string()),
            manufacturer: Some(manufacturer.into()),
            supports_key_storage: true,
            supports_attestation: false,
            supports_pcr_quote: false,
        }
    }
}
