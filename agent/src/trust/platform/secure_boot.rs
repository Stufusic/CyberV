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
//! Secure Boot Verification Engine (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 6 & 7:
//! "SecureBootPolicy-v1 (PCR 7). Secure Boot status."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureBootStatus {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureBootEvidence {
    pub status: SecureBootStatus,
    pub pcr_7_digest: Option<String>,
    pub is_compliant: bool,
}

impl SecureBootEvidence {
    pub fn new_enabled(pcr_7: impl Into<String>) -> Self {
        Self {
            status: SecureBootStatus::Enabled,
            pcr_7_digest: Some(pcr_7.into()),
            is_compliant: true,
        }
    }

    pub fn new_disabled() -> Self {
        Self {
            status: SecureBootStatus::Disabled,
            pcr_7_digest: None,
            is_compliant: false,
        }
    }

    pub fn new_unknown() -> Self {
        Self {
            status: SecureBootStatus::Unknown,
            pcr_7_digest: None,
            is_compliant: false,
        }
    }
}
