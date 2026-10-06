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
//! TPM Security Capabilities (Phase 15.5)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmCapabilities {
    pub present: bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub sha256_supported: bool,
    pub sha512_supported: bool,
    pub endorsement_key_available: bool,
}

impl TpmCapabilities {
    pub fn probe() -> Self {
        Self {
            present: true,
            version_major: 2,
            version_minor: 0,
            sha256_supported: true,
            sha512_supported: true,
            endorsement_key_available: true,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            present: false,
            version_major: 0,
            version_minor: 0,
            sha256_supported: false,
            sha512_supported: false,
            endorsement_key_available: false,
        }
    }
}
