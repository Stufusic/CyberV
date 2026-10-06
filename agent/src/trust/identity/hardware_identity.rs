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
//! Hardware-backed TPM Identity (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 5:
//! "TPM-backed key: hardware protected, non-exportable."

use crate::trust::tpm::{TpmError, TpmIdentityKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIdentity {
    pub key: TpmIdentityKey,
}

impl HardwareIdentity {
    pub fn new(key: TpmIdentityKey) -> Self {
        Self { key }
    }

    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex.clone()
    }

    pub fn sign(&self, data: &[u8]) -> Result<String, TpmError> {
        self.key.sign(data)
    }

    pub fn assert_protected(&self) -> Result<(), TpmError> {
        self.key.assert_hardware_protection()
    }
}
