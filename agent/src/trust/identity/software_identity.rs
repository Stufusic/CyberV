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
//! Software-based Identity Fallback (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 4 & 5:
//! "Consumer mode: TPM unavailable -> software fallback -> lower assurance."

use crate::identity::DeviceIdentityKey;

#[derive(Clone)]
pub struct SoftwareIdentity {
    pub key: DeviceIdentityKey,
}

impl SoftwareIdentity {
    pub fn new(key: DeviceIdentityKey) -> Self {
        Self { key }
    }

    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let sig = self.key.sign(data);
        sig.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
