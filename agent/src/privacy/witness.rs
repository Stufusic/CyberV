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
//! Private Hardware Witness (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 35:
//! Private Witness: Hardware leaves, Merkle inclusion paths, virtual evidence,
//! constraint metrics, and blinding factor.

use crate::evidence::merkle::proof::MerkleInclusionProof;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareLeafWitness {
    pub label: String,
    pub canonical_id: String,
    pub leaf_hash_hex: String,
    pub proof: MerkleInclusionProof,
}

/// Nhân chứng bằng chứng phần cứng riêng tư (Private Witness)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareWitness {
    pub leaves: Vec<HardwareLeafWitness>,
    pub tpm_active: bool,
    pub kernel_consistent: bool,
    pub cpu_family: String,
    pub total_memory_bytes: u64,
    /// Hệ số làm mờ bí mật (Blinding Factor) bảo đảm Zero-Knowledge
    pub blinding_factor: String,
}

impl HardwareWitness {
    pub fn new(
        leaves: Vec<HardwareLeafWitness>,
        tpm_active: bool,
        kernel_consistent: bool,
        cpu_family: impl Into<String>,
        total_memory_bytes: u64,
        blinding_factor: impl Into<String>,
    ) -> Self {
        Self {
            leaves,
            tpm_active,
            kernel_consistent,
            cpu_family: cpu_family.into(),
            total_memory_bytes,
            blinding_factor: blinding_factor.into(),
        }
    }
}
