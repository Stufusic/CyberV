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
//! Merkle-DAG Node Representation (HCE-3)
//!
//! Ref: Docs/rv9.md HCE-3:
//! "Merkle structure with 64-byte SHA-512 hashes and Subtree Commitments."

use sha2::{Digest, Sha512};

pub const DOMAIN_MERKLE_LEAF: &[u8] = b"CYBERV/DBS/MERKLE_LEAF/v1\0";
pub const DOMAIN_MERKLE_INTERNAL: &[u8] = b"CYBERV/DBS/MERKLE_INTERNAL/v1\0";

/// Nút trong cây Merkle-DAG
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleNode {
    pub hash: [u8; 64], // SHA-512
    pub label: String,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    /// Tạo nút lá từ nhãn và dữ liệu byte bất kỳ
    pub fn new_leaf(label: impl Into<String>, data: &[u8]) -> Self {
        let label_str = label.into();
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_MERKLE_LEAF);
        hasher.update((label_str.len() as u32).to_be_bytes());
        hasher.update(label_str.as_bytes());
        hasher.update((data.len() as u32).to_be_bytes());
        hasher.update(data);

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hasher.finalize());

        Self {
            hash,
            label: label_str,
            left: None,
            right: None,
        }
    }

    /// Tạo nút nội bộ (Internal Branch) từ hai nút con
    pub fn new_internal(label: impl Into<String>, left: MerkleNode, right: MerkleNode) -> Self {
        let label_str = label.into();
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_MERKLE_INTERNAL);
        hasher.update((label_str.len() as u32).to_be_bytes());
        hasher.update(label_str.as_bytes());
        hasher.update(left.hash);
        hasher.update(right.hash);

        let mut hash = [0u8; 64];
        hash.copy_from_slice(&hasher.finalize());

        Self {
            hash,
            label: label_str,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    /// Trả về chuỗi hex 128 ký tự của hash SHA-512
    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
