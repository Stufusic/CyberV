//! Merkle Selective Inclusion Proof (HCE-3)
//!
//! Ref: Docs/rv9.md HCE-3:
//! "Merkle Inclusion Proof / Selective Disclosure:
//! Chứng minh SSD hoặc CPU thuộc Device Graph bằng Merkle path O(log N)
//! mà không cần gửi toàn bộ dữ liệu cấu hình."

use super::node::{MerkleNode, DOMAIN_MERKLE_INTERNAL};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleSiblingDirection {
    /// Sibling nằm ở bên trái nút hiện tại (tức nút hiện tại là con phải)
    SiblingIsLeft,
    /// Sibling nằm ở bên phải nút hiện tại (tức nút hiện tại là con trái)
    SiblingIsRight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub sibling_hash_hex: String,
    pub direction: MerkleSiblingDirection,
    pub parent_label: String,
}

/// Bằng chứng bao hàm chọn lọc Merkle (Inclusion Proof)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    pub leaf_label: String,
    pub leaf_hash_hex: String,
    pub path: Vec<MerkleProofStep>,
    pub root_hash_hex: String,
}

impl MerkleInclusionProof {
    /// Xác minh tính hợp lệ của bằng chứng Merkle (độ phức tạp O(log N))
    pub fn verify(&self) -> bool {
        let mut current_hash = match hex_to_bytes64(&self.leaf_hash_hex) {
            Some(h) => h,
            None => return false,
        };

        for step in &self.path {
            let sibling_hash = match hex_to_bytes64(&step.sibling_hash_hex) {
                Some(h) => h,
                None => return false,
            };

            let mut hasher = Sha512::new();
            hasher.update(DOMAIN_MERKLE_INTERNAL);
            hasher.update((step.parent_label.len() as u32).to_be_bytes());
            hasher.update(step.parent_label.as_bytes());

            match step.direction {
                MerkleSiblingDirection::SiblingIsLeft => {
                    hasher.update(sibling_hash);
                    hasher.update(current_hash);
                }
                MerkleSiblingDirection::SiblingIsRight => {
                    hasher.update(current_hash);
                    hasher.update(sibling_hash);
                }
            }

            let mut next_hash = [0u8; 64];
            next_hash.copy_from_slice(&hasher.finalize());
            current_hash = next_hash;
        }

        let computed_root_hex: String = current_hash.iter().map(|b| format!("{:02x}", b)).collect();
        computed_root_hex == self.root_hash_hex
    }
}

/// Trích xuất bằng chứng bao hàm Merkle từ cây cho một nhãn nút lá cụ thể
pub fn generate_inclusion_proof(
    root: &MerkleNode,
    target_leaf_label: &str,
) -> Option<MerkleInclusionProof> {
    let mut path = Vec::new();
    let mut leaf_hash = None;

    if find_path_dfs(root, target_leaf_label, &mut path, &mut leaf_hash) {
        // DFS đẩy vào path khi hàm đệ quy unwind, do đó thứ tự tự nhiên đã là từ Leaf -> Root
        Some(MerkleInclusionProof {
            leaf_label: target_leaf_label.to_string(),
            leaf_hash_hex: bytes64_to_hex(&leaf_hash?),
            path,
            root_hash_hex: root.hash_hex(),
        })
    } else {
        None
    }
}

fn find_path_dfs(
    node: &MerkleNode,
    target_label: &str,
    path: &mut Vec<MerkleProofStep>,
    leaf_hash: &mut Option<[u8; 64]>,
) -> bool {
    // Nếu là lá
    if node.left.is_none() && node.right.is_none() {
        if node.label == target_label {
            *leaf_hash = Some(node.hash);
            return true;
        }
        return false;
    }

    // Nếu là nút nhánh
    if let (Some(left), Some(right)) = (&node.left, &node.right) {
        // Thử tìm nhánh trái
        if find_path_dfs(left, target_label, path, leaf_hash) {
            path.push(MerkleProofStep {
                sibling_hash_hex: right.hash_hex(),
                direction: MerkleSiblingDirection::SiblingIsRight,
                parent_label: node.label.clone(),
            });
            return true;
        }

        // Thử tìm nhánh phải
        if find_path_dfs(right, target_label, path, leaf_hash) {
            path.push(MerkleProofStep {
                sibling_hash_hex: left.hash_hex(),
                direction: MerkleSiblingDirection::SiblingIsLeft,
                parent_label: node.label.clone(),
            });
            return true;
        }
    }

    false
}

fn hex_to_bytes64(hex_str: &str) -> Option<[u8; 64]> {
    if hex_str.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for i in 0..64 {
        let byte_hex = &hex_str[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_hex, 16).ok()?;
    }
    Some(bytes)
}

fn bytes64_to_hex(bytes: &[u8; 64]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
