//! Merkle Mountain Range (MMR) Data Structure (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8 Section 41, 43:
//! "MMR Append-only Log, Peak Bagging, Inclusion Proofs O(log N)."

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const DOMAIN_MMR_INTERNAL: &[u8] = b"CYBERV/DBS/MMR_INTERNAL/v1\0";
pub const DOMAIN_MMR_PEAK_BAG: &[u8] = b"CYBERV/DBS/MMR_BAG_PEAKS/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProofStep {
    pub sibling_hash: String,
    pub is_right_sibling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrInclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: String,
    pub path_to_peak: Vec<MmrProofStep>,
    pub peak_hash: String,
    pub all_peaks: Vec<String>,
    pub mmr_root: String,
    pub tree_size: u64,
}

impl MmrInclusionProof {
    /// Xác minh bằng chứng bao hàm trong MMR
    pub fn verify(&self) -> bool {
        // 1. Tái tạo đỉnh Peak từ lá và đường đi
        let mut current_hash = self.leaf_hash.clone();
        for step in &self.path_to_peak {
            let mut hasher = Sha512::new();
            hasher.update(DOMAIN_MMR_INTERNAL);
            if step.is_right_sibling {
                hasher.update(current_hash.as_bytes());
                hasher.update(step.sibling_hash.as_bytes());
            } else {
                hasher.update(step.sibling_hash.as_bytes());
                hasher.update(current_hash.as_bytes());
            }
            current_hash = format!("{:x}", hasher.finalize());
        }

        if current_hash != self.peak_hash {
            return false;
        }

        // 2. Kiểm tra peak có nằm trong danh sách các đỉnh hợp lệ
        if !self.all_peaks.contains(&self.peak_hash) {
            return false;
        }

        // 3. Tái tạo MMR Root từ danh sách các đỉnh
        let computed_root = bag_peaks(&self.all_peaks);
        computed_root == self.mmr_root
    }
}

/// Cấu trúc Merkle Mountain Range (MMR)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleMountainRange {
    pub leaves: Vec<String>, // Danh sách băm các lá
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Thêm 1 phần tử lá vào MMR và trả về chỉ số lá (0-indexed)
    pub fn append(&mut self, entry_hash: impl Into<String>) -> u64 {
        let idx = self.leaves.len() as u64;
        self.leaves.push(entry_hash.into());
        idx
    }

    /// Trích xuất danh sách các đỉnh (Peaks) của MMR
    pub fn get_peaks(&self) -> Vec<String> {
        if self.leaves.is_empty() {
            return Vec::new();
        }

        // Phân rã tree_size thành tổng các lũy thừa của 2
        let mut peaks = Vec::new();
        let mut offset = 0;
        let mut remaining = self.leaves.len();

        while remaining > 0 {
            let mut power = 1;
            while power * 2 <= remaining {
                power *= 2;
            }

            let peak_hash = build_subtree_peak(&self.leaves[offset..offset + power]);
            peaks.push(peak_hash);

            offset += power;
            remaining -= power;
        }

        peaks
    }

    /// Tính toán MMR Root bằng cách gom các đỉnh (Peak Bagging)
    pub fn root(&self) -> String {
        let peaks = self.get_peaks();
        bag_peaks(&peaks)
    }

    /// Sinh bằng chứng bao hàm cho một phần tử lá
    pub fn generate_proof(&self, leaf_index: u64) -> Option<MmrInclusionProof> {
        let idx = leaf_index as usize;
        if idx >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[idx].clone();
        let all_peaks = self.get_peaks();

        // Xác định subtree chứa lá
        let mut offset = 0;
        let mut remaining = self.leaves.len();
        let mut target_subtree = &self.leaves[..];

        while remaining > 0 {
            let mut power = 1;
            while power * 2 <= remaining {
                power *= 2;
            }

            if idx >= offset && idx < offset + power {
                target_subtree = &self.leaves[offset..offset + power];
                break;
            }

            offset += power;
            remaining -= power;
        }

        let rel_idx = idx - offset;
        let (path_to_peak, peak_hash) = generate_subtree_proof(target_subtree, rel_idx);

        Some(MmrInclusionProof {
            leaf_index,
            leaf_hash,
            path_to_peak,
            peak_hash,
            all_peaks,
            mmr_root: self.root(),
            tree_size: self.tree_size(),
        })
    }
}

fn build_subtree_peak(leaves: &[String]) -> String {
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = &current_level[i + 1];

            let mut hasher = Sha512::new();
            hasher.update(DOMAIN_MMR_INTERNAL);
            hasher.update(left.as_bytes());
            hasher.update(right.as_bytes());
            next_level.push(format!("{:x}", hasher.finalize()));
        }
        current_level = next_level;
    }

    current_level[0].clone()
}

fn generate_subtree_proof(leaves: &[String], target_idx: usize) -> (Vec<MmrProofStep>, String) {
    let mut path = Vec::new();
    let mut current_level = leaves.to_vec();
    let mut idx = target_idx;

    while current_level.len() > 1 {
        let is_left = idx.is_multiple_of(2);
        let sibling_idx = if is_left { idx + 1 } else { idx - 1 };
        let sibling_hash = current_level[sibling_idx].clone();

        path.push(MmrProofStep {
            sibling_hash,
            is_right_sibling: is_left,
        });

        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = &current_level[i + 1];

            let mut hasher = Sha512::new();
            hasher.update(DOMAIN_MMR_INTERNAL);
            hasher.update(left.as_bytes());
            hasher.update(right.as_bytes());
            next_level.push(format!("{:x}", hasher.finalize()));
        }
        current_level = next_level;
        idx /= 2;
    }

    (path, current_level[0].clone())
}

pub fn bag_peaks(peaks: &[String]) -> String {
    if peaks.is_empty() {
        return "0".repeat(128);
    }
    if peaks.len() == 1 {
        return peaks[0].clone();
    }

    // Hash gom các đỉnh từ phải sang trái
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_MMR_PEAK_BAG);
    for peak in peaks {
        hasher.update(peak.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
