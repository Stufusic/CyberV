//! Merkle Selective Disclosure (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 37:
//! "Consumer default: Merkle selective disclosure.
//! Cho phép công khai từng trường linh kiện chọn lọc (VD: dung lượng RAM)
//! kèm Merkle Inclusion Proof dẫn tới Public Root mà giấu kín Serial ổ đĩa."

use crate::evidence::merkle::proof::MerkleInclusionProof;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
    #[error("Gốc Merkle của thuộc tính '{0}' không khớp với Public Root: {1}")]
    RootMismatch(String, String),

    #[error("Bằng chứng bao hàm Merkle của thuộc tính '{0}' không hợp lệ")]
    InvalidInclusionProof(String),

    #[error("Yêu cầu công bố chọn lọc rỗng")]
    EmptyClaim,
}

/// Thuộc tính linh kiện được công bố chọn lọc
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosedAttribute {
    pub field_name: String,
    pub field_value: String,
    pub inclusion_proof: MerkleInclusionProof,
}

/// Gói tuyên bố công bố chọn lọc (Selective Disclosure Claim)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureClaim {
    pub public_root: String,
    pub attributes: Vec<DisclosedAttribute>,
}

pub struct SelectiveDisclosureEngine;

impl SelectiveDisclosureEngine {
    /// Xác minh tính xác thực của các trường được công bố chọn lọc mà không cần biết các trường bí mật khác
    pub fn verify_claim(
        claim: &SelectiveDisclosureClaim,
        expected_root: &str,
    ) -> Result<bool, SelectiveDisclosureError> {
        if claim.attributes.is_empty() {
            return Err(SelectiveDisclosureError::EmptyClaim);
        }

        if claim.public_root != expected_root {
            return Err(SelectiveDisclosureError::RootMismatch(
                "claim_root".to_string(),
                claim.public_root.clone(),
            ));
        }

        for attr in &claim.attributes {
            if attr.inclusion_proof.root_hash_hex != expected_root {
                return Err(SelectiveDisclosureError::RootMismatch(
                    attr.field_name.clone(),
                    attr.inclusion_proof.root_hash_hex.clone(),
                ));
            }

            if !attr.inclusion_proof.verify() {
                return Err(SelectiveDisclosureError::InvalidInclusionProof(
                    attr.field_name.clone(),
                ));
            }
        }

        Ok(true)
    }
}
