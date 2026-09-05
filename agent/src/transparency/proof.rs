//! Revocation Verification & Anti-Rogue-Admin Engine (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8 Section 45, 46:
//! "Verify checkpoint, verify inclusion proof, prevent silent un-revoke by rogue admin."

use super::checkpoint::SignedCheckpoint;
use super::event::{EventType, RevocationEvent};
use super::mmr::MmrInclusionProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationVerificationResult {
    /// Thiết bị bị thu hồi hợp lệ (có bằng chứng MMR và Checkpoint chuẩn)
    RevocationConfirmed {
        device_id: String,
        timestamp: u64,
        reason: String,
    },
    /// Phát hiện gian lận: Cơ sở dữ liệu mở khóa thiết bị nhưng không có bằng chứng UNREVOKED trong sổ cái MMR
    RogueAdminTamperDetected { device_id: String, reason: String },
    /// Bằng chứng giả mạo hoặc Checkpoint không hợp lệ
    VerificationFailed(String),
}

pub struct RevocationVerifier;

impl RevocationVerifier {
    /// Xác thực bằng chứng thu hồi thiết bị
    pub fn verify_revocation(
        checkpoint: &SignedCheckpoint,
        event: &RevocationEvent,
        proof: &MmrInclusionProof,
        expected_device_id: &str,
    ) -> RevocationVerificationResult {
        // 1. Xác thực chữ ký Authority trên Checkpoint
        if !checkpoint.verify() {
            return RevocationVerificationResult::VerificationFailed(
                "Chữ ký thẩm quyền trên Checkpoint không hợp lệ".to_string(),
            );
        }

        // 2. Ràng buộc device_id
        if event.device_id != expected_device_id {
            return RevocationVerificationResult::VerificationFailed(
                "Device ID trong sự kiện không khớp với thiết bị yêu cầu".to_string(),
            );
        }

        // 3. Kiểm tra loại sự kiện
        if event.event_type != EventType::DeviceRevoked {
            return RevocationVerificationResult::VerificationFailed(
                "Sự kiện không phải loại DEVICE_REVOKED".to_string(),
            );
        }

        // 4. Xác minh băm của event khớp với leaf_hash trong proof
        let entry_hash = event.entry_hash();
        if entry_hash != proof.leaf_hash {
            return RevocationVerificationResult::VerificationFailed(
                "Entry hash của sự kiện không khớp với bằng chứng MMR".to_string(),
            );
        }

        // 5. Xác minh MMR Root trong proof khớp với Checkpoint
        if proof.mmr_root != checkpoint.mmr_root {
            return RevocationVerificationResult::VerificationFailed(
                "MMR Root trong bằng chứng không khớp với Checkpoint đã ký".to_string(),
            );
        }

        // 6. Xác minh bằng chứng bao hàm trong cây MMR
        if !proof.verify() {
            return RevocationVerificationResult::VerificationFailed(
                "Xác minh đường đi Merkle Mountain Range thất bại".to_string(),
            );
        }

        RevocationVerificationResult::RevocationConfirmed {
            device_id: event.device_id.clone(),
            timestamp: event.timestamp,
            reason: event.reason_code.clone(),
        }
    }

    /// Kiểm tra chốt chặn chống Rogue Admin (Silent Un-revoke)
    pub fn verify_unrevocation_guard(
        db_status_active: bool,
        was_previously_revoked: bool,
        unrevoke_event: Option<(&RevocationEvent, &MmrInclusionProof, &SignedCheckpoint)>,
        device_id: &str,
    ) -> RevocationVerificationResult {
        if was_previously_revoked && db_status_active {
            // Thiết bị từng bị thu hồi nhưng DB lại báo Active -> Bắt buộc phải có sự kiện UNREVOKED trong sổ cái MMR
            let (event, proof, checkpoint) = match unrevoke_event {
                Some(triple) => triple,
                None => {
                    return RevocationVerificationResult::RogueAdminTamperDetected {
                        device_id: device_id.to_string(),
                        reason: "Thiết bị được kích hoạt lại trên DB mà không có sự kiện UNREVOKED trong sổ cái MMR".to_string(),
                    };
                }
            };

            // Xác minh sự kiện UNREVOKED hợp lệ
            if event.event_type != EventType::DeviceUnrevoked
                || !checkpoint.verify()
                || !proof.verify()
                || event.entry_hash() != proof.leaf_hash
            {
                return RevocationVerificationResult::RogueAdminTamperDetected {
                    device_id: device_id.to_string(),
                    reason: "Sự kiện phục hồi UNREVOKED không có chữ ký hợp lệ trong MMR"
                        .to_string(),
                };
            }
        }

        RevocationVerificationResult::RevocationConfirmed {
            device_id: device_id.to_string(),
            timestamp: 0,
            reason: "UNREVOCATION_VALID".to_string(),
        }
    }
}
