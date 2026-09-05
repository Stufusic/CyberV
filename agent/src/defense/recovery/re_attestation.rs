//! Safe Recovery & Re-Attestation Lifecycle (Phase 22)
//!
//! Ref: Docs/rv11.md Section 10:
//! "Safe Recovery Pipeline:
//! Khi PCR mismatch sau BIOS update: KHÔNG lập tức brick hoặc destroy identity.
//! Chuyển trạng thái sang RECOVERY_PENDING (Assurance degraded to OSProtected).
//! Yêu cầu Re-Attestation thông qua Recovery Challenge.
//! Cập nhật PCR Golden Baseline mới sau khi kiểm tra chữ ký OEM hợp lệ."

use super::transition::PlatformUpdateType;
use crate::security::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fmt::Write;

fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceLifecycleState {
    /// Hoạt động bình thường, đã qua kiểm định đo lường mã hóa
    ActiveAttested,
    /// Phát hiện thay đổi nền tảng hợp lệ, chờ xác thực re-attestation
    RecoveryPending,
    /// Bị cách ly do phát hiện can thiệp bất hợp pháp hoặc xác thực phục hồi thất bại
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryChallenge {
    pub challenge_id: String,
    pub device_id: String,
    pub nonce: [u8; 32],
    pub previous_pcr_sha512: String,
    pub new_pcr_sha512: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryProof {
    pub challenge_id: String,
    pub admin_signature_sha512: String,
    pub oem_update_cert_hash: String,
}

pub struct RecoveryManager;

impl RecoveryManager {
    /// Xử lý sự kiện cập nhật / thay đổi nền tảng
    pub fn handle_transition(
        current_state: DeviceLifecycleState,
        update_type: PlatformUpdateType,
    ) -> (DeviceLifecycleState, AssuranceLevel) {
        match update_type {
            PlatformUpdateType::Unchanged => (current_state, AssuranceLevel::Attested),
            PlatformUpdateType::ExpectedOemUpdate | PlatformUpdateType::ExpectedOsUpdate => {
                // Không brick máy, chuyển sang RECOVERY_PENDING và hạ tạm thời xuống OSProtected
                (
                    DeviceLifecycleState::RecoveryPending,
                    AssuranceLevel::OSProtected,
                )
            }
            PlatformUpdateType::UnexpectedTampering => {
                // Can thiệp bất hợp pháp -> cách ly ngay lập tức
                (DeviceLifecycleState::Quarantined, AssuranceLevel::Unknown)
            }
        }
    }

    /// Tạo một thử thách phục hồi (Recovery Challenge)
    pub fn create_challenge(
        device_id: impl Into<String>,
        nonce: [u8; 32],
        previous_pcr: &[u8],
        new_pcr: &[u8],
        now: u64,
    ) -> RecoveryChallenge {
        let challenge_id = format!("rc_{:x}_{}", now, &sha512_hex(&nonce)[..8]);
        RecoveryChallenge {
            challenge_id,
            device_id: device_id.into(),
            nonce,
            previous_pcr_sha512: sha512_hex(previous_pcr),
            new_pcr_sha512: sha512_hex(new_pcr),
            created_at: now,
        }
    }

    /// Xác minh bằng chứng phục hồi (Recovery Proof)
    pub fn verify_and_re_attest(
        challenge: &RecoveryChallenge,
        proof: &RecoveryProof,
        admin_pubkey: &[u8],
        expected_oem_cert_hash: &str,
    ) -> Result<DeviceLifecycleState, &'static str> {
        if challenge.challenge_id != proof.challenge_id {
            return Err("Challenge ID mismatch");
        }

        if proof.oem_update_cert_hash != expected_oem_cert_hash {
            return Err("OEM update certificate hash mismatch");
        }

        // Kiểm tra chữ ký admin xác nhận re-attestation: H(challenge_id || new_pcr || admin_pubkey)
        let mut expected_admin_hasher = Sha512::new();
        expected_admin_hasher.update(challenge.challenge_id.as_bytes());
        expected_admin_hasher.update(challenge.new_pcr_sha512.as_bytes());
        expected_admin_hasher.update(admin_pubkey);
        let expected_admin_sig = {
            let out = expected_admin_hasher.finalize();
            let mut s = String::with_capacity(out.len() * 2);
            for b in out {
                let _ = write!(s, "{:02x}", b);
            }
            s
        };

        if proof.admin_signature_sha512 != expected_admin_sig {
            return Err("Invalid admin authorization signature");
        }

        // Tái xác thực thành công -> phục hồi trạng thái ActiveAttested
        Ok(DeviceLifecycleState::ActiveAttested)
    }
}
