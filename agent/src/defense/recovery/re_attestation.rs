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

    /// Ký số thông điệp thử thách phục hồi bằng khóa riêng Ed25519 của Admin
    pub fn sign_recovery_challenge(
        challenge: &RecoveryChallenge,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;
        let msg = compute_canonical_recovery_message(challenge);
        let sig = signing_key.sign(&msg);
        let mut s = String::with_capacity(128);
        for b in sig.to_bytes() {
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    /// Xác minh bằng chứng phục hồi (Recovery Proof)
    ///
    /// INV-003: bắt buộc chữ ký Ed25519 bất đối xứng từ Admin Authority.
    /// Đường "legacy fallback" cũ đã bị XÓA: "chữ ký" SHA-512 trên toàn bộ input
    /// công khai (challenge_id || new_pcr || pubkey) không chứa bất kỳ bí mật nào
    /// nên bất kỳ caller nào cũng tự tính được — đó là bypass xác thực, không phải
    /// cơ chế tương thích. Khóa admin sai độ dài giờ là lỗi cứng.
    ///
    /// `now` được inject để kiểm tra hạn challenge (fail-closed) mà vẫn kiểm thử
    /// deterministic được; caller truyền thời gian thực hiện tại.
    pub fn verify_and_re_attest(
        challenge: &RecoveryChallenge,
        proof: &RecoveryProof,
        admin_pubkey: &[u8],
        expected_oem_cert_hash: &str,
        now: u64,
    ) -> Result<DeviceLifecycleState, &'static str> {
        // 1. Challenge phải còn hạn: chặn replay challenge cũ đã bị lộ
        //    (chống snapshot rollback: kẻ tấn công khôi phục trạng thái cũ
        //    không được tái sử dụng challenge tạo trước thời điểm rollback).
        if now < challenge.created_at {
            return Err("Recovery challenge timestamp is in the future");
        }
        if now.saturating_sub(challenge.created_at) > MAX_RECOVERY_CHALLENGE_AGE_SECS {
            return Err("Recovery challenge expired");
        }

        if challenge.challenge_id != proof.challenge_id {
            return Err("Challenge ID mismatch");
        }

        if proof.oem_update_cert_hash != expected_oem_cert_hash {
            return Err("OEM update certificate hash mismatch");
        }

        // 2. INV-003: khóa admin phải là Ed25519 32-byte — không có ngoại lệ
        if admin_pubkey.len() != 32 {
            return Err("Admin public key must be a 32-byte Ed25519 key");
        }
        let pubkey_bytes: [u8; 32] = admin_pubkey
            .try_into()
            .map_err(|_| "Admin public key must be a 32-byte Ed25519 key")?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| "Invalid Ed25519 public key")?;

        let sig_bytes = hex_decode_64(&proof.admin_signature_sha512)
            .ok_or("Invalid admin authorization signature")?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let canonical_msg = compute_canonical_recovery_message(challenge);
        verifying_key
            .verify_strict(&canonical_msg, &signature)
            .map_err(|_| "Invalid admin authorization signature")?;

        // Tái xác thực thành công -> phục hồi trạng thái ActiveAttested
        Ok(DeviceLifecycleState::ActiveAttested)
    }
}

/// Hạn tối đa của một Recovery Challenge: 15 phút.
pub const MAX_RECOVERY_CHALLENGE_AGE_SECS: u64 = 900;

pub const DOMAIN_RECOVERY: &[u8] = b"CYBERV/RECOVERY/v1\0";

/// Thông điệp ký canonical của challenge phục hồi: mọi trường độ dài thay đổi
/// đều prefix độ dài (u32 BE), kèm previous_pcr, nonce và created_at để chữ ký
/// bó chặt vào toàn bộ ngữ cảnh chuyển đổi PCR — không thể chuyển chữ ký giữa
/// hai challenge hay hai lần chuyển trạng thái khác nhau.
pub fn compute_canonical_recovery_message(challenge: &RecoveryChallenge) -> Vec<u8> {
    fn push_field(msg: &mut Vec<u8>, field: &[u8]) {
        msg.extend_from_slice(&(field.len() as u32).to_be_bytes());
        msg.extend_from_slice(field);
    }

    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_RECOVERY);
    push_field(&mut msg, challenge.challenge_id.as_bytes());
    push_field(&mut msg, challenge.device_id.as_bytes());
    push_field(&mut msg, challenge.previous_pcr_sha512.as_bytes());
    push_field(&mut msg, challenge.new_pcr_sha512.as_bytes());
    msg.extend_from_slice(&challenge.nonce);
    msg.extend_from_slice(&challenge.created_at.to_le_bytes());
    msg
}

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    let bytes = s.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 64];
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
    }
    Some(out)
}

