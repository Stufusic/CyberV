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

        // Bất biến INV-003: Nếu admin_pubkey là khóa Ed25519 32-byte, thực thi kiểm tra chữ ký số bất đối xứng nghiêm ngặt
        if admin_pubkey.len() == 32 {
            let pubkey_bytes: [u8; 32] = admin_pubkey
                .try_into()
                .map_err(|_| "Invalid admin public key length")?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
                .map_err(|_| "Invalid Ed25519 public key")?;

            let sig_bytes = hex_decode_64(&proof.admin_signature_sha512)
                .ok_or("Invalid signature format (expected 64 bytes hex)")?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            let canonical_msg = compute_canonical_recovery_message(challenge);
            verifying_key
                .verify_strict(&canonical_msg, &signature)
                .map_err(|_| "Invalid admin authorization signature (Ed25519 verification failed)")?;

            return Ok(DeviceLifecycleState::ActiveAttested);
        }

        // Fallback tương thích ngược với legacy mock key (< 32 bytes)
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

pub const DOMAIN_RECOVERY: &[u8] = b"CYBERV/RECOVERY/v1\0";

pub fn compute_canonical_recovery_message(challenge: &RecoveryChallenge) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_RECOVERY);
    msg.extend_from_slice(challenge.challenge_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(challenge.new_pcr_sha512.as_bytes());
    msg.push(0);
    msg.extend_from_slice(challenge.device_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&challenge.created_at.to_le_bytes());
    msg
}

fn hex_decode_64(hex_str: &str) -> Option<[u8; 64]> {
    if hex_str.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for i in 0..64 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}
