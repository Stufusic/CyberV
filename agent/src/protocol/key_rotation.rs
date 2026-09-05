//! CyberV Cryptographic Key Rotation Protocol
//!
//! Ref: Plan.md Section 22, rv4.md #1, #4 and Rule.md Điều 1, 2, 6, 8, 20:
//! "Key Rotation cho phép Agent thay thế cặp khóa Ed25519 mà không làm đứt gãy
//! chuỗi liên kết đồ thị và device_id. Quá trình yêu cầu chữ ký kép (Dual-Proof-of-Possession):
//! - signature_old: Ký bởi khóa cũ để ủy quyền bàn giao.
//! - signature_new: Ký bởi khóa mới để chứng minh thực sự sở hữu khóa bí mật mới."

use crate::identity::error::IdentityError;
use crate::identity::keypair::DeviceIdentityKey;
use crate::protocol::constants::{DOMAIN_KEY_ROTATION, PROTOCOL_VERSION};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Yêu cầu quay vòng khóa định danh thiết bị kèm chữ ký kép (Dual Proof-of-Possession)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub device_id: String,
    pub old_public_key_hex: String,
    pub new_public_key_hex: String,
    pub state_hash: String,
    pub graph_version: u32,
    pub nonce: String,
    pub timestamp: u64,
    pub signature_old: String, // Ký bởi khóa cũ (128 hex chars)
    pub signature_new: String, // Ký bởi khóa mới (128 hex chars)
}

/// Xây dựng mảng byte chính tắc có tiền tố độ dài chuẩn xác (Length-prefixed Canonical Bytes)
#[allow(clippy::too_many_arguments)]
pub fn build_key_rotation_signature_payload(
    protocol_version: u32,
    device_id: &str,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    state_hash: &str,
    graph_version: u32,
    nonce: &str,
    timestamp: u64,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // 1. Domain separator
    buffer.extend_from_slice(DOMAIN_KEY_ROTATION);
    buffer.push(0x00);

    // 2. Protocol version
    buffer.extend_from_slice(&protocol_version.to_be_bytes());
    buffer.push(0x00);

    // 3. Graph version
    buffer.extend_from_slice(&graph_version.to_be_bytes());
    buffer.push(0x00);

    // 4. Timestamp
    buffer.extend_from_slice(&timestamp.to_be_bytes());
    buffer.push(0x00);

    // 5. Length-prefixed device_id
    let dev_bytes = device_id.as_bytes();
    buffer.extend_from_slice(&(dev_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(dev_bytes);
    buffer.push(0x00);

    // 6. Length-prefixed old_public_key_hex
    let old_pk_bytes = old_public_key_hex.as_bytes();
    buffer.extend_from_slice(&(old_pk_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(old_pk_bytes);
    buffer.push(0x00);

    // 7. Length-prefixed new_public_key_hex
    let new_pk_bytes = new_public_key_hex.as_bytes();
    buffer.extend_from_slice(&(new_pk_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(new_pk_bytes);
    buffer.push(0x00);

    // 8. Length-prefixed state_hash
    let sh_bytes = state_hash.as_bytes();
    buffer.extend_from_slice(&(sh_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(sh_bytes);
    buffer.push(0x00);

    // 9. Length-prefixed nonce
    let nonce_bytes = nonce.as_bytes();
    buffer.extend_from_slice(&(nonce_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(nonce_bytes);

    buffer
}

/// Khởi tạo và ký kép một yêu cầu quay vòng khóa Ed25519
pub fn create_key_rotation_request(
    old_key: &DeviceIdentityKey,
    new_key: &DeviceIdentityKey,
    device_id: &str,
    state_hash: &str,
    graph_version: u32,
    nonce: &str,
    timestamp: u64,
) -> Result<KeyRotationRequest, IdentityError> {
    let old_public_key_hex = old_key.public_key_hex();
    let new_public_key_hex = new_key.public_key_hex();

    if old_public_key_hex == new_public_key_hex {
        return Err(IdentityError::InvalidPublicKey(
            "New public key cannot be identical to old public key".to_string(),
        ));
    }

    let payload = build_key_rotation_signature_payload(
        PROTOCOL_VERSION,
        device_id,
        &old_public_key_hex,
        &new_public_key_hex,
        state_hash,
        graph_version,
        nonce,
        timestamp,
    );

    let sig_old_bytes = old_key.sign(&payload);
    let signature_old: String = sig_old_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let sig_new_bytes = new_key.sign(&payload);
    let signature_new: String = sig_new_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(KeyRotationRequest {
        device_id: device_id.to_string(),
        old_public_key_hex,
        new_public_key_hex,
        state_hash: state_hash.to_string(),
        graph_version,
        nonce: nonce.to_string(),
        timestamp,
        signature_old,
        signature_new,
    })
}

fn parse_hex_pubkey(hex_str: &str) -> Result<VerifyingKey, IdentityError> {
    if hex_str.len() != 64 {
        return Err(IdentityError::InvalidPublicKey(format!(
            "Expected 64 hex characters for public key, got {}",
            hex_str.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let byte_hex = &hex_str[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(byte_hex, 16)
            .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))
}

fn parse_hex_signature(hex_str: &str) -> Result<[u8; 64], IdentityError> {
    if hex_str.len() != 128 {
        return Err(IdentityError::SignatureVerification(format!(
            "Expected 128 hex characters for signature, got {}",
            hex_str.len()
        )));
    }
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let byte_hex = &hex_str[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(byte_hex, 16)
            .map_err(|e| IdentityError::SignatureVerification(e.to_string()))?;
    }
    Ok(bytes)
}

/// Thẩm định toàn diện chữ ký kép (Dual Signature Verification)
pub fn verify_key_rotation_request(request: &KeyRotationRequest) -> Result<bool, IdentityError> {
    if request.old_public_key_hex == request.new_public_key_hex {
        return Ok(false);
    }

    let payload = build_key_rotation_signature_payload(
        PROTOCOL_VERSION,
        &request.device_id,
        &request.old_public_key_hex,
        &request.new_public_key_hex,
        &request.state_hash,
        request.graph_version,
        &request.nonce,
        request.timestamp,
    );

    // 1. Thẩm định signature_old với old_public_key
    let old_verifying_key = match parse_hex_pubkey(&request.old_public_key_hex) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let sig_old_bytes = match parse_hex_signature(&request.signature_old) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    if DeviceIdentityKey::verify(&old_verifying_key, &payload, &sig_old_bytes).is_err() {
        return Ok(false);
    }

    // 2. Thẩm định signature_new với new_public_key
    let new_verifying_key = match parse_hex_pubkey(&request.new_public_key_hex) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let sig_new_bytes = match parse_hex_signature(&request.signature_new) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    if DeviceIdentityKey::verify(&new_verifying_key, &payload, &sig_new_bytes).is_err() {
        return Ok(false);
    }

    Ok(true)
}
