//! CyberV Initial Device Enrollment Protocol
//!
//! Ref: Plan.md Section 1, Rule.md Điều 1, 8, 10, 20:
//! "Mỗi thiết bị được cấp một Device Identity ngẫu nhiên...
//! Đăng ký ban đầu có chữ ký số Ed25519 của stable device identity trên DOMAIN_ENROLL."

use crate::identity::error::IdentityError;
use crate::identity::keypair::DeviceIdentityKey;
use crate::protocol::constants::{DOMAIN_ENROLL, PROTOCOL_VERSION};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Represents an authenticated initial device enrollment application
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollmentRequest {
    pub device_id: String,
    pub public_key_hex: String,
    pub current_graph_hash: String,
    pub current_state_hash: String,
    pub current_graph_version: u32,
    pub canonical_graph_json: serde_json::Value,
    pub proof_signature: String, // 128 lowercase hex characters (64 bytes Ed25519)
}

/// Builds length-prefixed canonical bytes for the enrollment signature
pub fn build_enrollment_signature_payload(
    protocol_version: u32,
    device_id: &str,
    public_key_hex: &str,
    graph_hash: &str,
    state_hash: &str,
    graph_version: u32,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // 1. Domain
    buffer.extend_from_slice(DOMAIN_ENROLL);
    buffer.push(0x00);

    // 2. Protocol version
    buffer.extend_from_slice(&protocol_version.to_be_bytes());
    buffer.push(0x00);

    // 3. Graph version
    buffer.extend_from_slice(&graph_version.to_be_bytes());
    buffer.push(0x00);

    // 4. Length-prefixed device_id
    let dev_bytes = device_id.as_bytes();
    buffer.extend_from_slice(&(dev_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(dev_bytes);
    buffer.push(0x00);

    // 5. Length-prefixed public_key_hex
    let pk_bytes = public_key_hex.as_bytes();
    buffer.extend_from_slice(&(pk_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(pk_bytes);
    buffer.push(0x00);

    // 6. Length-prefixed graph_hash
    let gh_bytes = graph_hash.as_bytes();
    buffer.extend_from_slice(&(gh_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(gh_bytes);
    buffer.push(0x00);

    // 7. Length-prefixed state_hash
    let sh_bytes = state_hash.as_bytes();
    buffer.extend_from_slice(&(sh_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(sh_bytes);

    buffer
}

/// Creates and cryptographically signs an initial enrollment request
pub fn create_enrollment_request(
    key: &DeviceIdentityKey,
    device_id: &str,
    graph_hash: &str,
    state_hash: &str,
    graph_version: u32,
    canonical_graph_json: serde_json::Value,
) -> Result<DeviceEnrollmentRequest, IdentityError> {
    let public_key_hex = key.public_key_hex();

    let payload = build_enrollment_signature_payload(
        PROTOCOL_VERSION,
        device_id,
        &public_key_hex,
        graph_hash,
        state_hash,
        graph_version,
    );

    let signature = key.sign(&payload);
    let proof_signature: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(DeviceEnrollmentRequest {
        device_id: device_id.to_string(),
        public_key_hex,
        current_graph_hash: graph_hash.to_string(),
        current_state_hash: state_hash.to_string(),
        current_graph_version: graph_version,
        canonical_graph_json,
        proof_signature,
    })
}

/// Verifies that a DeviceEnrollmentRequest was signed by its public key
pub fn verify_enrollment_request(
    verifying_key: &VerifyingKey,
    req: &DeviceEnrollmentRequest,
) -> Result<(), IdentityError> {
    if req.proof_signature.len() != 128 {
        return Err(IdentityError::SignatureVerification(format!(
            "Expected 128 hex characters for proof signature, got {}",
            req.proof_signature.len()
        )));
    }

    let mut sig_bytes = [0u8; 64];
    for (i, byte) in sig_bytes.iter_mut().enumerate() {
        let byte_hex = &req.proof_signature[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(byte_hex, 16)
            .map_err(|e| IdentityError::SignatureVerification(e.to_string()))?;
    }

    let payload = build_enrollment_signature_payload(
        PROTOCOL_VERSION,
        &req.device_id,
        &req.public_key_hex,
        &req.current_graph_hash,
        &req.current_state_hash,
        req.current_graph_version,
    );

    DeviceIdentityKey::verify(verifying_key, &payload, &sig_bytes)
}
