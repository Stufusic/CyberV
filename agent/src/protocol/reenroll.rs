//! CyberV Dynamic Re-enrollment Protocol
//!
//! Ref: Pipeline.md Section 22-24, Rule.md Điều 1, 10, 15:
//! "Re-enrollment Request có chữ ký Ed25519 của stable device identity...
//! Length-prefixed canonical payload trên DOMAIN_REENROLL."

use crate::identity::error::IdentityError;
use crate::identity::keypair::DeviceIdentityKey;
use crate::protocol::constants::{DOMAIN_REENROLL, PROTOCOL_VERSION};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Represents an authenticated hardware state re-enrollment application
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenrollmentRequest {
    pub device_id: String,
    pub previous_state_hash: String,
    pub new_state_hash: String,
    pub new_graph_hash: String,
    pub new_graph_version: u32,
    pub reason: String,
    pub proof_signature: String, // 128 lowercase hex characters (64 bytes Ed25519)
}

/// Builds length-prefixed canonical bytes for the re-enrollment signature
#[allow(clippy::too_many_arguments)]
pub fn build_reenrollment_signature_payload(
    protocol_version: u32,
    device_id: &str,
    previous_state_hash: &str,
    new_state_hash: &str,
    new_graph_hash: &str,
    new_graph_version: u32,
    reason: &str,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // 1. Domain
    buffer.extend_from_slice(DOMAIN_REENROLL);
    buffer.push(0x00);

    // 2. Versions
    buffer.extend_from_slice(&protocol_version.to_be_bytes());
    buffer.push(0x00);
    buffer.extend_from_slice(&new_graph_version.to_be_bytes());
    buffer.push(0x00);

    // 3. Length-prefixed device_id
    let dev_bytes = device_id.as_bytes();
    buffer.extend_from_slice(&(dev_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(dev_bytes);
    buffer.push(0x00);

    // 4. Length-prefixed previous_state_hash
    let prev_bytes = previous_state_hash.as_bytes();
    buffer.extend_from_slice(&(prev_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(prev_bytes);
    buffer.push(0x00);

    // 5. Length-prefixed new_state_hash
    let new_bytes = new_state_hash.as_bytes();
    buffer.extend_from_slice(&(new_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(new_bytes);
    buffer.push(0x00);

    // 6. Length-prefixed new_graph_hash
    let gh_bytes = new_graph_hash.as_bytes();
    buffer.extend_from_slice(&(gh_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(gh_bytes);
    buffer.push(0x00);

    // 7. Length-prefixed reason
    let reason_bytes = reason.as_bytes();
    buffer.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(reason_bytes);

    buffer
}

/// Creates and cryptographically signs a re-enrollment request using the device's stable keypair
pub fn create_reenrollment_request(
    key: &DeviceIdentityKey,
    device_id: &str,
    previous_state_hash: &str,
    new_state_hash: &str,
    new_graph_hash: &str,
    new_graph_version: u32,
    reason: &str,
) -> Result<ReenrollmentRequest, IdentityError> {
    let payload = build_reenrollment_signature_payload(
        PROTOCOL_VERSION,
        device_id,
        previous_state_hash,
        new_state_hash,
        new_graph_hash,
        new_graph_version,
        reason,
    );

    let signature = key.sign(&payload);
    let proof_signature: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(ReenrollmentRequest {
        device_id: device_id.to_string(),
        previous_state_hash: previous_state_hash.to_string(),
        new_state_hash: new_state_hash.to_string(),
        new_graph_hash: new_graph_hash.to_string(),
        new_graph_version,
        reason: reason.to_string(),
        proof_signature,
    })
}

/// Verifies that a ReenrollmentRequest was signed by the holder of the corresponding VerifyingKey
pub fn verify_reenrollment_request(
    verifying_key: &VerifyingKey,
    req: &ReenrollmentRequest,
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

    let payload = build_reenrollment_signature_payload(
        PROTOCOL_VERSION,
        &req.device_id,
        &req.previous_state_hash,
        &req.new_state_hash,
        &req.new_graph_hash,
        req.new_graph_version,
        &req.reason,
    );

    DeviceIdentityKey::verify(verifying_key, &payload, &sig_bytes)
}
