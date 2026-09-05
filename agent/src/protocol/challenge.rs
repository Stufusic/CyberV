//! CyberV Challenge-Response Protocol & Proof of Possession
//!
//! Ref: rv4.md #10, #13, #14:
//! "Payload chữ ký có purpose, domain riêng...
//! Length-prefixed encoding...
//! Ký trên (protocol_v, graph_v, purpose, challenge_id, nonce, device_id, state_hash)..."

use crate::identity::error::IdentityError;
use crate::identity::keypair::DeviceIdentityKey;
use crate::protocol::constants::{
    DOMAIN_AUTH, DOMAIN_REENROLL, PROTOCOL_VERSION, PURPOSE_REENROLLMENT,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Challenge issued by the server
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeObject {
    pub challenge_id: String,
    pub nonce: String,
    pub device_id: String,
    pub purpose: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Cryptographic proof-of-possession signed by the device private key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedChallengeProof {
    pub challenge_id: String,
    pub nonce: String,
    pub device_id: String,
    pub purpose: String,
    pub state_hash: String,
    pub graph_version: u32,
    pub signature_hex: String, // 128 lowercase hex chars (64 bytes Ed25519)
}

/// Constructs deterministic, length-prefixed canonical signature payload bytes
#[allow(clippy::too_many_arguments)]
pub fn build_challenge_signature_payload(
    domain: &[u8],
    purpose: &str,
    protocol_version: u32,
    challenge_id: &str,
    nonce: &str,
    device_id: &str,
    state_hash: &str,
    graph_version: u32,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    // 1. Domain
    buffer.extend_from_slice(domain);
    buffer.push(0x00);

    // 2. Protocol & Graph versions
    buffer.extend_from_slice(&protocol_version.to_be_bytes());
    buffer.push(0x00);
    buffer.extend_from_slice(&graph_version.to_be_bytes());
    buffer.push(0x00);

    // 3. Length-prefixed purpose
    let purp_bytes = purpose.as_bytes();
    buffer.extend_from_slice(&(purp_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(purp_bytes);
    buffer.push(0x00);

    // 4. Length-prefixed challenge_id
    let chal_bytes = challenge_id.as_bytes();
    buffer.extend_from_slice(&(chal_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(chal_bytes);
    buffer.push(0x00);

    // 5. Length-prefixed nonce
    let nonce_bytes = nonce.as_bytes();
    buffer.extend_from_slice(&(nonce_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(nonce_bytes);
    buffer.push(0x00);

    // 6. Length-prefixed device_id
    let dev_bytes = device_id.as_bytes();
    buffer.extend_from_slice(&(dev_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(dev_bytes);
    buffer.push(0x00);

    // 7. Length-prefixed state_hash
    let hash_bytes = state_hash.as_bytes();
    buffer.extend_from_slice(&(hash_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(hash_bytes);

    buffer
}

/// Signs a challenge with the device's stable private key, returning SignedChallengeProof
pub fn create_challenge_proof(
    key: &DeviceIdentityKey,
    challenge: &ChallengeObject,
    state_hash: &str,
    graph_version: u32,
) -> Result<SignedChallengeProof, IdentityError> {
    let domain = match challenge.purpose.as_str() {
        PURPOSE_REENROLLMENT => DOMAIN_REENROLL,
        _ => DOMAIN_AUTH,
    };

    let payload = build_challenge_signature_payload(
        domain,
        &challenge.purpose,
        PROTOCOL_VERSION,
        &challenge.challenge_id,
        &challenge.nonce,
        &challenge.device_id,
        state_hash,
        graph_version,
    );

    let signature = key.sign(&payload);
    let signature_hex: String = signature.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(SignedChallengeProof {
        challenge_id: challenge.challenge_id.clone(),
        nonce: challenge.nonce.clone(),
        device_id: challenge.device_id.clone(),
        purpose: challenge.purpose.clone(),
        state_hash: state_hash.to_string(),
        graph_version,
        signature_hex,
    })
}

/// Verifies a SignedChallengeProof against a given VerifyingKey
pub fn verify_challenge_proof(
    verifying_key: &VerifyingKey,
    proof: &SignedChallengeProof,
) -> Result<(), IdentityError> {
    if proof.signature_hex.len() != 128 {
        return Err(IdentityError::SignatureVerification(format!(
            "Expected 128 hex chars for signature, got {}",
            proof.signature_hex.len()
        )));
    }

    let mut sig_bytes = [0u8; 64];
    for (i, byte) in sig_bytes.iter_mut().enumerate() {
        let byte_hex = &proof.signature_hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(byte_hex, 16)
            .map_err(|e| IdentityError::SignatureVerification(e.to_string()))?;
    }

    let domain = match proof.purpose.as_str() {
        PURPOSE_REENROLLMENT => DOMAIN_REENROLL,
        _ => DOMAIN_AUTH,
    };

    let payload = build_challenge_signature_payload(
        domain,
        &proof.purpose,
        PROTOCOL_VERSION,
        &proof.challenge_id,
        &proof.nonce,
        &proof.device_id,
        &proof.state_hash,
        proof.graph_version,
    );

    DeviceIdentityKey::verify(verifying_key, &payload, &sig_bytes)
}
