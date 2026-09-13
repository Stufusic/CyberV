//! Phase 19: FSE-4 VBS-Isolated Security Core Tests
//!
//! Ref: Docs/rv11.md Section 5:
//! Validates:
//! - VBS Capability Matrix & Assurance Level mapping
//! - Secure I/O Memory Boundary isolation & zeroization
//! - Identity Binding Proof between TPM 2.0 and VBS Enclave
//! - Attestation Engine & Virtual Node/Point generation

use cyberv_agent::defense::enclave::{
    BoundaryError, EnclaveAttestationEngine, EnclaveCapabilityMatrix, EnclaveMeasurement,
    EnclaveStatus, IdentityBindingEngine, SecureIsoBuffer, MAX_SECURE_PAYLOAD_SIZE,
};
use cyberv_agent::security::assurance::AssuranceLevel;

#[test]
fn test_01_enclave_active_attested_score() {
    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    assert_eq!(cap.status, EnclaveStatus::ActiveAttested);
    assert_eq!(cap.vtl_level, 1);
    assert!(cap.hvci_active);
    assert_eq!(cap.security_score(), 10000);
}

#[test]
fn test_02_enclave_supported_not_loaded_score() {
    let cap = EnclaveCapabilityMatrix::supported_not_loaded();
    assert_eq!(cap.status, EnclaveStatus::SupportedNotLoaded);
    assert_eq!(cap.vtl_level, 0);
    assert_eq!(cap.security_score(), 6000);
}

#[test]
fn test_03_enclave_unsupported_score() {
    let cap = EnclaveCapabilityMatrix::unsupported_software_fallback();
    assert_eq!(cap.status, EnclaveStatus::Unsupported);
    assert_eq!(cap.vtl_level, 0);
    assert_eq!(cap.security_score(), 2000);
}

#[test]
fn test_04_enclave_assurance_levels() {
    let active = EnclaveCapabilityMatrix::active_attested_vtl1();
    assert_eq!(active.assurance_level(), AssuranceLevel::Attested);

    let not_loaded = EnclaveCapabilityMatrix::supported_not_loaded();
    assert_eq!(not_loaded.assurance_level(), AssuranceLevel::OSProtected);

    let unsupported = EnclaveCapabilityMatrix::unsupported_software_fallback();
    assert_eq!(unsupported.assurance_level(), AssuranceLevel::Software);
}

#[test]
fn test_05_boundary_safe_copy_success() {
    let raw_data = b"VTL0_UNTRUSTED_SENSITIVE_KEY_PAYLOAD_123456789";
    let buf = SecureIsoBuffer::copy_from_untrusted(raw_data).expect("safe copy should succeed");
    assert_eq!(buf.len(), raw_data.len());
    assert_eq!(buf.as_slice(), raw_data);
}

#[test]
fn test_06_boundary_empty_buffer_error() {
    let empty = b"";
    let res = SecureIsoBuffer::copy_from_untrusted(empty);
    assert_eq!(res.unwrap_err(), BoundaryError::EmptyBuffer);
}

#[test]
fn test_07_boundary_too_large_error() {
    let large = vec![0x42u8; MAX_SECURE_PAYLOAD_SIZE + 1];
    let res = SecureIsoBuffer::copy_from_untrusted(&large);
    assert_eq!(
        res.unwrap_err(),
        BoundaryError::PayloadTooLarge(MAX_SECURE_PAYLOAD_SIZE + 1)
    );
}

#[test]
fn test_08_boundary_memory_zeroing_on_drop() {
    // Tests that memory zeroing drop works without crashing
    {
        let data = vec![0xAA; 128];
        let _buf = SecureIsoBuffer::copy_from_untrusted(&data).unwrap();
        // Dropped here
    }
}

#[test]
fn test_09_identity_binding_creation() {
    let tpm_ak = b"TPM_2_0_AIK_PUBLIC_KEY_BLOB_RSA_2048";
    let pcr_digest = b"PCR_0_7_11_SHA256_COMPOSITE_DIGEST_BYTES";
    let enclave_key = b"VBS_ENCLAVE_SIGNING_PUBLIC_KEY_ED25519";
    let nonce = [0x5Au8; 32];

    let proof = IdentityBindingEngine::create_binding(tpm_ak, pcr_digest, enclave_key, &nonce);
    assert_eq!(proof.tpm_ak_pub_sha512.len(), 128); // 64 bytes in hex
    assert_eq!(proof.pcr_digest_sha512.len(), 128);
    assert_eq!(proof.enclave_pubkey_sha512.len(), 128);
    assert_eq!(proof.binding_nonce_hex.len(), 64);
    assert_eq!(proof.combined_proof_digest.len(), 128);
}

#[test]
fn test_10_identity_binding_verification_success() {
    let tpm_ak = b"TPM_2_0_AIK_PUBLIC_KEY_BLOB_RSA_2048";
    let pcr_digest = b"PCR_0_7_11_SHA256_COMPOSITE_DIGEST_BYTES";
    let enclave_key = b"VBS_ENCLAVE_SIGNING_PUBLIC_KEY_ED25519";
    let nonce = [0x5Au8; 32];

    let proof = IdentityBindingEngine::create_binding(tpm_ak, pcr_digest, enclave_key, &nonce);
    let is_valid =
        IdentityBindingEngine::verify_binding(&proof, tpm_ak, pcr_digest, enclave_key, &nonce);
    assert!(is_valid);
}

#[test]
fn test_11_identity_binding_verification_tamper_fails() {
    let tpm_ak = b"TPM_2_0_AIK_PUBLIC_KEY_BLOB_RSA_2048";
    let pcr_digest = b"PCR_0_7_11_SHA256_COMPOSITE_DIGEST_BYTES";
    let enclave_key = b"VBS_ENCLAVE_SIGNING_PUBLIC_KEY_ED25519";
    let nonce = [0x5Au8; 32];

    let proof = IdentityBindingEngine::create_binding(tpm_ak, pcr_digest, enclave_key, &nonce);

    // Tampered TPM AK
    let tampered_tpm_ak = b"ROGUE_SPOOFED_TPM_KEY";
    let is_valid = IdentityBindingEngine::verify_binding(
        &proof,
        tampered_tpm_ak,
        pcr_digest,
        enclave_key,
        &nonce,
    );
    assert!(!is_valid);
}

#[test]
fn test_12_identity_binding_nonce_mismatch_fails() {
    let tpm_ak = b"TPM_2_0_AIK_PUBLIC_KEY_BLOB_RSA_2048";
    let pcr_digest = b"PCR_0_7_11_SHA256_COMPOSITE_DIGEST_BYTES";
    let enclave_key = b"VBS_ENCLAVE_SIGNING_PUBLIC_KEY_ED25519";
    let nonce = [0x5Au8; 32];
    let diff_nonce = [0x11u8; 32];

    let proof = IdentityBindingEngine::create_binding(tpm_ak, pcr_digest, enclave_key, &nonce);
    let is_valid =
        IdentityBindingEngine::verify_binding(&proof, tpm_ak, pcr_digest, enclave_key, &diff_nonce);
    assert!(!is_valid);
}

#[test]
fn test_13_enclave_attestation_full_valid() {
    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    let measurement = EnclaveMeasurement {
        author_id: "CyberV-Security-Corp-VBS-Authority".to_string(),
        image_id: "CyberVEnclaveCore.dll".to_string(),
        svn: 2,
        measurement_hash_sha512: "a1b2c3d4e5f6...".to_string(),
    };

    let tpm_ak = b"TPM_AK";
    let pcr_digest = b"PCR_DIGEST";
    let enclave_key = b"ENCLAVE_KEY";
    let nonce = [0x01u8; 32];
    let binding = IdentityBindingEngine::create_binding(tpm_ak, pcr_digest, enclave_key, &nonce);

    let report = EnclaveAttestationEngine::evaluate(&cap, Some(&measurement), Some(&binding));
    assert_eq!(report.composite_score, 10000);
    assert_eq!(report.assurance_level, AssuranceLevel::Attested);
    assert!(report.is_enclave_trusted);
    assert_eq!(report.virtual_points.len(), 2);
    assert_eq!(report.virtual_nodes.len(), 1);
    assert!(report.summary.contains("trusted=true"));
}

#[test]
fn test_14_enclave_attestation_missing_binding_penalty() {
    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    let measurement = EnclaveMeasurement {
        author_id: "CyberV-Security-Corp-VBS-Authority".to_string(),
        image_id: "CyberVEnclaveCore.dll".to_string(),
        svn: 2,
        measurement_hash_sha512: "a1b2c3d4e5f6...".to_string(),
    };

    // Missing binding proof
    let report = EnclaveAttestationEngine::evaluate(&cap, Some(&measurement), None);
    assert_eq!(report.composite_score, 8000); // 10000 - 2000
    assert!(!report.is_enclave_trusted); // Requires both measurement and binding
}

#[test]
fn test_15_enclave_attestation_unsupported_software_fallback() {
    let cap = EnclaveCapabilityMatrix::unsupported_software_fallback();
    let report = EnclaveAttestationEngine::evaluate(&cap, None, None);
    assert_eq!(report.composite_score, 2000);
    assert_eq!(report.assurance_level, AssuranceLevel::Software);
    assert!(!report.is_enclave_trusted);
    assert!(report.summary.contains("trusted=false"));
}
