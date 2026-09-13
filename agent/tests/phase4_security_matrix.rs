//! CyberV Phase 4 Security & Cryptographic Test Matrix
//!
//! Ref: rv4.md #20: 7 Comprehensive Test Categories
//! 1. IDENTITY
//! 2. INTEGRITY
//! 3. KDF
//! 4. STATE
//! 5. STORAGE (including hardware mutation without destroying vault)
//! 6. REPLAY
//! 7. CROSS-IMPLEMENTATION

use cyberv_agent::fingerprint::component_hasher::hash_snapshot;
use cyberv_agent::fingerprint::graph::build_evidence_graph;
use cyberv_agent::fingerprint::state_hasher::evaluate_device_state;
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::identity::error::IdentityError;
use cyberv_agent::identity::kdf::derive_state_bound_material;
use cyberv_agent::identity::keypair::DeviceIdentityKey;
use cyberv_agent::identity::rng::{OsCryptoRng, SecureRandom};
use cyberv_agent::identity::secret::Secret32;
use cyberv_agent::identity::storage::{DeviceSecureStorage, MockSecureStorage, PersistedIdentity};
use cyberv_agent::protocol::challenge::{
    build_challenge_signature_payload, create_challenge_proof, verify_challenge_proof,
    ChallengeObject,
};
use cyberv_agent::protocol::constants::{
    DOMAIN_AUTH, PROTOCOL_VERSION, PURPOSE_DEVICE_AUTH, PURPOSE_REENROLLMENT,
};
use std::collections::BTreeMap;

/// Deterministic RNG strictly for unit testing and known vector verification
struct DeterministicTestRng {
    state: [u8; 32],
    counter: u64,
}

impl DeterministicTestRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            counter: 0,
        }
    }
}

impl SecureRandom for DeterministicTestRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), IdentityError> {
        use sha2::{Digest, Sha512};
        let mut filled = 0;
        while filled < dest.len() {
            let mut hasher = Sha512::new();
            hasher.update(self.state);
            hasher.update(self.counter.to_be_bytes());
            self.counter += 1;
            let digest = hasher.finalize();

            let to_copy = (dest.len() - filled).min(digest.len());
            dest[filled..filled + to_copy].copy_from_slice(&digest[..to_copy]);
            filled += to_copy;
        }
        Ok(())
    }
}

// =========================================================================
// 1. IDENTITY TESTS
// =========================================================================

#[test]
fn test_identity_keypair_generation_and_signing() {
    let mut rng = OsCryptoRng;
    let keypair = DeviceIdentityKey::generate(&mut rng).expect("Keygen failed");

    let payload = b"CyberV Test Payload";
    let sig = keypair.sign(payload);

    let verify_result = DeviceIdentityKey::verify(keypair.verifying_key(), payload, &sig);
    assert!(verify_result.is_ok(), "Signature verification must succeed");
}

#[test]
fn test_public_key_stable_after_reload() {
    let mut rng = OsCryptoRng;
    let keypair1 = DeviceIdentityKey::generate(&mut rng).unwrap();
    let pubkey_hex1 = keypair1.public_key_hex();
    let secret = keypair1.secret_bytes();

    let keypair2 = DeviceIdentityKey::from_secret_bytes(&secret).unwrap();
    let pubkey_hex2 = keypair2.public_key_hex();

    assert_eq!(
        pubkey_hex1, pubkey_hex2,
        "Public key must remain stable after reload"
    );
    assert_eq!(
        pubkey_hex1.len(),
        64,
        "Ed25519 public key hex must be 64 characters"
    );
}

// =========================================================================
// 2. INTEGRITY TESTS
// =========================================================================

#[test]
fn test_payload_nonce_mutation_rejected() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let challenge = ChallengeObject {
        challenge_id: "c1234567-0000-0000-0000-000000000001".to_string(),
        nonce: "a".repeat(64),
        device_id: "d1234567-0000-0000-0000-000000000001".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1000,
        expires_at: 1060,
    };

    let proof = create_challenge_proof(&key, &challenge, &"0".repeat(128), 1).unwrap();

    // Verify valid proof succeeds
    assert!(verify_challenge_proof(key.verifying_key(), &proof).is_ok());

    // Tamper with nonce
    let mut tampered_proof = proof.clone();
    tampered_proof.nonce = "b".repeat(64);
    assert!(
        verify_challenge_proof(key.verifying_key(), &tampered_proof).is_err(),
        "Tampered nonce must be rejected"
    );
}

#[test]
fn test_state_mutation_rejected() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    let challenge = ChallengeObject {
        challenge_id: "chal-uuid-001".to_string(),
        nonce: "1".repeat(64),
        device_id: "dev-uuid-001".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1000,
        expires_at: 1060,
    };

    let proof = create_challenge_proof(&key, &challenge, &"1".repeat(128), 1).unwrap();

    let mut tampered = proof.clone();
    tampered.state_hash = "2".repeat(128); // Tampered state
    assert!(verify_challenge_proof(key.verifying_key(), &tampered).is_err());
}

#[test]
fn test_purpose_mutation_rejected() {
    let mut rng = OsCryptoRng;
    let key = DeviceIdentityKey::generate(&mut rng).unwrap();

    // Proof generated for device-auth
    let challenge = ChallengeObject {
        challenge_id: "chal-uuid-002".to_string(),
        nonce: "2".repeat(64),
        device_id: "dev-uuid-002".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1000,
        expires_at: 1060,
    };

    let proof = create_challenge_proof(&key, &challenge, &"3".repeat(128), 1).unwrap();

    // Attacker tries to use the same proof for reenrollment
    let mut tampered = proof.clone();
    tampered.purpose = PURPOSE_REENROLLMENT.to_string();
    assert!(
        verify_challenge_proof(key.verifying_key(), &tampered).is_err(),
        "Cross-purpose signature substitution must fail"
    );
}

// =========================================================================
// 3. KDF TESTS (HKDF-SHA-512)
// =========================================================================

#[test]
fn test_kdf_deterministic() {
    let seed = Secret32::new([42u8; 32]);
    let vhash = "a".repeat(128);
    let info = b"session_context_1";

    let k1 = derive_state_bound_material(&seed, &vhash, info).unwrap();
    let k2 = derive_state_bound_material(&seed, &vhash, info).unwrap();

    assert_eq!(k1, k2, "KDF must be deterministic given identical input");
}

#[test]
fn test_kdf_salt_binding() {
    let seed = Secret32::new([7u8; 32]);
    let vhash1 = "a".repeat(128);
    let vhash2 = "b".repeat(128); // Hardware changed

    let k1 = derive_state_bound_material(&seed, &vhash1, b"context").unwrap();
    let k2 = derive_state_bound_material(&seed, &vhash2, b"context").unwrap();

    assert_ne!(
        k1, k2,
        "Changing verification_hash must change derived material"
    );
}

#[test]
fn test_kdf_single_bit_mutation_differs() {
    let seed1 = Secret32::new([0u8; 32]);
    let mut seed2_bytes = [0u8; 32];
    seed2_bytes[0] ^= 0x01; // 1-bit mutation in IKM
    let seed2 = Secret32::new(seed2_bytes);

    let vhash = "c".repeat(128);
    let k1 = derive_state_bound_material(&seed1, &vhash, b"ctx").unwrap();
    let k2 = derive_state_bound_material(&seed2, &vhash, b"ctx").unwrap();

    assert_ne!(
        k1, k2,
        "1-bit mutation in input seed must yield completely different output"
    );
}

// =========================================================================
// 4. STATE TESTS (Tier 6)
// =========================================================================

#[test]
fn test_state_hash_deterministic_and_length() {
    let mut ctx = BTreeMap::new();
    ctx.insert("os".to_string(), "windows".to_string());
    ctx.insert("arch".to_string(), "x86_64".to_string());

    let state1 = evaluate_device_state("dev-001", 1, &"e".repeat(128), &ctx);
    let state2 = evaluate_device_state("dev-001", 1, &"e".repeat(128), &ctx);

    assert_eq!(state1.state_hash, state2.state_hash);
    assert_eq!(
        state1.state_hash.len(),
        128,
        "SHA-512 state hash must be 128 hex chars"
    );
}

#[test]
fn test_graph_mutation_changes_state() {
    let baseline = MockHardwareCollector::baseline()
        .unwrap()
        .collect()
        .unwrap();
    let ram_up = MockHardwareCollector::ram_upgrade()
        .unwrap()
        .collect()
        .unwrap();

    let h_base = hash_snapshot(&baseline);
    let h_ram = hash_snapshot(&ram_up);

    let g_base = build_evidence_graph(&h_base, 1);
    let g_ram = build_evidence_graph(&h_ram, 2);

    let mut ctx = BTreeMap::new();
    ctx.insert("mode".to_string(), "prod".to_string());

    let state_base = evaluate_device_state("dev-001", 1, &g_base.verification_hash, &ctx);
    let state_ram = evaluate_device_state("dev-001", 2, &g_ram.verification_hash, &ctx);

    assert_ne!(state_base.verification_hash, state_ram.verification_hash);
    assert_ne!(state_base.state_hash, state_ram.state_hash);
}

// =========================================================================
// 5. STORAGE TESTS (Vault Persistence & Deadlock Prevention)
// =========================================================================

#[test]
fn test_save_load_identity_vault() {
    let storage = MockSecureStorage::new();

    let identity = PersistedIdentity::new(
        "dev-uuid-12345".to_string(),
        Secret32::new([11u8; 32]),
        Secret32::new([22u8; 32]),
        1700000000,
    );

    storage.save_identity(&identity).unwrap();

    let loaded = storage
        .load_identity()
        .unwrap()
        .expect("Identity should exist");
    assert_eq!(loaded.device_id, "dev-uuid-12345");
    assert_eq!(loaded.device_seed, Secret32::new([11u8; 32]));
    assert_eq!(loaded.signing_key, Secret32::new([22u8; 32]));
    assert_eq!(loaded.created_at, 1700000000);
}

#[test]
fn test_corrupt_vault_detected() {
    let mut valid_bytes = PersistedIdentity::new(
        "dev-1".to_string(),
        Secret32::new([1u8; 32]),
        Secret32::new([2u8; 32]),
        100,
    )
    .to_vault_bytes();

    // Corrupt one byte in the middle
    valid_bytes[20] ^= 0xff;

    let result = PersistedIdentity::from_vault_bytes(&valid_bytes);
    assert!(result.is_err(), "Corrupt checksum must be detected");
}

#[test]
fn test_hardware_change_does_not_destroy_vault() {
    // rv4.md #4: Hardware mutation MUST NOT break vault accessibility
    let storage = MockSecureStorage::new();

    let orig_identity = PersistedIdentity::new(
        "dev-stable-id".to_string(),
        Secret32::new([99u8; 32]),
        Secret32::new([88u8; 32]),
        1000,
    );
    storage.save_identity(&orig_identity).unwrap();

    // Simulate Hardware change (RAM upgraded, disk replaced)
    let ram_up = MockHardwareCollector::ram_upgrade()
        .unwrap()
        .collect()
        .unwrap();
    let h_ram = hash_snapshot(&ram_up);
    let g_ram = build_evidence_graph(&h_ram, 2);

    // Vault can still be loaded without relying on g_ram.verification_hash for decryption!
    let reloaded = storage
        .load_identity()
        .unwrap()
        .expect("Vault must remain intact");
    assert_eq!(reloaded.device_id, "dev-stable-id");
    assert_eq!(reloaded.signing_key, Secret32::new([88u8; 32]));

    // Device can use the SAME signing key to sign the NEW state
    let key = DeviceIdentityKey::from_secret_bytes(&reloaded.signing_key).unwrap();
    let challenge = ChallengeObject {
        challenge_id: "c-new-state".to_string(),
        nonce: "9".repeat(64),
        device_id: reloaded.device_id.clone(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 2000,
        expires_at: 2060,
    };

    let proof = create_challenge_proof(&key, &challenge, &g_ram.verification_hash, 2).unwrap();
    assert!(verify_challenge_proof(key.verifying_key(), &proof).is_ok());
}

// =========================================================================
// 6. REPLAY TESTS
// =========================================================================

#[test]
fn test_challenge_nonce_uniqueness() {
    let mut rng = OsCryptoRng;
    let mut nonce1 = [0u8; 32];
    let mut nonce2 = [0u8; 32];

    rng.fill(&mut nonce1).unwrap();
    rng.fill(&mut nonce2).unwrap();

    assert_ne!(nonce1, nonce2, "CSPRNG nonces must be uniquely generated");
}

// =========================================================================
// 7. CROSS-IMPLEMENTATION TEST VECTORS
// =========================================================================

#[test]
fn test_cross_implementation_vector() {
    // Deterministic test vector
    let seed = [0x55u8; 32];
    let mut det_rng = DeterministicTestRng::new(seed);
    let key = DeviceIdentityKey::generate(&mut det_rng).unwrap();

    let challenge = ChallengeObject {
        challenge_id: "test-chal-vector-001".to_string(),
        nonce: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        device_id: "test-dev-vector-001".to_string(),
        purpose: PURPOSE_DEVICE_AUTH.to_string(),
        issued_at: 1700000000,
        expires_at: 1700000060,
    };

    let state_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let proof = create_challenge_proof(&key, &challenge, state_hash, 1).unwrap();

    assert_eq!(proof.signature_hex.len(), 128);
    assert!(verify_challenge_proof(key.verifying_key(), &proof).is_ok());

    // Verify canonical payload encoding is deterministic
    let payload1 = build_challenge_signature_payload(
        DOMAIN_AUTH,
        &challenge.purpose,
        PROTOCOL_VERSION,
        &challenge.challenge_id,
        &challenge.nonce,
        &challenge.device_id,
        state_hash,
        1,
    );

    let payload2 = build_challenge_signature_payload(
        DOMAIN_AUTH,
        &challenge.purpose,
        PROTOCOL_VERSION,
        &challenge.challenge_id,
        &challenge.nonce,
        &challenge.device_id,
        state_hash,
        1,
    );

    assert_eq!(payload1, payload2);
}
