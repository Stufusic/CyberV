//! CyberV Phase 11: TPM 2.0 Hardware Root of Trust & Platform Attestation Tests (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! TPM Detection, Capabilities, Hardware-backed Keys, Non-exportability,
//! PCR Policies (PCR 7, PCR 0/2/7), Measured Boot, TPM Quotes, Replay Protection,
//! Platform Transition Recovery, and Hybrid Identity Assurance Scoring.

use cyberv_agent::identity::rng::OsCryptoRng;
use cyberv_agent::identity::DeviceIdentityKey;
use cyberv_agent::trust::identity::{
    AssuranceLevel, HardwareIdentity, HybridDeviceIdentity, SoftwareIdentity,
};
use cyberv_agent::trust::platform::{
    BootConfigurationLog, BootLogEntry, PlatformMeasurement, PlatformTrustState, SecureBootStatus,
    TpmRecoveryHandler,
};
use cyberv_agent::trust::tpm::{
    HashAlgorithm, MockTpmDetector, MockTpmProvider, PcrBank, PcrPolicy, TpmDetector, TpmError,
    TpmProvider, TpmStatus,
};

#[test]
fn test_01_tpm_present_detection() {
    let detector = MockTpmDetector::present("INTC");
    let caps = detector.detect();

    assert!(caps.present);
    assert_eq!(caps.status, TpmStatus::TpmPresent);
    assert_eq!(caps.version, Some("2.0".to_string()));
    assert_eq!(caps.manufacturer, Some("INTC".to_string()));
    assert!(caps.supports_key_storage);
    assert!(caps.supports_attestation);
    assert!(caps.supports_pcr_quote);
}

#[test]
fn test_02_tpm_unavailable_graceful_fallback() {
    let detector = MockTpmDetector::unavailable();
    let caps = detector.detect();

    assert!(!caps.present);
    assert_eq!(caps.status, TpmStatus::TpmUnavailable);
    assert_eq!(caps.version, None);
    assert!(!caps.supports_key_storage);
    assert!(!caps.supports_attestation);
}

#[test]
fn test_03_tpm_degraded_capability_handling() {
    let detector = MockTpmDetector::degraded("AMD", "Attestation subsystem locked");
    let caps = detector.detect();

    assert!(caps.present);
    assert_eq!(caps.status, TpmStatus::TpmDegraded);
    assert!(caps.supports_key_storage);
    assert!(
        !caps.supports_attestation,
        "Degraded TPM không hỗ trợ attestation"
    );
}

#[test]
fn test_04_hardware_backed_key_generation() {
    let mut provider = MockTpmProvider::new_standard("INTC");
    let key = provider
        .generate_key("device-identity-key-01")
        .expect("Tạo khóa TPM thành công");

    assert!(key.key_reference.starts_with("tpm://"));
    assert_eq!(key.public_key_hex.len(), 64);
    assert!(key.is_hardware_backed);
    assert!(!key.is_exportable);

    // Ký thử thông điệp qua TPM key
    let data = b"CYBERV_ATTESTATION_CHALLENGE_PAYLOAD";
    let sig_hex = key.sign(data).expect("Ký qua TPM thành công");
    assert_eq!(sig_hex.len(), 128); // Ed25519 signature hex
}

#[test]
fn test_05_key_non_exportability_invariant() {
    let mut provider = MockTpmProvider::new_standard("MSFT");
    let key = provider
        .generate_key("device-identity-key-02")
        .expect("Tạo khóa TPM thành công");

    // Khóa phải thỏa mãn bất biến: hardware_backed == true và exportable == false
    assert!(key.assert_hardware_protection().is_ok());

    let mut forged_key = key.clone();
    forged_key.is_exportable = true; // Thử phá vỡ bất biến
    assert!(forged_key.assert_hardware_protection().is_err());
}

#[test]
fn test_06_secure_boot_pcr7_policy_evaluation() {
    let policy = PcrPolicy::secure_boot_policy();
    assert_eq!(policy.required_pcrs, vec![7]);
    assert_eq!(policy.policy_id, "SecureBootPolicy-v1");

    let mut pcr_bank = PcrBank::new(HashAlgorithm::Sha512);
    pcr_bank.set_pcr(
        7,
        "7777777777777777777777777777777777777777777777777777777777777777",
    );

    let digest1 = policy
        .compute_composite_digest(&pcr_bank)
        .expect("Tính composite digest PCR 7");
    let digest2 = policy
        .compute_composite_digest(&pcr_bank)
        .expect("Tính composite digest PCR 7 lần 2");

    assert_eq!(digest1, digest2, "Tính toán phải tất định 100%");
    assert_eq!(digest1.len(), 128); // SHA-512 hex
}

#[test]
fn test_07_measured_boot_pcr_0_2_7_policy_evaluation() {
    let policy = PcrPolicy::measured_boot_policy();
    assert_eq!(policy.required_pcrs, vec![0, 2, 7]);

    let mut pcr_bank = PcrBank::new(HashAlgorithm::Sha512);
    pcr_bank.set_pcr(
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    pcr_bank.set_pcr(
        2,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    pcr_bank.set_pcr(
        7,
        "7777777777777777777777777777777777777777777777777777777777777777",
    );

    let digest = policy.compute_composite_digest(&pcr_bank).unwrap();
    assert_eq!(digest.len(), 128);

    // Nếu thiếu 1 PCR trong policy thì phải báo lỗi
    let mut incomplete_bank = pcr_bank.clone();
    incomplete_bank.values.remove(&2);
    assert!(policy.compute_composite_digest(&incomplete_bank).is_err());
}

#[test]
fn test_08_tpm_attestation_quote_generation_and_verification() {
    let mut provider = MockTpmProvider::new_standard("INTC");
    let key = provider.generate_key("device-key-test").unwrap();
    let policy = PcrPolicy::measured_boot_policy();
    let pcr_bank = provider.read_pcr_bank(&policy).unwrap();

    let device_id = "device-cyberv-tpm-001";
    let nonce = "challenge-nonce-random-8888";
    let timestamp = 1757077200;

    let quote = provider
        .generate_quote(device_id, nonce, &policy, timestamp, &key)
        .expect("Sinh TPM Quote thành công");

    // Xác minh quote hợp lệ
    let verify_res = quote.verify(nonce, device_id, &policy, &pcr_bank);
    assert!(verify_res.is_ok());
    assert!(verify_res.unwrap());
}

#[test]
fn test_09_tpm_quote_replay_nonce_mismatch_rejected() {
    let mut provider = MockTpmProvider::new_standard("INTC");
    let key = provider.generate_key("device-key-test").unwrap();
    let policy = PcrPolicy::measured_boot_policy();
    let pcr_bank = provider.read_pcr_bank(&policy).unwrap();

    let device_id = "device-cyberv-tpm-001";
    let original_nonce = "challenge-nonce-001";
    let quote = provider
        .generate_quote(device_id, original_nonce, &policy, 1757077200, &key)
        .unwrap();

    // Server kiểm tra với nonce khác (Replay attack)
    let bad_nonce = "challenge-nonce-999";
    let verify_res = quote.verify(bad_nonce, device_id, &policy, &pcr_bank);

    assert_eq!(verify_res.err(), Some(TpmError::NonceMismatch));
}

#[test]
fn test_10_tpm_quote_device_id_tampering_rejected() {
    let mut provider = MockTpmProvider::new_standard("INTC");
    let key = provider.generate_key("device-key-test").unwrap();
    let policy = PcrPolicy::measured_boot_policy();
    let pcr_bank = provider.read_pcr_bank(&policy).unwrap();

    let device_id = "device-victim-001";
    let nonce = "challenge-nonce-001";
    let quote = provider
        .generate_quote(device_id, nonce, &policy, 1757077200, &key)
        .unwrap();

    // Server kiểm tra cho device khác
    let attacker_device_id = "device-attacker-002";
    let verify_res = quote.verify(nonce, attacker_device_id, &policy, &pcr_bank);

    assert!(matches!(
        verify_res.err(),
        Some(TpmError::QuoteVerificationFailed(_))
    ));
}

#[test]
fn test_11_tpm_quote_pcr_digest_mutation_rejected() {
    let mut provider = MockTpmProvider::new_standard("INTC");
    let key = provider.generate_key("device-key-test").unwrap();
    let policy = PcrPolicy::measured_boot_policy();

    let device_id = "device-cyberv-001";
    let nonce = "challenge-nonce-001";
    let quote = provider
        .generate_quote(device_id, nonce, &policy, 1757077200, &key)
        .unwrap();

    // Ngân hàng PCR ở thời điểm xác minh bị sai lệch (Firmware bị đổi)
    let mut mutated_bank = provider.read_pcr_bank(&policy).unwrap();
    mutated_bank.set_pcr(
        0,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );

    let verify_res = quote.verify(nonce, device_id, &policy, &mutated_bank);
    assert!(matches!(
        verify_res.err(),
        Some(TpmError::PcrMismatch { .. })
    ));
}

#[test]
fn test_12_measured_boot_log_parsing_and_verification() {
    let entries = vec![
        BootLogEntry {
            pcr_index: 0,
            event_type: "EV_S_CRTM_VERSION".to_string(),
            digest_hex: "01020304".to_string(),
        },
        BootLogEntry {
            pcr_index: 2,
            event_type: "EV_EFI_BOOT_SERVICES_DRIVER".to_string(),
            digest_hex: "05060708".to_string(),
        },
    ];

    let log = BootConfigurationLog::new(entries);
    assert_eq!(log.composite_digest.len(), 128); // SHA-512 hex

    let policy = PcrPolicy::measured_boot_policy();
    let mut pcr_bank = PcrBank::new(HashAlgorithm::Sha512);
    pcr_bank.set_pcr(0, "00");
    pcr_bank.set_pcr(2, "02");
    pcr_bank.set_pcr(7, "07");

    let measurement =
        PlatformMeasurement::collect(&policy, &pcr_bank, &log, SecureBootStatus::Enabled)
            .expect("Thu thập PlatformMeasurement thành công");

    assert!(measurement.secure_boot);
    assert_eq!(measurement.boot_log_digest, log.composite_digest);
}

#[test]
fn test_13_platform_transition_authorized_firmware_update() {
    let old_pcr = "pcr_digest_version_1.0";
    let new_pcr = "pcr_digest_version_2.0";

    // Kịch bản: Cập nhật BIOS được IT Admin phê duyệt trước
    let authorized = true;
    let transition_res =
        TpmRecoveryHandler::validate_firmware_transition(new_pcr, old_pcr, authorized);

    assert!(transition_res.is_ok());
    assert!(transition_res.unwrap());
}

#[test]
fn test_14_platform_transition_unauthorized_firmware_tamper() {
    let old_pcr = "pcr_digest_version_1.0";
    let tampered_pcr = "pcr_digest_malicious_uefi_rootkit";

    // Kịch bản: BIOS bị ghi đè rootkit không có chứng thực
    let authorized = false;
    let transition_res =
        TpmRecoveryHandler::validate_firmware_transition(tampered_pcr, old_pcr, authorized);

    assert!(matches!(
        transition_res.err(),
        Some(TpmError::PlatformTransitionRejected(_))
    ));
}

#[test]
fn test_15_hybrid_device_identity_assurance_scoring() {
    // 1. Trường hợp có phần cứng TPM
    let mut provider = MockTpmProvider::new_standard("INTC");
    let tpm_key = provider.generate_key("hw-key-1").unwrap();
    let hw_identity = HybridDeviceIdentity::Hardware(HardwareIdentity::new(tpm_key));

    assert!(hw_identity.is_hardware_backed());
    assert_eq!(hw_identity.assurance_level(), AssuranceLevel::HardwareTpm);
    assert_eq!(hw_identity.assurance_level().score(), 10000);

    // Đánh giá Platform Trust State với TPM + SecureBoot
    let state_tpm = PlatformTrustState::evaluate(
        TpmStatus::TpmPresent,
        SecureBootStatus::Enabled,
        Some(PlatformMeasurement {
            pcr_digest: "pcr".to_string(),
            boot_log_digest: "log".to_string(),
            secure_boot: true,
            policy_version: 1,
        }),
    );
    assert_eq!(state_tpm.assurance_score, 10000);

    // 2. Trường hợp máy không có TPM (Fallback tiêu dùng)
    let mut rng = OsCryptoRng;
    let sw_key = DeviceIdentityKey::generate(&mut rng).unwrap();
    let sw_identity = HybridDeviceIdentity::Software(SoftwareIdentity::new(sw_key));

    assert!(!sw_identity.is_hardware_backed());
    assert_eq!(sw_identity.assurance_level(), AssuranceLevel::SoftwareVault);
    assert_eq!(sw_identity.assurance_level().score(), 6000);

    let state_sw =
        PlatformTrustState::evaluate(TpmStatus::TpmUnavailable, SecureBootStatus::Unknown, None);
    assert_eq!(state_sw.assurance_score, 3000);
}
