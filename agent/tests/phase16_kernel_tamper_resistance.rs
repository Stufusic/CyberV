//! CyberV Phase 16: FSE-1 Kernel Tamper Resistance Tests
//!
//! Ref: Docs/rv11.md Section 2:
//! Registration integrity (PID + time + nonce), Handle telemetry (ALLOW/DENY/SUSPICIOUS),
//! Driver tampering detection (vnode:kernel_defense_degraded), Vault Shield.

use cyberv_agent::defense::kernel::{
    AntiTamperManager, HandleOperationResult, ProtectedProcessRegistration, ShieldTelemetry,
    VaultShield, VaultShieldError, KERNEL_TAMPER_DERIVATION_VERSION,
};

#[test]
fn test_01_protected_process_registration_nonce_and_timestamp() {
    let reg = ProtectedProcessRegistration::current("nonce_reg_123", 1);
    assert_eq!(reg.pid, std::process::id());
    assert!(reg.process_start_time > 0);
    assert_eq!(reg.registration_nonce, "nonce_reg_123");
    assert_eq!(reg.driver_instance_id, 1);
}

#[test]
fn test_02_registration_binding_prevents_pid_reuse() {
    let reg1 = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let reg2 = ProtectedProcessRegistration::new(1234, 2000, "nonce2", 1);

    // Cùng PID 1234 nhưng khác start_time và nonce -> Không thể mạo danh đăng ký cũ
    assert_ne!(reg1, reg2);
}

#[test]
fn test_03_active_shield_telemetry_reporting() {
    let tele = ShieldTelemetry::active(1234);
    assert!(tele.is_shield_active);
    assert_eq!(tele.protected_pid, 1234);
    assert_eq!(tele.total_blocked(), 0);
    assert!(!tele.has_tampering_attempts());
}

#[test]
fn test_04_tampering_attempts_lower_defense_score() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let mut tele = ShieldTelemetry::active(1234);
    tele.blocked_terminations = 2; // Bị cố tình kill 2 lần
    tele.blocked_vm_reads = 1; // Bị cố tình đọc RAM 1 lần

    let report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert!(report.is_tampering_detected);
    assert!(report.defense_score < 10000);
    assert!(report.defense_score >= 5000);
}

#[test]
fn test_05_blocked_terminations_recorded_in_graph_node() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let mut tele = ShieldTelemetry::active(1234);
    tele.blocked_terminations = 5;

    let report = AntiTamperManager::evaluate(&reg, &tele, true);
    let node = report
        .virtual_nodes
        .iter()
        .find(|n| n.id == "vnode:process_tamper_attempt");
    assert!(node.is_some());
    let vnode = node.unwrap();
    assert_eq!(vnode.attributes.get("blocked_terminations").unwrap(), "5");
    assert_eq!(vnode.attributes.get("tamper_alert").unwrap(), "true");
}

#[test]
fn test_06_driver_unload_attempt_heavily_penalized() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let mut tele = ShieldTelemetry::active(1234);
    tele.driver_unload_attempts = 1; // Kẻ tấn công cố tình unload driver

    let report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert!(report.is_tampering_detected);
    assert!(
        report.defense_score <= 8000,
        "Cố tình unload driver phải bị trừ điểm nặng"
    );
}

#[test]
fn test_07_driver_unreachable_emits_degraded_vnode() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let tele = ShieldTelemetry::inactive();

    // Driver bị gỡ bỏ hoặc dịch vụ bị dừng (driver_reachable = false)
    let report = AntiTamperManager::evaluate(&reg, &tele, false);
    assert!(report.is_tampering_detected);
    assert_eq!(report.defense_score, 3000);

    let degraded_node = report
        .virtual_nodes
        .iter()
        .find(|n| n.id == "vnode:kernel_defense_degraded");
    assert!(
        degraded_node.is_some(),
        "Phải sinh ra vnode:kernel_defense_degraded khi driver mất kết nối"
    );
}

#[test]
fn test_08_driver_tamper_alert_attribute_set() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let tele = ShieldTelemetry::inactive();

    let report = AntiTamperManager::evaluate(&reg, &tele, false);
    let vnode = &report.virtual_nodes[0];
    assert_eq!(vnode.attributes.get("tamper_alert").unwrap(), "true");
}

#[test]
fn test_09_virtual_point_reflects_tamper_resistance_score() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let tele = ShieldTelemetry::active(1234);

    let report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert_eq!(report.virtual_points.len(), 1);
    let point = &report.virtual_points[0];
    assert_eq!(point.id, "point:kernel_tamper_resistance");
    assert_eq!(point.value, 10000);
    assert_eq!(point.scale, 10000);
    assert_eq!(point.derivation_version, KERNEL_TAMPER_DERIVATION_VERSION);
}

#[test]
fn test_10_vault_shield_initial_baseline_lock() {
    let temp_dir = std::env::temp_dir();
    let test_vault_file = temp_dir.join("cyberv_test_vault_initial.bin");
    std::fs::write(&test_vault_file, b"vault_secret_keys_content_v1").unwrap();

    let mut shield = VaultShield::new(&test_vault_file);
    let commitment = shield.lock_baseline().unwrap();
    assert_eq!(commitment.len(), 128); // SHA-512 hex

    // Kiểm tra tính toàn vẹn ngay sau khi khóa -> Hợp lệ
    assert!(shield.verify_integrity().unwrap());

    // Dọn dẹp
    let _ = std::fs::remove_file(test_vault_file);
}

#[test]
fn test_11_vault_shield_tampering_detected() {
    let temp_dir = std::env::temp_dir();
    let test_vault_file = temp_dir.join("cyberv_test_vault_tampered.bin");
    std::fs::write(&test_vault_file, b"legitimate_original_vault").unwrap();

    let mut shield = VaultShield::new(&test_vault_file);
    shield.lock_baseline().unwrap();

    // Giả lập hacker sửa đổi file vault trên đĩa
    std::fs::write(&test_vault_file, b"hacked_tampered_vault_file").unwrap();

    let result = shield.verify_integrity();
    assert!(matches!(
        result,
        Err(VaultShieldError::IntegrityViolation { .. })
    ));

    let _ = std::fs::remove_file(test_vault_file);
}

#[test]
fn test_12_vault_shield_missing_file_error() {
    let shield = VaultShield::new("non_existent_vault_path_987654.bin");
    let result = shield.compute_file_commitment();
    assert!(matches!(result, Err(VaultShieldError::NotFound(_))));
}

#[test]
fn test_13_clean_state_produces_maximum_score_10000() {
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce1", 1);
    let tele = ShieldTelemetry::active(1234);

    let report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert!(!report.is_tampering_detected);
    assert_eq!(report.defense_score, 10000);
    assert!(report.summary.contains("ổn định"));
}

#[test]
fn test_14_handle_operation_results_classification() {
    let allow = HandleOperationResult::Allow;
    let deny = HandleOperationResult::Deny;
    let suspicious = HandleOperationResult::Suspicious;
    let unknown = HandleOperationResult::Unknown;

    assert_ne!(allow, deny);
    assert_ne!(suspicious, unknown);
}

#[test]
fn test_15_end_to_end_kernel_tamper_resistance_lifecycle() {
    let reg = ProtectedProcessRegistration::current("challenge_nonce_phase16", 1);
    let mut tele = ShieldTelemetry::active(reg.pid);

    // Ban đầu bình thường
    let mut report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert_eq!(report.defense_score, 10000);

    // Kẻ gian thử tấn công kill process
    tele.blocked_terminations = 1;
    report = AntiTamperManager::evaluate(&reg, &tele, true);
    assert!(report.is_tampering_detected);
    assert_eq!(report.defense_score, 9500);

    // Kẻ gian cố tình tắt driver (điểm rơi xuống 3000 - 500 = 2500)
    report = AntiTamperManager::evaluate(&reg, &tele, false);
    assert_eq!(report.defense_score, 2500);
    assert_eq!(report.virtual_nodes[0].id, "vnode:kernel_defense_degraded");
}
