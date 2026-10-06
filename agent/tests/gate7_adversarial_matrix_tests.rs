//! Gate 7: Adversarial Matrix Expansion Tests
//!
//! Ref: Docs/GATE0_SECURITY_CONTRACT_FREEZE.md & Docs/INVARIANTS.md:
//! - INV-001 (Fail-Closed Enforcement)
//! - INV-002 (Evidence Corroboration & Zero-Match Honesty)
//! - INV-007 (Simulation/Fallback Honesty)
//! - 5-State Taxonomy: PHYSICAL, VIRTUAL, UNKNOWN, UNAVAILABLE, CONFLICTED
//! - Evidence Confidence Matrix Bounds

use cyberv_agent::defense::dma::{IommuReport, PreBootDmaReport};
use cyberv_agent::defense::dma::fusion::DmaEvidenceFusionEngine;
use cyberv_agent::defense::enclave::{
    EnclaveAttestationEngine, EnclaveCapabilityMatrix,
};
use cyberv_agent::defense::firmware::boot_guard::BootGuardReport;
use cyberv_agent::defense::firmware::config::FirmwareConfigReport;
use cyberv_agent::defense::firmware::fusion::FirmwareEvidenceFusionEngine;
use cyberv_agent::defense::firmware::secure_boot::SecureBootDbReport;
use cyberv_agent::defense::firmware::smm::SmmSecurityReport;
use cyberv_agent::defense::kernel::{
    AntiTamperManager, AntiTamperReport, ProtectedProcessRegistration, ShieldTelemetry,
};
use cyberv_agent::defense::policy::{
    EvidenceSourceWeight, HardwareEvidenceState, PolicyConfig, PolicyDecision,
    SecurityPolicyEngine, MAX_CONFIDENCE_KERNEL_BUS, MAX_CONFIDENCE_MESH_QUORUM,
    MAX_CONFIDENCE_STORAGE_PNP, MAX_CONFIDENCE_TPM_QUOTE, MAX_CONFIDENCE_USER_WMI,
};
use cyberv_agent::evidence::unified::EvidenceSource;
use cyberv_agent::hardware::collector::HardwareCollector;
use cyberv_agent::hardware::mock::MockHardwareCollector;
use cyberv_agent::hardware::models::ComponentType;
use cyberv_agent::kernel::{
    CrossLayerValidator, KernelObservationPayload, KernelPciDevice, MockKernelClient,
    ValidationStatus,
};
use cyberv_agent::security::assurance::AssuranceLevel;
use cyberv_agent::security::freshness::EvidenceMetadata;

fn helper_benign_reports() -> (
    u32,
    AntiTamperReport,
    cyberv_agent::defense::dma::DmaSecurityReport,
    cyberv_agent::defense::firmware::FirmwareSecurityReport,
    cyberv_agent::defense::enclave::EnclaveAttestationReport,
) {
    let tpm_score = 10000;
    let reg = ProtectedProcessRegistration::new(1234, 1000, "nonce_gate7", 1);
    let telem = ShieldTelemetry::active(1234);
    let kernel_report = AntiTamperManager::evaluate(&reg, &telem, true);

    let iommu = IommuReport::probe();
    let preboot = PreBootDmaReport::protected();
    let dma_report = DmaEvidenceFusionEngine::evaluate(&iommu, &preboot, true, true);

    let sb = SecureBootDbReport::standard_hardened();
    let bg = BootGuardReport::intel_boot_guard_profile5();
    let smm = SmmSecurityReport::hardened();
    let cfg = FirmwareConfigReport::standard_asus();
    let fw_report = FirmwareEvidenceFusionEngine::evaluate(&sb, &bg, &smm, &cfg);

    let cap = EnclaveCapabilityMatrix::active_attested_vtl1();
    let enclave_report = EnclaveAttestationEngine::evaluate(&cap, None, None);

    (
        tpm_score,
        kernel_report,
        dma_report,
        fw_report,
        enclave_report,
    )
}

fn create_mock_pci_nvme(serial: &str) -> KernelPciDevice {
    KernelPciDevice {
        vendor_id: 0x144d, // Samsung
        device_id: 0xa80a, // 980 Pro
        subsystem_vendor_id: 0x144d,
        subsystem_device_id: 0xa801,
        segment: 0,
        bus: 1,
        device: 0,
        function: 0,
        device_class: 0x01, // Mass Storage
        serial_number: Some(serial.to_string()),
    }
}

// 1. Tấn công WMI Spoofer: Kẻ tấn công hook userland WMI để thay đổi serial đĩa.
// Kernel Probe phát hiện serial vật lý khác biệt -> Contradictory -> Policy chuyển ISOLATE + CONFLICTED.
#[test]
fn test_01_cross_layer_wmi_spoofed_forces_immediate_isolate_conflicted() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let mut snapshot = collector.collect().unwrap();

    for comp in &mut snapshot.components {
        if comp.component_type == ComponentType::Storage {
            comp.attributes
                .insert("serial".to_string(), "ATTACKER_HOOKED_WMI_SERIAL".to_string());
        }
    }

    let real_serial = "s5p2nf0r123456";
    let pci_dev = create_mock_pci_nvme(real_serial);
    let payload = KernelObservationPayload::new(1, vec![pci_dev], 1757077200);
    let kernel_client = MockKernelClient::available(payload);

    let cross_layer_report = CrossLayerValidator::validate(&snapshot, &kernel_client);
    assert!(
        matches!(cross_layer_report.status, ValidationStatus::Contradictory { .. }),
        "CrossLayerValidator phải phát hiện mâu thuẫn chéo giữa WMI và Kernel"
    );

    let (tpm_score, kernel, dma, fw, enclave) = helper_benign_reports();
    let config = PolicyConfig::default();
    let now = 1000;

    let policy_report = SecurityPolicyEngine::evaluate_with_cross_layer(
        &config,
        tpm_score,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&cross_layer_report),
        None,
        now,
    );

    match policy_report.decision {
        PolicyDecision::Isolate { reason, severity } => {
            assert!(
                reason.contains("Cross-Layer Contradiction Detected")
                    || reason.contains("Conflicted"),
                "Lý do cách ly phải chỉ rõ mâu thuẫn chéo phần cứng: {}",
                reason
            );
            assert_eq!(severity, 10000, "Mức độ nghiêm trọng của vi phạm giả mạo phần cứng phải tối đa (10000)");
        }
        _ => panic!("Chính sách bắt buộc phải ISOLATE khi phát hiện WMI Spoofer"),
    }

    assert_eq!(policy_report.composite_score, 0);
    assert_eq!(policy_report.freshness_confidence, 0);
    assert_eq!(policy_report.evidence_state, HardwareEvidenceState::Conflicted);
    assert!(policy_report.evidence_state.is_conflicted());
    assert!(!policy_report.evidence_state.is_hardware_verified());
}

// 2. Bất biến INV-002: Zero-Match Hardware Fail-Closed
// Khi kernel probe trả về danh sách trống hoặc không khớp thiết bị nào,
// hệ thống phải trả về Unknown và is_hardware_verified = false, KHÔNG được tự nhận Consistent.
#[test]
fn test_02_zero_match_hardware_fail_closed_unknown_state() {
    let collector = MockHardwareCollector::baseline().unwrap();
    let snapshot = collector.collect().unwrap();

    let empty_payload = KernelObservationPayload::new(1, Vec::new(), 1757077200);
    let kernel_client = MockKernelClient::available(empty_payload);

    let cross_layer_report = CrossLayerValidator::validate(&snapshot, &kernel_client);
    assert_eq!(
        cross_layer_report.status,
        ValidationStatus::Unknown,
        "Zero-match phải có trạng thái Unknown"
    );
    assert!(
        !cross_layer_report.is_hardware_verified,
        "INV-002: Zero-match tuyệt đối không được đánh dấu là hardware_verified"
    );
    assert_eq!(cross_layer_report.penalty, 0, "Graceful fallback không bị trừ điểm oan");
}

// 3. Ma trận Giới hạn Tin cậy Bằng chứng (Gate 0 Section 1.3)
// User-mode WMI tối đa 2000, Kernel Bus tối đa 8500, TPM tối đa 10000.
#[test]
fn test_03_evidence_confidence_scoring_matrix_bounds() {
    assert_eq!(MAX_CONFIDENCE_TPM_QUOTE, 10000);
    assert_eq!(MAX_CONFIDENCE_KERNEL_BUS, 8500);
    assert_eq!(MAX_CONFIDENCE_STORAGE_PNP, 7000);
    assert_eq!(MAX_CONFIDENCE_MESH_QUORUM, 6000);
    assert_eq!(MAX_CONFIDENCE_USER_WMI, 2000);

    assert_eq!(EvidenceSourceWeight::TpmQuote.max_confidence(), 10000);
    assert_eq!(EvidenceSourceWeight::KernelBusType0.max_confidence(), 8500);
    assert_eq!(EvidenceSourceWeight::StoragePnpDescriptor.max_confidence(), 7000);
    assert_eq!(EvidenceSourceWeight::MeshQuorumCorroboration.max_confidence(), 6000);
    assert_eq!(EvidenceSourceWeight::UserModeWmiOrRegistry.max_confidence(), 2000);

    // Bằng chứng chỉ từ WMI không thể đạt ngưỡng Allow của PolicyConfig (mặc định 8000)
    let wmi_max = EvidenceSourceWeight::UserModeWmiOrRegistry.max_confidence();
    let allow_threshold = PolicyConfig::default().allow_threshold;
    assert!(
        wmi_max < allow_threshold,
        "Bằng chứng WMI đơn thuần không bao giờ đủ điều kiện Allow"
    );
}

// 4. 5-State Taxonomy Base Confidence & Semantics
#[test]
fn test_04_hardware_evidence_5_state_taxonomy_semantics() {
    assert_eq!(HardwareEvidenceState::Physical.base_confidence(), 10000);
    assert_eq!(HardwareEvidenceState::Virtual.base_confidence(), 7500);
    assert_eq!(HardwareEvidenceState::Unavailable.base_confidence(), 5000);
    assert_eq!(HardwareEvidenceState::Unknown.base_confidence(), 0);
    assert_eq!(HardwareEvidenceState::Conflicted.base_confidence(), 0);

    assert!(HardwareEvidenceState::Physical.is_hardware_verified());
    assert!(!HardwareEvidenceState::Virtual.is_hardware_verified());
    assert!(!HardwareEvidenceState::Unknown.is_hardware_verified());
    assert!(!HardwareEvidenceState::Unavailable.is_hardware_verified());
    assert!(!HardwareEvidenceState::Conflicted.is_hardware_verified());

    assert!(HardwareEvidenceState::Conflicted.is_conflicted());
    assert!(!HardwareEvidenceState::Physical.is_conflicted());
    assert!(!HardwareEvidenceState::Virtual.is_conflicted());
    assert!(!HardwareEvidenceState::Unknown.is_conflicted());
    assert!(!HardwareEvidenceState::Unavailable.is_conflicted());
}

// 5. Tấn công Clock Manipulation & Freshness Expiration
// Khi bằng chứng hết hạn TTL hoặc thời gian nhảy lùi, độ tin cậy rơi về 0
#[test]
fn test_05_expired_or_manipulated_evidence_freshness_confidence_zero() {

    let now = 1_000_000u64;
    let ttl_secs = 60u64; // TTL 60s per Gate 0 Section 3.3
    let meta = EvidenceMetadata::new(
        now,
        Some(ttl_secs),
        EvidenceSource::TpmRootOfTrust,
        10000,
        AssuranceLevel::Attested,
        1,
    );

    // Thời điểm sau 61s: Bằng chứng đã hết hạn
    let expired_time = now + ttl_secs + 1;
    assert!(!meta.is_fresh(expired_time));
    assert_eq!(meta.effective_confidence(expired_time, 86400), 0);

    let (tpm_score, kernel, dma, fw, enclave) = helper_benign_reports();
    let config = PolicyConfig::default();

    let report = SecurityPolicyEngine::evaluate(
        &config,
        tpm_score,
        &kernel,
        &dma,
        &fw,
        &enclave,
        Some(&meta),
        expired_time,
    );

    // Vì freshness_confidence = 0, composite_score = 0 -> Phải Isolate do suy giảm nghiêm trọng
    assert_eq!(report.freshness_confidence, 0);
    assert_eq!(report.composite_score, 0);
    match report.decision {
        PolicyDecision::Isolate { reason, .. } => {
            assert!(reason.contains("Degraded") || reason.contains("Score"));
        }
        _ => panic!("Bằng chứng hết hạn hoàn toàn phải dẫn tới Isolate"),
    }
}
