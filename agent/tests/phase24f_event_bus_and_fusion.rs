//! Phase 24F: Security Event Bus & Evidence Fusion Integration Tests
//!
//! Ref: Docs/rv13.md Section 10 & Section 11:
//! Validates:
//! - Decoupled SecurityEventBus publishing and draining
//! - SecurityEvent conversion to standardized EvidenceItem
//! - Full PassiveDefenseCoordinator evaluation producing PassiveDefenseReport
//! - VirtualNodes (vnode:passive_prevention_shield, vnode:ipc_security_boundary)
//! - VirtualPoints (mitigation_score, privilege_score, driver_integrity_score, passive_defense_score)
//! - Multi-tier AssuranceLevel determination
//! - Non-destructive, decoupled fail-safe operation (no panic or premature key destruction)

use cyberv_agent::defense::passive::binary_integrity::{
    BinaryIntegrityChecker, BinaryIntegrityReport, DiskIntegrityReport, LoadedImageIntegrityReport,
    RuntimeConfigIntegrityReport,
};
use cyberv_agent::defense::passive::capability::{CapabilityMatrixReport, CapabilityProfiler};
use cyberv_agent::defense::passive::driver_integrity::{
    DriverIntegrityChecker, DriverIntegrityReport,
};
use cyberv_agent::defense::passive::event_bus::{SecurityEvent, SecurityEventBus};
use cyberv_agent::defense::passive::filesystem_acl::{
    FilesystemAclManager, FilesystemSecurityReport,
};
use cyberv_agent::defense::passive::ipc::IpcSecurityReport;
use cyberv_agent::defense::passive::network_surface::{
    NetworkSurfaceInspector, NetworkSurfaceReport,
};
use cyberv_agent::defense::passive::platform_integrity::{
    PlatformIntegrityChecker, PlatformIntegrityReport,
};
use cyberv_agent::defense::passive::privilege::{PrivilegeIsolationReport, PrivilegeManager};
use cyberv_agent::defense::passive::process_mitigations::{
    ProcessMitigationConfig, ProcessMitigationManager, ProcessMitigationStatus,
};
use cyberv_agent::defense::passive::update::UpdateIntegrityReport;
use cyberv_agent::defense::passive::{PassiveDefenseCoordinator, PassiveDefenseReport};
use cyberv_agent::evidence::unified::{EvidenceClass, EvidenceSource};
use cyberv_agent::hardware::models::Confidence;
use cyberv_agent::security::assurance::AssuranceLevel;

fn create_standard_mock_subsystem_reports() -> (
    ProcessMitigationStatus,
    PrivilegeIsolationReport,
    NetworkSurfaceReport,
    BinaryIntegrityReport,
    DriverIntegrityReport,
    IpcSecurityReport,
    FilesystemSecurityReport,
    UpdateIntegrityReport,
    PlatformIntegrityReport,
    CapabilityMatrixReport,
) {
    let mit_cfg = ProcessMitigationConfig::default();
    let mitigation = ProcessMitigationManager::apply_and_verify(&mit_cfg);
    let privilege = PrivilegeManager::inspect_and_drop_dangerous_privileges();
    let network = NetworkSurfaceInspector::audit_network_surface(vec![]);
    let binary = BinaryIntegrityChecker::evaluate(
        true,
        "valid_hash",
        "valid_hash",
        true,
        true,
        true,
        true,
        true,
    );
    let driver = DriverIntegrityChecker::verify_driver(
        DriverIntegrityChecker::EXPECTED_PUBLISHER,
        "driver_sha512",
        "driver_sha512",
        DriverIntegrityChecker::EXPECTED_VERSION,
        true,
    );
    let ipc = IpcSecurityReport::standard_hardened(r"\\.\pipe\CyberV_IPC");
    let critical_paths = [
        "C:\\ProgramData\\CyberV\\identity.vault",
        "C:\\ProgramData\\CyberV\\config.json",
    ];
    let filesystem = FilesystemAclManager::audit_critical_assets(&critical_paths, None);
    let update = UpdateIntegrityReport::verified_active();
    let platform = PlatformIntegrityChecker::evaluate(
        true,
        true,
        true,
        "pcr0_firmware_sha512",
        "pcr7_secureboot_sha512",
    );
    let capability = CapabilityProfiler::probe_system_capabilities();

    (
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    )
}

#[test]
fn test_01_security_event_bus_publish_and_drain() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::BinaryTamperDetected {
        detail: "Section .text integrity violation detected in module core.dll".to_string(),
    });
    bus.publish(SecurityEvent::IpcAuthFailed {
        client_pid: 9999,
        reason: "Untrusted PID without process token verification".to_string(),
    });

    let drained = bus.drain_events();
    assert_eq!(drained.len(), 2);

    // Draining a second time should return empty
    let drained_again = bus.drain_events();
    assert!(drained_again.is_empty());
}

#[test]
fn test_02_security_event_conversion_to_evidence_item() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::AclViolationDetected {
        path: "C:\\ProgramData\\CyberV\\identity.vault".to_string(),
    });
    bus.publish(SecurityEvent::UpdateRollbackAttempt {
        current: 5,
        target: 2,
    });
    bus.publish(SecurityEvent::MitigationDisabled {
        capability: "UserShadowStackCet".to_string(),
    });

    let evidence_items = bus.drain_as_evidence_items();
    assert_eq!(evidence_items.len(), 3);

    // Item 0: ACL Violation
    assert_eq!(evidence_items[0].evidence_type, "EVENT_ACL_VIOLATION");
    assert_eq!(
        evidence_items[0].source,
        EvidenceSource::PassiveProcessMitigation
    );
    assert_eq!(evidence_items[0].evidence_class, EvidenceClass::Structural);
    assert_eq!(evidence_items[0].confidence, Confidence::High);
    assert_eq!(evidence_items[0].score, 2500);

    // Item 1: Rollback Attempt
    assert_eq!(evidence_items[1].evidence_type, "EVENT_UPDATE_ROLLBACK");
    assert_eq!(evidence_items[1].score, 0);

    // Item 2: Mitigation Disabled
    assert_eq!(evidence_items[2].evidence_type, "EVENT_MITIGATION_DISABLED");
    assert_eq!(evidence_items[2].score, 3000);
}

#[test]
fn test_03_driver_and_privilege_events_evidence_structure() {
    let ev_driver = SecurityEvent::DriverUnexpected {
        reason: "Unsigned kernel binary attempted load".to_string(),
    };
    let item_drv = ev_driver.to_evidence_item("ev_drv_01");
    assert_eq!(item_drv.evidence_type, "EVENT_DRIVER_UNEXPECTED");
    assert_eq!(item_drv.source, EvidenceSource::KernelTamperResistance);
    assert_eq!(item_drv.evidence_class, EvidenceClass::Platform);
    assert_eq!(item_drv.score, 1000);

    let ev_priv = SecurityEvent::PrivilegePresent {
        privilege: "SeDebugPrivilege".to_string(),
    };
    let item_priv = ev_priv.to_evidence_item("ev_priv_01");
    assert_eq!(item_priv.evidence_type, "EVENT_PRIVILEGE_PRESENT");
    assert_eq!(item_priv.evidence_class, EvidenceClass::Behavioral);
    assert_eq!(item_priv.score, 4000);
}

#[test]
fn test_04_passive_defense_coordinator_evaluate_all_full_score() {
    let (
        mitigation,
        privilege,
        network,
        binary,
        driver,
        ipc,
        filesystem,
        update,
        platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    assert_eq!(report.composite_passive_score, 10000);
    assert_eq!(report.assurance, AssuranceLevel::HardwareBacked);
    assert_eq!(report.confidence, 10000);
    assert!(report.summary.contains("Score=10000/10000"));
}

#[test]
fn test_05_passive_defense_virtual_nodes_generated() {
    let (
        mitigation,
        privilege,
        network,
        binary,
        driver,
        ipc,
        filesystem,
        update,
        platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    // Must have exactly 2 virtual nodes
    assert_eq!(report.virtual_nodes.len(), 2);

    let vnode_shield = report
        .virtual_nodes
        .iter()
        .find(|n| n.id == "vnode:passive_prevention_shield")
        .expect("Shield vnode must exist");
    assert_eq!(vnode_shield.virtual_type, "PASSIVE_PREVENTION_SHIELD");
    assert_eq!(vnode_shield.attributes.get("acg_active").unwrap(), "true");
    assert_eq!(
        vnode_shield.attributes.get("least_privilege").unwrap(),
        "true"
    );
    assert_eq!(vnode_shield.attributes.get("driver_valid").unwrap(), "true");

    let vnode_ipc = report
        .virtual_nodes
        .iter()
        .find(|n| n.id == "vnode:ipc_security_boundary")
        .expect("IPC vnode must exist");
    assert_eq!(vnode_ipc.virtual_type, "IPC_SECURITY_BOUNDARY");
    assert_eq!(vnode_ipc.attributes.get("pipe_hardened").unwrap(), "true");
    assert_eq!(vnode_ipc.attributes.get("schema_bounded").unwrap(), "true");
}

#[test]
fn test_06_passive_defense_virtual_points_generated() {
    let (
        mitigation,
        privilege,
        network,
        binary,
        driver,
        ipc,
        filesystem,
        update,
        platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    assert_eq!(report.virtual_points.len(), 5);

    let pt_mit = report
        .virtual_points
        .iter()
        .find(|p| p.id == "point:mitigation_score")
        .unwrap();
    assert_eq!(pt_mit.value, 10000);
    assert_eq!(pt_mit.scale, 10000);

    let pt_drv = report
        .virtual_points
        .iter()
        .find(|p| p.id == "point:driver_integrity_score")
        .unwrap();
    assert_eq!(pt_drv.value, 10000);

    let pt_pass = report
        .virtual_points
        .iter()
        .find(|p| p.id == "point:passive_defense_score")
        .unwrap();
    assert_eq!(pt_pass.value, 10000);
}

#[test]
fn test_07_assurance_level_fallback_when_compromised() {
    let (
        mut mitigation,
        privilege,
        network,
        _,
        driver,
        ipc,
        filesystem,
        update,
        platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    mitigation.is_acg_active = false;
    mitigation.mitigation_score = 4000;

    // Degraded binary integrity
    let binary = BinaryIntegrityReport {
        disk: DiskIntegrityReport {
            authenticode_valid: false,
            file_sha512: "tampered".to_string(),
            expected_sha512: "expected".to_string(),
            is_disk_intact: false,
        },
        loaded_image: LoadedImageIntegrityReport {
            pe_sections_intact: false,
            iat_unhooked: false,
            text_section_r_x_only: false,
            is_loaded_image_intact: false,
        },
        runtime_config: RuntimeConfigIntegrityReport {
            acg_enforced: false,
            driver_connected: true,
            is_runtime_config_intact: false,
        },
        binary_integrity_score: 2000,
        summary: "Binary integrity degraded".to_string(),
    };

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    // Score is lower than 8000, falls back from HardwareBacked to OSProtected or Software
    assert!(report.composite_passive_score < 8000);
    assert_ne!(report.assurance, AssuranceLevel::HardwareBacked);
}

#[test]
fn test_08_assurance_software_when_severely_degraded() {
    let (
        mut mitigation,
        mut privilege,
        mut network,
        _,
        mut driver,
        mut ipc,
        mut filesystem,
        mut update,
        mut platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    mitigation.mitigation_score = 1000;
    privilege.privilege_score = 1000;
    network.network_surface_score = 1000;

    let binary = BinaryIntegrityReport {
        disk: DiskIntegrityReport {
            authenticode_valid: false,
            file_sha512: "bad".to_string(),
            expected_sha512: "exp".to_string(),
            is_disk_intact: false,
        },
        loaded_image: LoadedImageIntegrityReport {
            pe_sections_intact: false,
            iat_unhooked: false,
            text_section_r_x_only: false,
            is_loaded_image_intact: false,
        },
        runtime_config: RuntimeConfigIntegrityReport {
            acg_enforced: false,
            driver_connected: false,
            is_runtime_config_intact: false,
        },
        binary_integrity_score: 1000,
        summary: "Severely degraded".to_string(),
    };

    driver.driver_integrity_score = 1000;
    driver.is_signer_valid = false;
    ipc.ipc_score = 1000;
    filesystem.acl_score = 1000;
    update.update_score = 1000;
    platform.platform_score = 1000;
    platform.is_measured_boot_active = false;

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    assert!(report.composite_passive_score < 5000);
    assert_eq!(report.assurance, AssuranceLevel::Software);
}

#[test]
fn test_09_passive_defense_report_json_serde_roundtrip() {
    let (
        mitigation,
        privilege,
        network,
        binary,
        driver,
        ipc,
        filesystem,
        update,
        platform,
        capability,
    ) = create_standard_mock_subsystem_reports();

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    let serialized = serde_json::to_string(&report).expect("Must serialize to JSON");
    let deserialized: PassiveDefenseReport =
        serde_json::from_str(&serialized).expect("Must deserialize from JSON");

    assert_eq!(report, deserialized);
}

#[test]
fn test_10_decoupled_fail_safe_no_direct_destruction() {
    // Crucial rule: Passive detection does NOT unilaterally isolate or destroy keys.
    // Instead, events flow cleanly into SecurityEventBus without panics or uncoordinated side-effects.
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::BinaryTamperDetected {
        detail: "Memory page 0x7FFF0000 altered".to_string(),
    });

    let items = bus.drain_as_evidence_items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].evidence_type, "EVENT_BINARY_TAMPER");
    // EvidenceItem is ready for policy fusion evaluation, no key destruction occurred.
}
