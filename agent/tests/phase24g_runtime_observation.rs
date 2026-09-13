//! Phase 24G: Runtime Integrity Observation Tests (Phase 24.1)
//!
//! Ref: Docs/rv14.md:
//! Validates:
//! - Group A: Synthetic & Preamble Baseline (Tests 01 - 08)
//! - Group B: Memory State Observation (Tests 09 - 16)
//! - Group C: Debug & Thread Context Evidence (Tests 17 - 24)
//! - Group D: Freshness, Lifecycle & EDR Coexistence (Tests 25 - 31)
//! - Group E: Separation of Observation and Response & Event Bus (Tests 32 - 37)

use cyberv_agent::defense::passive::debug::{
    DebugSignalConfidence, DebugStateAssessment, DebugStateAuditor,
};
use cyberv_agent::defense::passive::event_bus::{EventSeverity, SecurityEvent, SecurityEventBus};
use cyberv_agent::defense::passive::memory::{
    AnomalySignalStrength, MemoryAnomalyClass, MemoryObservationReport, MemoryStateAuditor,
    MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
};
use cyberv_agent::defense::passive::runtime_freshness::{EvidenceFreshness, FreshnessState};
use cyberv_agent::defense::passive::runtime_guard::RuntimeIntegrityObserver;
use cyberv_agent::defense::passive::syscall::{
    BaselineLifecycleManager, BaselineRefreshResult, HookAssessment, NtdllBaseline,
    NtdllIntegrityAnalyzer, NtdllObservationReport, StubIntegrityChecker, StubVariantAssessment,
};
use cyberv_agent::defense::passive::{
    PassiveDefenseCoordinator, PassiveDefenseReport, REPORT_SCHEMA_VERSION_CURRENT,
};
use cyberv_agent::evidence::unified::{EvidenceClass, EvidenceSource};

// ============================================================================
// Group A: Synthetic & Preamble Baseline (Tests 01 - 08)
// ============================================================================

#[test]
fn test_01_standard_ntdll_baseline_creation() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash_dummy");
    assert_eq!(baseline.os_build, 22631);
    assert_eq!(baseline.architecture, "x86_64");
    assert_eq!(baseline.approved_preambles.len(), 2);
}

#[test]
fn test_02_stub_integrity_known_good_standard_x64() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    // mov r10, rcx; mov eax, 0x18 (NtAllocateVirtualMemory on Win11)
    let stub = [
        0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    ];
    let assessment = StubIntegrityChecker::assess_stub(&stub, &baseline);
    assert_eq!(assessment, StubVariantAssessment::KnownGood { ssn: 0x18 });
}

#[test]
fn test_03_stub_integrity_expected_variant_mov_eax_first() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    // mov eax, 0x24; mov r10, rcx
    let stub = [0xB8, 0x24, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1];
    let assessment = StubIntegrityChecker::assess_stub(&stub, &baseline);
    assert_eq!(
        assessment,
        StubVariantAssessment::ExpectedVariant {
            ssn: 0x24,
            variant_name: "MovEaxFirstVariant".to_string()
        }
    );
}

#[test]
fn test_04_stub_integrity_unexpected_corrupted_preamble() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    let garbage_stub = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
    let assessment = StubIntegrityChecker::assess_stub(&garbage_stub, &baseline);
    assert!(matches!(
        assessment,
        StubVariantAssessment::Unexpected { .. }
    ));
}

#[test]
fn test_05_hook_detector_clean_in_module() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    let stub = [0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00];
    let obs =
        NtdllIntegrityAnalyzer::analyze_function("NtOpenProcess", &stub, true, None, &baseline);
    assert_eq!(obs.hook_assessment, HookAssessment::Clean);
    assert!(obs.is_within_ntdll_range);
}

#[test]
fn test_06_hook_detector_suspected_jmp_rel32_detour() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    // E9 00 10 00 00 -> JMP +0x1000 outside ntdll
    let hooked_stub = [0xE9, 0x00, 0x10, 0x00, 0x00, 0x90, 0x90, 0x90];
    let obs = NtdllIntegrityAnalyzer::analyze_function(
        "NtOpenProcess",
        &hooked_stub,
        false, // target is outside ntdll!
        None,
        &baseline,
    );
    assert_eq!(
        obs.hook_assessment,
        HookAssessment::Suspected {
            detour_type: "JmpRel32OutsideModule".to_string(),
            target_displacement: 0x1000,
        }
    );
}

#[test]
fn test_07_hook_detector_suspected_indirect_rip_relative_jmp() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    // FF 25 00 20 00 00 -> JMP qword ptr [rip + 0x2000]
    let hooked_stub = [0xFF, 0x25, 0x00, 0x20, 0x00, 0x00, 0x90, 0x90];
    let obs = NtdllIntegrityAnalyzer::analyze_function(
        "NtAllocateVirtualMemory",
        &hooked_stub,
        false,
        None,
        &baseline,
    );
    assert_eq!(
        obs.hook_assessment,
        HookAssessment::Suspected {
            detour_type: "IndirectRipRelativeJmp".to_string(),
            target_displacement: 0,
        }
    );
}

#[test]
fn test_08_hook_detector_suspected_mov_rax_jmp_rax() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    // 48 B8 [8 bytes addr] FF E0
    let hooked_stub = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
    ];
    let obs = NtdllIntegrityAnalyzer::analyze_function(
        "NtProtectVirtualMemory",
        &hooked_stub,
        false,
        None,
        &baseline,
    );
    assert_eq!(
        obs.hook_assessment,
        HookAssessment::Suspected {
            detour_type: "MovRaxImm64JmpRax".to_string(),
            target_displacement: 0,
        }
    );
}

// ============================================================================
// Group B: Memory State Observation (Tests 09 - 16)
// ============================================================================

#[test]
fn test_09_memory_state_clean_image_mapping() {
    let obs = MemoryStateAuditor::assess_region(
        0x1000,
        0x20000,
        PAGE_EXECUTE_READ,
        MEM_IMAGE,
        1700000000,
    );
    assert_eq!(obs.anomaly_class, None);
    assert_eq!(obs.signal_strength, None);
    assert_eq!(obs.region_base_offset, 0x1000);
}

#[test]
fn test_10_memory_state_detects_rwx_violation_high_signal() {
    let obs = MemoryStateAuditor::assess_region(
        0x4000,
        0x1000,
        PAGE_EXECUTE_READWRITE, // RWX!
        MEM_PRIVATE,
        1700000000,
    );
    assert_eq!(obs.anomaly_class, Some(MemoryAnomalyClass::RwxRegion));
    assert_eq!(obs.signal_strength, Some(AnomalySignalStrength::High));
}

#[test]
fn test_11_memory_state_detects_writecopy_rwx_violation() {
    let obs = MemoryStateAuditor::assess_region(
        0x5000,
        0x1000,
        PAGE_EXECUTE_WRITECOPY,
        MEM_IMAGE,
        1700000000,
    );
    assert_eq!(obs.anomaly_class, Some(MemoryAnomalyClass::RwxRegion));
    assert_eq!(obs.signal_strength, Some(AnomalySignalStrength::High));
}

#[test]
fn test_12_memory_state_detects_private_executable_medium_signal() {
    let obs = MemoryStateAuditor::assess_region(
        0x8000,
        0x4000,
        PAGE_EXECUTE_READ,
        MEM_PRIVATE, // Private + RX (unbacked executable)
        1700000000,
    );
    assert_eq!(
        obs.anomaly_class,
        Some(MemoryAnomalyClass::ExecutablePrivateRegion)
    );
    assert_eq!(obs.signal_strength, Some(AnomalySignalStrength::Medium));
}

#[test]
fn test_13_memory_state_detects_private_execute_only() {
    let obs =
        MemoryStateAuditor::assess_region(0x9000, 0x1000, PAGE_EXECUTE, MEM_PRIVATE, 1700000000);
    assert_eq!(
        obs.anomaly_class,
        Some(MemoryAnomalyClass::ExecutablePrivateRegion)
    );
}

#[test]
fn test_14_memory_state_clean_data_pages_no_anomaly() {
    let obs = MemoryStateAuditor::assess_region(
        0x10000,
        0x8000,
        PAGE_READWRITE, // Normal heap/stack memory
        MEM_PRIVATE,
        1700000000,
    );
    assert_eq!(obs.anomaly_class, None);
}

#[test]
fn test_15_memory_state_clean_readonly_pages_no_anomaly() {
    let obs =
        MemoryStateAuditor::assess_region(0x20000, 0x4000, PAGE_READONLY, MEM_IMAGE, 1700000000);
    assert_eq!(obs.anomaly_class, None);
}

#[test]
fn test_16_memory_state_bulk_audit_report_generation() {
    let regions = vec![
        (0x1000, 0x10000, PAGE_EXECUTE_READ, MEM_IMAGE),
        (0x20000, 0x1000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE), // Anomaly 1
        (0x30000, 0x2000, PAGE_EXECUTE_READ, MEM_PRIVATE),      // Anomaly 2
        (0x40000, 0x4000, PAGE_READWRITE, MEM_PRIVATE),
    ];
    let observations = MemoryStateAuditor::audit_regions(&regions, 1700000000);
    let report = MemoryObservationReport::from_observations(observations);

    assert_eq!(report.total_scanned_regions, 4);
    assert_eq!(report.rwx_anomaly_count, 1);
    assert_eq!(report.executable_private_count, 1);
    assert!(report.summary.contains("RWX_Violations=1"));
}

// ============================================================================
// Group C: Debug & Thread Context Evidence (Tests 17 - 24)
// ============================================================================

#[test]
fn test_17_thread_context_clean_no_hardware_bp() {
    let tc = DebugStateAuditor::assess_thread_context(1001, 0, 0, 0, 0, 0, 0);
    assert!(!tc.has_hardware_breakpoint);
    assert_eq!(tc.thread_id, 1001);
}

#[test]
fn test_18_thread_context_detects_dr0_hardware_bp() {
    // DR0 has address, DR7 has bit 0 set (Local DR0 active)
    let tc = DebugStateAuditor::assess_thread_context(1001, 0x7FFE0000, 0, 0, 0, 0, 0x01);
    assert!(tc.has_hardware_breakpoint);
}

#[test]
fn test_19_thread_context_detects_dr1_hardware_bp() {
    // DR1 has address, DR7 has bit 2 set (0x04)
    let tc = DebugStateAuditor::assess_thread_context(1002, 0, 0x7FFE0010, 0, 0, 0, 0x04);
    assert!(tc.has_hardware_breakpoint);
}

#[test]
fn test_20_thread_context_detects_dr2_hardware_bp() {
    // DR2 has address, DR7 has bit 4 set (0x10)
    let tc = DebugStateAuditor::assess_thread_context(1003, 0, 0, 0x7FFE0020, 0, 0, 0x10);
    assert!(tc.has_hardware_breakpoint);
}

#[test]
fn test_21_thread_context_detects_dr3_hardware_bp() {
    // DR3 has address, DR7 has bit 6 set (0x40)
    let tc = DebugStateAuditor::assess_thread_context(1004, 0, 0, 0, 0x7FFE0030, 0, 0x40);
    assert!(tc.has_hardware_breakpoint);
}

#[test]
fn test_22_debug_auditor_no_evidence_when_clean() {
    let threads = vec![(1001, 0, 0, 0, 0, 0, 0), (1002, 0, 0, 0, 0, 0, 0)];
    let report = DebugStateAuditor::audit_process_debug_state(false, 0, &threads);
    assert_eq!(report.overall_assessment, DebugStateAssessment::NoEvidence);
    assert_eq!(report.threads_with_hardware_breakpoints, 0);
}

#[test]
fn test_23_debug_auditor_possible_instrumentation_on_peb_only() {
    let threads = vec![(1001, 0, 0, 0, 0, 0, 0)];
    // PEB.BeingDebugged = true, but no hardware BP -> PossibleInstrumentation (Low signal)
    let report = DebugStateAuditor::audit_process_debug_state(true, 0, &threads);
    assert_eq!(
        report.overall_assessment,
        DebugStateAssessment::PossibleInstrumentation
    );
    assert_eq!(report.peb_signal_confidence, DebugSignalConfidence::Low);
}

#[test]
fn test_24_debug_auditor_debug_state_detected_on_drx() {
    let threads = vec![
        (1001, 0, 0, 0, 0, 0, 0),
        (1002, 0x7FFE1000, 0, 0, 0, 0, 0x01), // HW BP active!
    ];
    let report = DebugStateAuditor::audit_process_debug_state(false, 0, &threads);
    assert_eq!(
        report.overall_assessment,
        DebugStateAssessment::DebugStateDetected
    );
    assert_eq!(report.threads_with_hardware_breakpoints, 1);
}

// ============================================================================
// Group D: Freshness, Lifecycle & EDR Coexistence (Tests 25 - 31)
// ============================================================================

#[test]
fn test_25_evidence_freshness_fresh_state() {
    let freshness = EvidenceFreshness::new(1000, 5000);
    assert_eq!(freshness.evaluate_state(2000), FreshnessState::Fresh);
    assert!(freshness.is_fresh(2000));
}

#[test]
fn test_26_evidence_freshness_stale_state() {
    let freshness = EvidenceFreshness::new(1000, 5000);
    // 1000 + 5000 = 6000. At 8000, it's stale (between 1x and 2x TTL)
    assert_eq!(freshness.evaluate_state(8000), FreshnessState::Stale);
    assert!(!freshness.is_fresh(8000));
    assert!(!freshness.is_expired(8000));
}

#[test]
fn test_27_evidence_freshness_expired_state() {
    let freshness = EvidenceFreshness::new(1000, 5000);
    // At 12000, elapsed = 11000 > 10000 (2x TTL) -> Expired
    assert_eq!(freshness.evaluate_state(12000), FreshnessState::Expired);
    assert!(freshness.is_expired(12000));
}

#[test]
fn test_28_baseline_lifecycle_legitimate_upgrade() {
    let init = NtdllBaseline::standard_windows_x64(19045, "sha512_old");
    let mut manager = BaselineLifecycleManager::new(init);

    let candidate = NtdllBaseline::standard_windows_x64(22631, "sha512_new");
    let res = manager.evaluate_and_refresh(candidate);

    assert_eq!(
        res,
        BaselineRefreshResult::UpdatedLegitimateOsUpgrade {
            old_build: 19045,
            new_build: 22631
        }
    );
    assert_eq!(manager.current().os_build, 22631);
    assert_eq!(manager.history_count(), 1);
}

#[test]
fn test_29_baseline_lifecycle_same_build_maintenance() {
    let init = NtdllBaseline::standard_windows_x64(22631, "sha512_patch1");
    let mut manager = BaselineLifecycleManager::new(init);

    let candidate = NtdllBaseline::standard_windows_x64(22631, "sha512_patch2");
    let res = manager.evaluate_and_refresh(candidate);

    assert_eq!(
        res,
        BaselineRefreshResult::ReplacedSameBuildMaintenance { build: 22631 }
    );
}

#[test]
fn test_30_baseline_lifecycle_rejects_unapproved_downgrade() {
    let init = NtdllBaseline::standard_windows_x64(22631, "sha512_current");
    let mut manager = BaselineLifecycleManager::new(init);

    let rogue_downgrade = NtdllBaseline::standard_windows_x64(19041, "sha512_old");
    let res = manager.evaluate_and_refresh(rogue_downgrade);

    assert_eq!(
        res,
        BaselineRefreshResult::RejectedUnapprovedDowngrade {
            current_build: 22631,
            target_build: 19041
        }
    );
    // Baseline is preserved
    assert_eq!(manager.current().os_build, 22631);
}

#[test]
fn test_31_hook_detector_known_edr_coexistence_not_attacker() {
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    let hooked_by_edr = [0xE9, 0x00, 0x10, 0x00, 0x00];
    let obs = NtdllIntegrityAnalyzer::analyze_function(
        "NtCreateFile",
        &hooked_by_edr,
        false,
        Some("Microsoft Defender ATP / CrowdStrike Falcon"),
        &baseline,
    );
    // Must NOT be classified as rogue attacker
    assert_eq!(
        obs.hook_assessment,
        HookAssessment::KnownSecuritySoftwareInstrumentation {
            vendor_or_module: "Microsoft Defender ATP / CrowdStrike Falcon".to_string()
        }
    );
}

// ============================================================================
// Group E: Separation of Observation and Response & Event Bus (Tests 32 - 37)
// ============================================================================

#[test]
fn test_32_runtime_detector_does_not_execute_response() {
    // CRITICAL INVARIANT: Docs/rv14.md Section 17 & 21:
    // Detection -> Event -> Evidence -> Policy
    // Cảm biến tuyệt đối không tự tiện: kill, wipe, block mạng hoặc hủy vault.
    let baseline = NtdllBaseline::standard_windows_x64(22631, "sha512_hash");
    let hooked_stub = [0xE9, 0x00, 0x10, 0x00, 0x00];
    let ntdll_obs = NtdllIntegrityAnalyzer::analyze_function(
        "NtOpenProcess",
        &hooked_stub,
        false,
        None,
        &baseline,
    );
    let ntdll_rep = NtdllObservationReport::new(22631, vec![ntdll_obs]);

    let mem_obs = MemoryStateAuditor::assess_region(
        0x1000,
        0x1000,
        PAGE_EXECUTE_READWRITE,
        MEM_PRIVATE,
        1000,
    );
    let mem_rep = MemoryObservationReport::from_observations(vec![mem_obs]);

    let threads = vec![(1001, 0x7FFE0000, 0, 0, 0, 0, 0x01)];
    let dbg_rep = DebugStateAuditor::audit_process_debug_state(false, 0, &threads);

    // Call observer: It synthesizes report without panicking, exiting, or wiping
    let report = RuntimeIntegrityObserver::observe(ntdll_rep, mem_rep, dbg_rep, 1000);

    // Confirms report was generated and observer degraded confidence as telemetry signal only
    assert!(report.confidence < 10000);
    assert!(report.freshness.is_fresh(1000));
    // Process still healthy, execution continues unhindered!
}

#[test]
fn test_33_event_bus_ntdll_discrepancy_event() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::NtdllDiscrepancyObserved {
        function_name: "NtOpenProcess".to_string(),
        assessment: "Suspected JMP Detour".to_string(),
        severity: EventSeverity::High,
    });

    let items = bus.drain_as_evidence_items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].evidence_type, "EVENT_NTDLL_DISCREPANCY");
    assert_eq!(items[0].evidence_class, EvidenceClass::Structural);
    assert_eq!(items[0].source, EvidenceSource::PassiveProcessMitigation);
    assert_eq!(items[0].score, 2000); // High severity
}

#[test]
fn test_34_event_bus_memory_anomaly_event() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::MemoryAnomalyObserved {
        anomaly_class: "RwxRegion".to_string(),
        size: 4096,
        severity: EventSeverity::Critical,
    });

    let items = bus.drain_as_evidence_items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].evidence_type, "EVENT_MEMORY_ANOMALY");
    assert_eq!(items[0].score, 0); // Critical severity
}

#[test]
fn test_35_event_bus_debug_instrumentation_event() {
    let bus = SecurityEventBus::new();
    bus.publish(SecurityEvent::DebugInstrumentationObserved {
        assessment: "DebugStateDetected (DR0 active)".to_string(),
        severity: EventSeverity::Medium,
    });

    let items = bus.drain_as_evidence_items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].evidence_type, "EVENT_DEBUG_INSTRUMENTATION");
    assert_eq!(items[0].evidence_class, EvidenceClass::Behavioral);
    assert_eq!(items[0].score, 4000); // Medium severity
}

#[test]
fn test_36_passive_defense_report_v2_json_roundtrip() {
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
    ) = (
        cyberv_agent::defense::ProcessMitigationManager::apply_and_verify(&Default::default()),
        cyberv_agent::defense::PrivilegeManager::inspect_and_drop_dangerous_privileges(),
        cyberv_agent::defense::NetworkSurfaceInspector::audit_network_surface(vec![]),
        cyberv_agent::defense::BinaryIntegrityChecker::evaluate(
            true, "h", "h", true, true, true, true, true,
        ),
        cyberv_agent::defense::DriverIntegrityChecker::verify_driver(
            "CyberV Security Core",
            "h",
            "h",
            "1.0.0",
            true,
        ),
        cyberv_agent::defense::IpcSecurityReport::standard_hardened(r"\\.\pipe\CyberV_IPC"),
        cyberv_agent::defense::FilesystemAclManager::audit_critical_assets(
            &["C:\\vault.dat"],
            None,
        ),
        cyberv_agent::defense::UpdateIntegrityReport::verified_active(),
        cyberv_agent::defense::PlatformIntegrityChecker::evaluate(true, true, true, "p0", "p7"),
        cyberv_agent::defense::CapabilityProfiler::probe_system_capabilities(),
    );

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    assert_eq!(report.report_schema_version, REPORT_SCHEMA_VERSION_CURRENT);
    assert_eq!(report.report_schema_version, 2);

    let serialized = serde_json::to_string(&report).expect("Must serialize");
    let deserialized: PassiveDefenseReport =
        serde_json::from_str(&serialized).expect("Must deserialize");

    assert_eq!(report, deserialized);
}

#[test]
fn test_37_legacy_json_deserialization_backward_compatibility() {
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
    ) = (
        cyberv_agent::defense::ProcessMitigationManager::apply_and_verify(&Default::default()),
        cyberv_agent::defense::PrivilegeManager::inspect_and_drop_dangerous_privileges(),
        cyberv_agent::defense::NetworkSurfaceInspector::audit_network_surface(vec![]),
        cyberv_agent::defense::BinaryIntegrityChecker::evaluate(
            true, "h", "h", true, true, true, true, true,
        ),
        cyberv_agent::defense::DriverIntegrityChecker::verify_driver(
            "CyberV Security Core",
            "h",
            "h",
            "1.0.0",
            true,
        ),
        cyberv_agent::defense::IpcSecurityReport::standard_hardened(r"\\.\pipe\CyberV_IPC"),
        cyberv_agent::defense::FilesystemAclManager::audit_critical_assets(
            &["C:\\vault.dat"],
            None,
        ),
        cyberv_agent::defense::UpdateIntegrityReport::verified_active(),
        cyberv_agent::defense::PlatformIntegrityChecker::evaluate(true, true, true, "p0", "p7"),
        cyberv_agent::defense::CapabilityProfiler::probe_system_capabilities(),
    );

    let report = PassiveDefenseCoordinator::evaluate_all(
        mitigation, privilege, network, binary, driver, ipc, filesystem, update, platform,
        capability,
    );

    // Chuyển đổi sang JSON value và xóa các trường mới (giả lập payload của client cũ)
    let mut val = serde_json::to_value(&report).expect("Serialize to value");
    if let serde_json::Value::Object(ref mut map) = val {
        map.remove("report_schema_version");
        map.remove("runtime_observation");
    }

    let legacy_json = serde_json::to_string(&val).expect("Serialize legacy value to json");

    let parsed: PassiveDefenseReport =
        serde_json::from_str(&legacy_json).expect("Legacy JSON must deserialize cleanly");

    // Defaults kick in seamlessly!
    assert_eq!(parsed.report_schema_version, REPORT_SCHEMA_VERSION_CURRENT);
    assert_eq!(parsed.runtime_observation, None);
    assert_eq!(
        parsed.composite_passive_score,
        report.composite_passive_score
    );
}
