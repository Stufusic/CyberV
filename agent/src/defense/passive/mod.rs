//! Passive Defense Foundation & Prevention Plane (Phase 24)
//!
//! Ref: Docs/rv13.md & Docs/rv12.md:
//! Nền tảng phòng ngự thụ động đa lớp bảo đảm:
//! "No single compromise should automatically imply trusted-device compromise."

pub mod binary_integrity;
pub mod capability;
pub mod debug;
pub mod driver_integrity;
pub mod event_bus;
pub mod filesystem_acl;
pub mod ipc;
pub mod isolation;
pub mod memory;
pub mod network_surface;
pub mod platform_integrity;
pub mod privilege;
pub mod process_mitigations;
pub mod recovery;
pub mod runtime_freshness;
pub mod runtime_guard;
pub mod syscall;
pub mod update;
pub mod wdac;

pub use binary_integrity::{
    BinaryIntegrityChecker, BinaryIntegrityReport, DiskIntegrityReport, LoadedImageIntegrityReport,
    RuntimeConfigIntegrityReport,
};
pub use capability::{
    CapabilityMatrixReport, CapabilityProfiler, MitigationCapability, SecurityCapabilityProfile,
};
pub use debug::{
    DebugInstrumentationReport, DebugSignalConfidence, DebugStateAssessment, DebugStateAuditor,
    ThreadDebugContext,
};
pub use driver_integrity::{DriverIntegrityChecker, DriverIntegrityReport};
pub use event_bus::{EventSeverity, SecurityEvent, SecurityEventBus};
pub use filesystem_acl::{AclAuditResult, FilesystemAclManager, FilesystemSecurityReport};
pub use ipc::{
    IpcAuthorizer, IpcClientIdentity, IpcCommand, IpcMessageEnvelope, IpcProtocolError,
    IpcProtocolValidator, IpcSecurityReport, PipeAclManager, PipeSecurityDescriptor,
    MAX_IPC_MESSAGE_SIZE,
};
pub use isolation::{
    BrokerError, BrokerPolicyAdmissionController, BrokerRpcCommand, BrokerStatus, CoreBroker,
    IpcFrameError, NetworkWorkerDaemon, PolicyAdmissionError, RpcEnvelope, RpcSessionValidator,
    SignedPolicyEnvelope, WorkerSandboxProfile, CURRENT_IPC_PROTOCOL_VERSION, MAX_IPC_FRAME_SIZE,
};
pub use memory::{
    AnomalySignalStrength, MemoryAnomalyClass, MemoryObservation, MemoryObservationReport,
    MemoryStateAuditor,
};
pub use network_surface::{
    NetworkSurfaceInspector, NetworkSurfaceReport, MAX_OUTBOUND_PAYLOAD_SIZE,
    STRICT_NETWORK_TIMEOUT_SECS,
};
pub use platform_integrity::{PlatformIntegrityChecker, PlatformIntegrityReport};
pub use privilege::{PrivilegeIsolationReport, PrivilegeManager};
pub use process_mitigations::{
    ProcessMitigationConfig, ProcessMitigationManager, ProcessMitigationStatus,
};
pub use recovery::{
    PassiveSystemState, SafeModeManager, StartupRecoveryStatus, StartupRecoveryTracker,
};
pub use runtime_freshness::{EvidenceFreshness, FreshnessState};
pub use runtime_guard::{RuntimeIntegrityObserver, RuntimeObservationReport};
pub use syscall::{
    BaselineLifecycleManager, BaselineRefreshResult, FunctionIntegrityObservation, HookAssessment,
    NtdllBaseline, NtdllIntegrityAnalyzer, NtdllObservationReport, StubIntegrityChecker,
    StubVariantAssessment,
};
pub use update::{
    CommitStage, HardwareVersionDecision, PendingCommitMarker, StartupRecoveryAction,
    UpdateIntegrityReport, UpdatePackageManifest, UpdateStagingManager, UpdateStagingState,
    VersionPolicyDecision, VersionPolicyValidator,
};
pub use wdac::{
    CodeIntegrityVerifier, ModuleClassification, ModuleEntry, ProcessModuleInspector,
    ProcessModuleIntegrityReport, SystemCodeIntegrityReport, WdacPolicyConfig, WdacPolicyGenerator,
    WdacSecurityReport,
};

use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use crate::security::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PASSIVE_DEFENSE_DERIVATION_VERSION: u32 = 1;
pub const REPORT_SCHEMA_VERSION_CURRENT: u32 = 2;

fn default_report_schema_version() -> u32 {
    REPORT_SCHEMA_VERSION_CURRENT
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveDefenseReport {
    #[serde(default = "default_report_schema_version")]
    pub report_schema_version: u32,
    pub mitigation: ProcessMitigationStatus,
    pub privilege: PrivilegeIsolationReport,
    pub network: NetworkSurfaceReport,
    pub binary: BinaryIntegrityReport,
    pub driver: DriverIntegrityReport,
    pub ipc: IpcSecurityReport,
    pub filesystem: FilesystemSecurityReport,
    pub update: UpdateIntegrityReport,
    pub platform: PlatformIntegrityReport,
    pub capability: CapabilityMatrixReport,
    #[serde(default)]
    pub runtime_observation: Option<RuntimeObservationReport>,
    #[serde(default)]
    pub wdac: Option<WdacSecurityReport>,
    #[serde(default)]
    pub tpm_counter_assurance: Option<crate::trust::tpm::TpmAssuranceType>,
    pub confidence: u16,
    pub assurance: AssuranceLevel,
    pub freshness: u16,
    pub composite_passive_score: u32,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub summary: String,
}

impl PassiveDefenseReport {
    pub fn with_runtime_observation(mut self, observation: RuntimeObservationReport) -> Self {
        self.runtime_observation = Some(observation);
        self
    }

    pub fn with_wdac(mut self, wdac: WdacSecurityReport) -> Self {
        self.wdac = Some(wdac);
        self
    }

    pub fn with_tpm_assurance(mut self, assurance: crate::trust::tpm::TpmAssuranceType) -> Self {
        self.tpm_counter_assurance = Some(assurance);
        self
    }
}

pub struct PassiveDefenseCoordinator;

impl PassiveDefenseCoordinator {
    /// Tổng hợp báo cáo phòng ngự thụ động toàn diện
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_all(
        mitigation: ProcessMitigationStatus,
        privilege: PrivilegeIsolationReport,
        network: NetworkSurfaceReport,
        binary: BinaryIntegrityReport,
        driver: DriverIntegrityReport,
        ipc: IpcSecurityReport,
        filesystem: FilesystemSecurityReport,
        update: UpdateIntegrityReport,
        platform: PlatformIntegrityReport,
        capability: CapabilityMatrixReport,
    ) -> PassiveDefenseReport {
        // Trọng số số nguyên (Integer Weighted Score - 0..10000 cho UI/Analytics):
        // Mitigation: 15%, Privilege: 10%, Network: 10%, Binary: 15%,
        // Driver: 15%, IPC: 10%, Filesystem: 10%, Update: 5%, Platform: 10%
        let weighted = (mitigation.mitigation_score as u64 * 1500)
            + (privilege.privilege_score as u64 * 1000)
            + (network.network_surface_score as u64 * 1000)
            + (binary.binary_integrity_score as u64 * 1500)
            + (driver.driver_integrity_score as u64 * 1500)
            + (ipc.ipc_score as u64 * 1000)
            + (filesystem.acl_score as u64 * 1000)
            + (update.update_score as u64 * 500)
            + (platform.platform_score as u64 * 1000);

        let composite_passive_score = (weighted / 10000) as u32;

        let assurance = if composite_passive_score >= 8000
            && platform.is_measured_boot_active
            && driver.is_signer_valid
        {
            AssuranceLevel::HardwareBacked
        } else if composite_passive_score >= 5000 {
            AssuranceLevel::OSProtected
        } else {
            AssuranceLevel::Software
        };

        // Virtual Points
        let p_mit = VirtualPoint::new(
            "point:mitigation_score",
            mitigation.mitigation_score as i64,
            10000,
            PASSIVE_DEFENSE_DERIVATION_VERSION,
        );
        let p_priv = VirtualPoint::new(
            "point:privilege_score",
            privilege.privilege_score as i64,
            10000,
            PASSIVE_DEFENSE_DERIVATION_VERSION,
        );
        let p_bin = VirtualPoint::new(
            "point:binary_integrity_score",
            binary.binary_integrity_score as i64,
            10000,
            PASSIVE_DEFENSE_DERIVATION_VERSION,
        );
        let p_drv = VirtualPoint::new(
            "point:driver_integrity_score",
            driver.driver_integrity_score as i64,
            10000,
            PASSIVE_DEFENSE_DERIVATION_VERSION,
        );
        let p_pass = VirtualPoint::new(
            "point:passive_defense_score",
            composite_passive_score as i64,
            10000,
            PASSIVE_DEFENSE_DERIVATION_VERSION,
        );

        // Virtual Nodes
        let mut shield_attrs = BTreeMap::new();
        shield_attrs.insert(
            "acg_active".to_string(),
            mitigation.is_acg_active.to_string(),
        );
        shield_attrs.insert(
            "image_load_restricted".to_string(),
            mitigation.is_image_load_restricted.to_string(),
        );
        shield_attrs.insert(
            "least_privilege".to_string(),
            privilege.is_least_privilege_active.to_string(),
        );
        shield_attrs.insert(
            "driver_valid".to_string(),
            driver.is_signer_valid.to_string(),
        );

        let vn_shield = VirtualNode {
            id: "vnode:passive_prevention_shield".to_string(),
            virtual_type: "PASSIVE_PREVENTION_SHIELD".to_string(),
            derivation_version: PASSIVE_DEFENSE_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("passive_shield_vhash_{:04}", composite_passive_score),
            attributes: shield_attrs,
        };

        let mut ipc_attrs = BTreeMap::new();
        ipc_attrs.insert("pipe_hardened".to_string(), ipc.is_acl_hardened.to_string());
        ipc_attrs.insert(
            "schema_bounded".to_string(),
            ipc.is_protocol_bounded.to_string(),
        );

        let vn_ipc = VirtualNode {
            id: "vnode:ipc_security_boundary".to_string(),
            virtual_type: "IPC_SECURITY_BOUNDARY".to_string(),
            derivation_version: PASSIVE_DEFENSE_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("ipc_boundary_vhash_{:04}", ipc.ipc_score),
            attributes: ipc_attrs,
        };

        let summary = format!(
            "Passive Defense: Score={}/10000, Assurance={}, Mitigations={}/10000, Driver={}/10000, IPC={}/10000",
            composite_passive_score, assurance, mitigation.mitigation_score, driver.driver_integrity_score, ipc.ipc_score
        );

        PassiveDefenseReport {
            report_schema_version: REPORT_SCHEMA_VERSION_CURRENT,
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
            runtime_observation: None,
            wdac: None,
            tpm_counter_assurance: None,
            confidence: 10000,

            assurance,
            freshness: 10000,
            composite_passive_score,
            virtual_nodes: vec![vn_shield, vn_ipc],
            virtual_points: vec![p_mit, p_priv, p_bin, p_drv, p_pass],
            summary,
        }
    }
}
