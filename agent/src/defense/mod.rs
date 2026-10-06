// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! Foundational Security Defense Engines (FSE)
//!
//! Ref: Docs/rv11.md:
//! FSE-1: Kernel Tamper Resistance
//! FSE-2: DMA / IOMMU Protection
//! FSE-3: Firmware & Platform Integrity
//! FSE-4: VBS-Isolated Security Core

pub mod dma;
pub mod enclave;
pub mod firmware;
pub mod kernel;
pub mod passive;
pub mod policy;
pub mod recovery;

pub use passive::{
    AclAuditResult, AnomalySignalStrength, BaselineLifecycleManager, BaselineRefreshResult,
    BinaryIntegrityChecker, BinaryIntegrityReport, CapabilityMatrixReport, CapabilityProfiler,
    DebugInstrumentationReport, DebugSignalConfidence, DebugStateAssessment, DebugStateAuditor,
    DiskIntegrityReport, DriverIntegrityChecker, DriverIntegrityReport, EventSeverity,
    EvidenceFreshness, FilesystemAclManager, FilesystemSecurityReport, FreshnessState,
    FunctionIntegrityObservation, HookAssessment, IpcAuthorizer, IpcClientIdentity, IpcCommand,
    IpcMessageEnvelope, IpcProtocolError, IpcProtocolValidator, IpcSecurityReport,
    LoadedImageIntegrityReport, MemoryAnomalyClass, MemoryObservation, MemoryObservationReport,
    MemoryStateAuditor, MitigationCapability, NetworkSurfaceInspector, NetworkSurfaceReport,
    NtdllBaseline, NtdllIntegrityAnalyzer, NtdllObservationReport, PassiveDefenseCoordinator,
    PassiveDefenseReport, PassiveSystemState, PipeAclManager, PipeSecurityDescriptor,
    PlatformIntegrityChecker, PlatformIntegrityReport, PrivilegeIsolationReport, PrivilegeManager,
    ProcessMitigationConfig, ProcessMitigationManager, ProcessMitigationStatus,
    RuntimeConfigIntegrityReport, RuntimeIntegrityObserver, RuntimeObservationReport,
    SafeModeManager, SecurityCapabilityProfile, SecurityEvent, SecurityEventBus,
    StartupRecoveryStatus, StartupRecoveryTracker, StubIntegrityChecker, StubVariantAssessment,
    ThreadDebugContext, UpdateIntegrityReport, UpdatePackageManifest, UpdateStagingManager,
    UpdateStagingState, VersionPolicyDecision, VersionPolicyValidator, MAX_IPC_MESSAGE_SIZE,
    MAX_OUTBOUND_PAYLOAD_SIZE, PASSIVE_DEFENSE_DERIVATION_VERSION, REPORT_SCHEMA_VERSION_CURRENT,
    STRICT_NETWORK_TIMEOUT_SECS,
};

pub use recovery::{
    DeviceLifecycleState, PlatformUpdateType, RecoveryChallenge, RecoveryManager, RecoveryProof,
    TransitionDetector,
};

pub use policy::{PolicyConfig, PolicyDecision, PolicyEvaluationReport, SecurityPolicyEngine};

pub use enclave::{
    BoundaryError, EnclaveAttestationEngine, EnclaveAttestationReport, EnclaveCapabilityMatrix,
    EnclaveMeasurement, EnclaveStatus, IdentityBindingEngine, IdentityBindingProof,
    SecureIsoBuffer, ENCLAVE_DERIVATION_VERSION, MAX_SECURE_PAYLOAD_SIZE,
};

pub use dma::{
    DmaEvidenceFusionEngine, DmaSecurityReport, IommuReport, IommuStatus, PreBootDmaReport,
    ThunderboltSecurityLevel,
};
pub use firmware::{
    BootGuardReport, FirmwareConfigReport, FirmwareEvidenceFusionEngine, FirmwareSecurityReport,
    HardwareBootTechnology, ImageValidationResult, SecureBootDbReport, SmmSecurityReport,
};
pub use kernel::{
    AntiTamperManager, AntiTamperReport, HandleOperationResult, ProtectedProcessRegistration,
    ShieldTelemetry, VaultShield, VaultShieldError,
};
