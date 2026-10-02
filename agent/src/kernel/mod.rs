//! CyberV Kernel & Lower-Layer Observation Subsystem (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6:
//! Independent Kernel observation, Cross-Layer Validation (Userland vs Ring-0).

pub mod client;
pub mod cross_validator;
pub mod protocol;

pub use client::{
    parse_kernel_observation_bytes, KernelProbeProvider, MockKernelClient, WindowsKernelClient,
    KERNEL_MAX_DEVICES, KERNEL_OBSERVATION_HEADER_SIZE, KERNEL_PCI_DEVICE_SIZE,
};
pub use cross_validator::{
    CrossLayerValidationReport, CrossLayerValidator, ValidationStatus, KERNEL_DERIVATION_VERSION,
};
pub use protocol::{
    KernelObservationPayload, KernelPciDevice, KernelShieldTelemetry,
    IOCTL_CYBERV_GET_PCI_INFO, IOCTL_CYBERV_GET_TOPOLOGY,
    IOCTL_CYBERV_REGISTER_PROTECTED_PID, IOCTL_CYBERV_GET_SHIELD_TELEMETRY,
};
