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
