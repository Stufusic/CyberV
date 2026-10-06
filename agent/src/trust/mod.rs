// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
//! CyberV Trust & Hardware Root of Trust Subsystem (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! TPM 2.0 Root of Trust, Measured Boot, PCR Policies, Platform Attestation.

pub mod identity;
pub mod platform;
pub mod tpm;

pub use identity::{AssuranceLevel, HardwareIdentity, HybridDeviceIdentity, SoftwareIdentity};
pub use platform::{
    BootConfigurationLog, BootLogEntry, PlatformMeasurement, PlatformTrustState,
    SecureBootEvidence, SecureBootStatus, TpmRecoveryHandler,
};
pub use tpm::{
    HashAlgorithm, MockTpmDetector, MockTpmProvider, PcrBank, PcrPolicy, TpmAttestationPayload,
    TpmCapabilities, TpmDetector, TpmError, TpmIdentityKey, TpmProvider, TpmQuote, TpmStatus,
    WindowsTpmDetector,
};
