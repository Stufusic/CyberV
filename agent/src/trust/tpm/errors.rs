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
//! TPM 2.0 Error Definitions (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4:
//! "TpmError: TPM unavailable, unsupported capabilities, quote failed, pcr mismatch."

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TpmError {
    #[error("TPM 2.0 chip is not present or unavailable")]
    NotPresent,

    #[error("TPM 2.0 platform crypto provider failed: {0}")]
    ProviderError(String),

    #[error("TPM key operation failed: {0}")]
    KeyError(String),

    #[error("TPM quote verification failed: {0}")]
    QuoteVerificationFailed(String),

    #[error("PCR selection invalid or unsupported: {0}")]
    InvalidPcrSelection(String),

    #[error("PCR digest mismatch: expected {expected}, actual {actual}")]
    PcrMismatch { expected: String, actual: String },

    #[error("Attestation nonce mismatch or replay detected")]
    NonceMismatch,

    #[error("Measured boot log corrupted or invalid: {0}")]
    InvalidBootLog(String),

    #[error("Platform transition policy rejected: {0}")]
    PlatformTransitionRejected(String),

    #[error("TPM NV index 0x{0:08X} not found or not provisioned")]
    NvIndexNotFound(u32),

    #[error("TPM NV index attribute mismatch: expected {expected}, actual {actual}")]
    NvIndexAttributeMismatch { expected: String, actual: String },

    #[error("TPM NV index 0x{0:08X} is occupied by foreign entity or unauthorized policy")]
    NvIndexForeignOwnership(u32),

    #[error("TPM NV counter 0x{0:08X} overflow limit reached")]
    NvCounterOverflow(u32),

    #[error("TPM NV access denied: {0}")]
    NvAccessDenied(String),
}
