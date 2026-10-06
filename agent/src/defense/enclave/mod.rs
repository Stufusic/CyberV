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
//! VBS-Isolated Security Core (FSE-4)
//!
//! Ref: Docs/rv11.md Section 5:
//! Enclave isolation, memory boundary defense, identity binding to TPM 2.0.

pub mod attestation;
pub mod binding;
pub mod boundary;
pub mod capability;

pub use attestation::{
    EnclaveAttestationEngine, EnclaveAttestationReport, EnclaveMeasurement,
    ENCLAVE_DERIVATION_VERSION,
};
pub use binding::{IdentityBindingEngine, IdentityBindingProof};
pub use boundary::{BoundaryError, SecureIsoBuffer, MAX_SECURE_PAYLOAD_SIZE};
pub use capability::{EnclaveCapabilityMatrix, EnclaveStatus};
