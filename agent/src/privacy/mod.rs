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
//! Zero-Knowledge Device Attestation & Privacy Layer (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 32-39:
//! Statement, Witness, Circuit, ZK Prover, ZK Verifier, Selective Disclosure.

pub mod circuit;
pub mod prover;
pub mod selective;
pub mod statement;
pub mod verifier;
pub mod witness;

pub use circuit::{CircuitError, CircuitEvaluationResult, HardwareCircuit, CIRCUIT_VERSION};
pub use prover::{ProverError, ZkProof, ZkProver};
pub use selective::{
    DisclosedAttribute, SelectiveDisclosureClaim, SelectiveDisclosureEngine,
    SelectiveDisclosureError,
};
pub use statement::{DevicePolicy, DeviceStatement};
pub use verifier::{NonceTracker, VerifierError, ZkVerifier};
pub use witness::{HardwareLeafWitness, HardwareWitness};
