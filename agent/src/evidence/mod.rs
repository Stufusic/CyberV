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
//! CyberV Hardware Evidence Engine (HCE)
//!
//! Ref: Docs/rv9.md:
//! HCE-1 — Physical Constraint Engine
//! HCE-2 — Hardware Topology Engine
//! HCE-3 — Merkle Evidence Engine & Selective Inclusion Proofs

pub mod constraints;
pub mod fusion;
pub mod merkle;
pub mod temporal;
pub mod topology;
pub mod unified;

pub use constraints::{
    ConstraintEvaluation, ConstraintEvaluator, ConstraintResult, PhysicalConstraintEngine,
    PhysicalConstraintReport,
};
pub use fusion::{EvidenceFusionEngine, EvidenceFusionReport, EvidenceRating};
pub use merkle::{
    generate_inclusion_proof, MerkleEvidenceTree, MerkleInclusionProof, MerkleNode,
    MerkleProofStep, MerkleSiblingDirection,
};
pub use topology::{
    BusNode, HardwareTopologyEngine, HardwareTopologyReport, MemoryChannel, MemoryChannelMode,
    MemoryTopology, PciLocation,
};
pub use unified::{
    EvidenceClass, EvidenceItem, EvidenceSource, EvidenceSourceWeight, HardwareEvidenceState,
    MAX_CONFIDENCE_KERNEL_BUS, MAX_CONFIDENCE_MESH_QUORUM, MAX_CONFIDENCE_STORAGE_PNP,
    MAX_CONFIDENCE_TPM_QUOTE, MAX_CONFIDENCE_USER_WMI,
};

