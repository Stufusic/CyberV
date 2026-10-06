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
//! CyberV Transparency & Append-Only Log Subsystem (HCE-8)
//!
//! Ref: Docs/rv10.md HCE-8:
//! Merkle Mountain Range (MMR), Signed Checkpoints, Anti-Rogue-Admin Guard.

pub mod checkpoint;
pub mod event;
pub mod mmr;
pub mod proof;

pub use checkpoint::SignedCheckpoint;
pub use event::{EventType, RevocationEvent};
pub use mmr::{MerkleMountainRange, MmrInclusionProof, MmrProofStep};
pub use proof::{RevocationVerificationResult, RevocationVerifier};
