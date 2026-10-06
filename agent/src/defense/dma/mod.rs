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
//! DMA & IOMMU Protection (FSE-2)
//!
//! Ref: Docs/rv11.md Section 3:
//! DMAR / IVRS, Runtime vs Pre-boot DMA, Kernel DMA Protection, Multi-factor DMA Fusion.

pub mod fusion;
pub mod iommu;
pub mod preboot;

pub use fusion::{DmaEvidenceFusionEngine, DmaSecurityReport, DMA_DERIVATION_VERSION};
pub use iommu::{IommuReport, IommuStatus};
pub use preboot::{PreBootDmaReport, ThunderboltSecurityLevel};
