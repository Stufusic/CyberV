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
//! Two-Layer Code Integrity Subsystem (WDAC & Process Module Policy - Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 7, 8, 9:
//! - Layer A: System Code Integrity (WDAC CIPolicy.xml Generator & Kernel CI Verifier)
//! - Layer B: Process Module Inventory & Authenticode Verification

pub mod ci_verifier;
pub mod policy_generator;
pub mod process_module_policy;

pub use ci_verifier::{CodeIntegrityVerifier, SystemCodeIntegrityReport};
pub use policy_generator::{WdacPolicyConfig, WdacPolicyGenerator};
pub use process_module_policy::{
    ModuleClassification, ModuleEntry, ProcessModuleInspector, ProcessModuleIntegrityReport,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WdacSecurityReport {
    pub system_ci: SystemCodeIntegrityReport,
    pub process_modules: ProcessModuleIntegrityReport,
    pub composite_score: u32,
    pub summary: String,
}

impl WdacSecurityReport {
    pub fn evaluate(
        system_ci: SystemCodeIntegrityReport,
        process_modules: ProcessModuleIntegrityReport,
    ) -> Self {
        // Trọng số: 50% System CI (Kernel), 50% Process Modules
        let composite = ((system_ci.integrity_score as u64 * 5000)
            + (process_modules.module_score as u64 * 5000))
            / 10000;
        let composite_score = composite as u32;

        let summary = format!(
            "Two-Layer Code Integrity: System CI={}/10000, Process Modules={}/10000, Composite={}/10000",
            system_ci.integrity_score, process_modules.module_score, composite_score
        );

        Self {
            system_ci,
            process_modules,
            composite_score,
            summary,
        }
    }
}
