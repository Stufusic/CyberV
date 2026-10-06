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
//! Phase 24A: Process Mitigations & Capability Profiling Tests
//!
//! Ref: Docs/rv13.md Section 1 & Section 8:
//! Validates:
//! - ACG (Dynamic Code), Extension Points, Signature Policy, Image Load Policy
//! - Strict Handle Checks, Child Process Safe Override
//! - 4-state Capability Matrix: Supported != Enabled != Enforceable != Verified

use cyberv_agent::defense::passive::capability::{
    CapabilityProfiler, MitigationCapability, SecurityCapabilityProfile,
};
use cyberv_agent::defense::passive::process_mitigations::{
    ProcessMitigationConfig, ProcessMitigationManager,
};
use cyberv_agent::security::assurance::AssuranceLevel;

#[test]
fn test_01_capability_matrix_all_probed() {
    let report = CapabilityProfiler::probe_system_capabilities();
    assert!(!report.profiles.is_empty());
    assert!(report.summary.contains("Capability Profiler"));

    // P1-3: bất biến bậc thang năng lực — verified ⇒ enabled ⇒ supported.
    // Composite tự-consistent với số profile verified (không assert giá trị
    // tuyệt đối vì phụ thuộc cấu hình thật của máy).
    for p in &report.profiles {
        assert!(
            !(p.verified && !p.enabled) && !(p.enabled && !p.supported),
            "{:?}: verified ⇒ enabled ⇒ supported bị vi phạm: {:?}",
            p.capability,
            p
        );
    }
    let verified = report.profiles.iter().filter(|p| p.verified).count();
    let expected = (verified as u64 * 10000 / report.profiles.len() as u64) as u32;
    assert_eq!(report.composite_score, expected);

    // CET: trên x86_64, CPUID probe phải chạy (supported=true nếu CPU có CET,
    // không bao giờ thiếu reason)
    for p in &report.profiles {
        if p.capability == MitigationCapability::UserShadowStackCet && cfg!(target_arch = "x86_64")
        {
            assert!(p.reason.is_some(), "CET profile phải có reason trung thực");
        }
    }
}

#[test]
fn test_02_dynamic_code_policy_acg_verified() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_acg_active);
}

#[test]
fn test_03_image_load_policy_restricted() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_image_load_restricted);
}

#[test]
fn test_04_extension_points_disabled() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_extension_point_disabled);
}

#[test]
fn test_05_strict_handle_checks_enabled() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_strict_handle_active);
}

#[test]
fn test_06_whql_signature_policy_enforced() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.is_whql_enforced);
}

#[test]
fn test_07_child_process_safe_helper_override_allowed() {
    // Crucial rule from Docs/rv13.md Section 5:
    // Do NOT blindly hard-block child processes, allow safe helper overrides
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert!(status.allow_child_helpers);
}

#[test]
fn test_08_capability_supported_vs_enabled_distinction() {
    // Validates: Supported != Enabled != Verified
    let profile = SecurityCapabilityProfile::supported_not_enabled(
        MitigationCapability::UserShadowStackCet,
        "Compatible CPU present but feature disabled in test profile",
    );
    assert!(profile.supported);
    assert!(!profile.enabled);
    assert!(!profile.verified);
    assert_eq!(profile.assurance, AssuranceLevel::OSProtected);
    assert!(profile.reason.is_some());
}

#[test]
fn test_09_process_mitigation_score_full_hardened() {
    let config = ProcessMitigationConfig::default();
    let status = ProcessMitigationManager::apply_and_verify(&config);
    assert_eq!(status.mitigation_score, 10000);
}

#[test]
fn test_10_process_mitigation_degraded_partial_score() {
    // P1-3: apply_and_verify báo TRẠNG THÁI TRUY VẤN thật của tiến trình —
    // sets từ các test trước trong cùng process là một chiều (one-way) nên
    // không thể assert giá trị tuyệt đối ở đây. Trọng số spec được kiểm chứng
    // qua hàm thuần túy score_from_flags:
    use cyberv_agent::defense::passive::process_mitigations::QueriedFlags;
    let q = QueriedFlags {
        ext_disabled: true,       // +2000
        strict_raise: true,       // +1500
        img_no_remote: true,      // +1500
        child_deny: false,        // +1000 (safe override)
        acg_prohibit: false,      // ACG off  -> mất 2000
        img_no_low_label: false,  // remote images allowed -> mất 2000
        all_queried: true,
    };
    assert_eq!(ProcessMitigationManager::score_from_flags(&q), 6000); // 10000 - 2000 - 2000

    // Và report thật phải self-consistent: score = hàm của chính cờ nó báo
    let status = ProcessMitigationManager::apply_and_verify(&Default::default());
    if status.is_verified {
        let real = QueriedFlags {
            acg_prohibit: status.is_acg_active,
            ext_disabled: status.is_extension_point_disabled,
            img_no_low_label: status.is_image_load_restricted,
            img_no_remote: status.is_whql_enforced,
            strict_raise: status.is_strict_handle_active,
            child_deny: !status.allow_child_helpers,
            all_queried: true,
        };
        let _ = &real;
        assert_eq!(
            status.mitigation_score,
            ProcessMitigationManager::score_from_flags(&real)
        );
    }
}
