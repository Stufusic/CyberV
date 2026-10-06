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
//! Security Capability & Assurance Profiler (P24.0)
//!
//! Ref: Docs/rv13.md Section 8:
//! "Supported != Enabled != Enforceable != Verified.
//! Ba trạng thái này phải tách. Windows cung cấp GetProcessMitigationPolicy để
//! query trạng thái mitigation thực tế của process."

use crate::security::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitigationCapability {
    Dep,
    Aslr,
    DynamicCodePolicy,
    ImageLoadPolicy,
    ExtensionPointDisable,
    StrictHandleCheck,
    UserShadowStackCet,
    ControlFlowGuardCfg,
    ChildProcessRestriction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityCapabilityProfile {
    pub capability: MitigationCapability,
    pub supported: bool,
    pub enabled: bool,
    pub enforceable: bool,
    pub verified: bool,
    pub assurance: AssuranceLevel,
    pub reason: Option<String>,
}

impl SecurityCapabilityProfile {
    pub fn verified_active(cap: MitigationCapability, assurance: AssuranceLevel) -> Self {
        Self {
            capability: cap,
            supported: true,
            enabled: true,
            enforceable: true,
            verified: true,
            assurance,
            reason: None,
        }
    }

    pub fn supported_not_enabled(cap: MitigationCapability, reason: impl Into<String>) -> Self {
        Self {
            capability: cap,
            supported: true,
            enabled: false,
            enforceable: true,
            verified: false,
            assurance: AssuranceLevel::OSProtected,
            reason: Some(reason.into()),
        }
    }

    pub fn unsupported(cap: MitigationCapability, reason: impl Into<String>) -> Self {
        Self {
            capability: cap,
            supported: false,
            enabled: false,
            enforceable: false,
            verified: false,
            assurance: AssuranceLevel::Software,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrixReport {
    pub profiles: Vec<SecurityCapabilityProfile>,
    pub composite_score: u32,
    pub summary: String,
}

pub struct CapabilityProfiler;

impl CapabilityProfiler {
    /// P1-3: thăm dò NĂNG LỰC THẬT từ các nguồn đã đo được:
    /// - Process mitigations: GetProcessMitigationPolicy (thật qua process_mitigations)
    /// - CET hardware: CPUID leaf 7 (ecx bit 7) — "supported" thật của CPU
    /// - Các năng lượng chưa có probe thật (TPM/IOMMU/firmware) phải báo
    ///   supported=false + lý do trung thực, KHÔNG verifiedActive.
    pub fn probe_system_capabilities() -> CapabilityMatrixReport {
        let mut profiles: Vec<SecurityCapabilityProfile> = Vec::new();

        // ---- 1. Mitigation thật của process (từ probe P1-3) ----
        let mit = crate::defense::passive::process_mitigations::ProcessMitigationManager::apply_and_verify(
            &Default::default(),
        );
        let measured = mit.is_verified;

        // DEP/ASLR: tính chất nền tảng của Windows x64 hiện đại (không phải cờ đo được
        // qua mitigation API) — verified khi chạy trên windows x64, else unsupported.
        let dep_aslr_ok = cfg!(all(windows, target_arch = "x86_64"));
        for cap in [MitigationCapability::Dep, MitigationCapability::Aslr] {
            profiles.push(if dep_aslr_ok {
                SecurityCapabilityProfile::verified_active(cap, AssuranceLevel::OSProtected)
            } else {
                SecurityCapabilityProfile::unsupported(cap, "Platform does not guarantee DEP/ASLR")
            });
        }

        if measured {
            profiles.push(profile_from(
                MitigationCapability::DynamicCodePolicy,
                mit.is_acg_active,
                "GetProcessMitigationPolicy(DynamicCode)",
                measured,
            ));
            profiles.push(profile_from(
                MitigationCapability::ImageLoadPolicy,
                mit.is_image_load_restricted,
                "GetProcessMitigationPolicy(ImageLoad)",
                measured,
            ));
            profiles.push(profile_from(
                MitigationCapability::ExtensionPointDisable,
                mit.is_extension_point_disabled,
                "GetProcessMitigationPolicy(ExtensionPointDisable)",
                measured,
            ));
            profiles.push(profile_from(
                MitigationCapability::StrictHandleCheck,
                mit.is_strict_handle_active,
                "GetProcessMitigationPolicy(StrictHandleCheck)",
                measured,
            ));
            profiles.push(profile_from(
                MitigationCapability::ChildProcessRestriction,
                !mit.allow_child_helpers,
                "GetProcessMitigationPolicy(ChildProcess)",
                measured,
            ));
            // CFG: binary compiled với /guard:cf — query thật
            #[cfg(windows)]
            {
                let cfg_flags =
                    crate::defense::passive::process_mitigations::query_policy_flags(
                        crate::defense::passive::process_mitigations::POLICY_CONTROL_FLOW_GUARD,
                    );
                profiles.push(profile_from(
                    MitigationCapability::ControlFlowGuardCfg,
                    cfg_flags.map(|f| f & 0x1 != 0).unwrap_or(false),
                    "GetProcessMitigationPolicy(ControlFlowGuard)",
                    cfg_flags.is_some(),
                ));
            }
        } else {
            for cap in [
                MitigationCapability::DynamicCodePolicy,
                MitigationCapability::ImageLoadPolicy,
                MitigationCapability::ExtensionPointDisable,
                MitigationCapability::StrictHandleCheck,
                MitigationCapability::ChildProcessRestriction,
                MitigationCapability::ControlFlowGuardCfg,
            ] {
                profiles.push(SecurityCapabilityProfile::unsupported(
                    cap,
                    "Mitigation probe unavailable (fail-closed)",
                ));
            }
        }

        // ---- 2. CET shadow stack: hardware support qua CPUID ----
        profiles.push(cet_profile());

        let verified_count = profiles.iter().filter(|p| p.verified).count();
        let total = profiles.len();
        let composite_score = if total > 0 {
            ((verified_count as u64 * 10000) / total as u64) as u32
        } else {
            0
        };

        let summary = format!(
            "Capability Profiler: {}/{} mitigations verified active (Score: {}/10000)",
            verified_count, total, composite_score
        );

        CapabilityMatrixReport {
            profiles,
            composite_score,
            summary,
        }
    }
}

/// Xây profile 4-trạng-thái từ một giá trị enabled đã đo được.
/// Bậc thang bất biến: verified ⇒ enabled ⇒ supported.
fn profile_from(
    cap: MitigationCapability,
    enabled: bool,
    source: &str,
    measured: bool,
) -> SecurityCapabilityProfile {
    if enabled {
        SecurityCapabilityProfile {
            capability: cap,
            supported: true,
            enabled: true,
            enforceable: true,
            verified: measured,
            assurance: if measured {
                AssuranceLevel::OSProtected
            } else {
                AssuranceLevel::Software
            },
            reason: Some(source.to_string()),
        }
    } else {
        SecurityCapabilityProfile::supported_not_enabled(
            cap,
            format!("{}: policy chưa bật trên process này", source),
        )
    }
}

/// CET shadow stack: hardware support thật qua CPUID (leaf 7, ECX bit 7).
/// "enabled" (kernel policy) chưa có probe → false trung thực cho tới P2.
fn cet_profile() -> SecurityCapabilityProfile {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: cpuid an toàn trên mọi x86_64
        let cpuid = std::arch::x86_64::__cpuid(7);
        let cet_supported = cpuid.ecx & (1 << 7) != 0;
        if cet_supported {
            SecurityCapabilityProfile {
                capability: MitigationCapability::UserShadowStackCet,
                supported: true,
                enabled: false,
                enforceable: true,
                verified: false,
                assurance: AssuranceLevel::OSProtected,
                reason: Some(
                    "CPU supports CET shadow stack (CPUID.7.ECX[7]); kernel policy probe pending (P2)"
                        .to_string(),
                ),
            }
        } else {
            SecurityCapabilityProfile::unsupported(
                MitigationCapability::UserShadowStackCet,
                "CPUID.7.ECX[7] = 0: CPU lacks CET shadow stack",
            )
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        SecurityCapabilityProfile::unsupported(
            MitigationCapability::UserShadowStackCet,
            "Non-x86_64 platform",
        )
    }
}
