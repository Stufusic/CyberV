//! Process Mitigation Policies (P24.1)
//!
//! Ref: Docs/rv13.md Section 1:
//! "Image Load Policy — nên thêm ngay: process_mitigations.rs: dynamic_code,
//! extension_points, signature, image_load, cfg, shadow_stack, child_process."
//!
//! P1-3: apply_and_verify giờ gọi SetProcessMitigationPolicy (best-effort)
//! rồi GetProcessMitigationPolicy để VERIFY — trạng thái báo cáo là giá trị
//! TRUY VẤN THẬT, không phải config yêu cầu. `is_verified` = các truy vấn
//! thành công (đo được thật); query thất bại → fail-closed score 0.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMitigationConfig {
    pub prohibit_dynamic_code: bool,
    pub disable_extension_points: bool,
    pub restrict_image_load: bool,
    pub strict_handle_checks: bool,
    pub microsoft_whql_signatures_only: bool,
    pub allow_child_helpers: bool,
}

impl Default for ProcessMitigationConfig {
    fn default() -> Self {
        Self {
            prohibit_dynamic_code: true,
            disable_extension_points: true,
            restrict_image_load: true,
            strict_handle_checks: true,
            microsoft_whql_signatures_only: true,
            allow_child_helpers: true, // Safe override for updater/browser
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMitigationStatus {
    pub is_acg_active: bool,
    pub is_extension_point_disabled: bool,
    pub is_image_load_restricted: bool,
    pub is_strict_handle_active: bool,
    pub is_whql_enforced: bool,
    pub allow_child_helpers: bool,
    #[serde(default)]
    pub is_verified: bool,
    pub mitigation_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct ProcessMitigationManager;

// ProcessMitigationPolicy enum values (Windows SDK — ổn định)
#[cfg(windows)]
pub const POLICY_DYNAMIC_CODE: u32 = 2;
#[cfg(windows)]
pub const POLICY_CONTROL_FLOW_GUARD: u32 = 7;
#[cfg(windows)]
const POLICY_STRICT_HANDLE_CHECK: u32 = 3;
#[cfg(windows)]
const POLICY_EXTENSION_POINT_DISABLE: u32 = 6;
#[cfg(windows)]
const POLICY_IMAGE_LOAD: u32 = 10;
#[cfg(windows)]
const POLICY_CHILD_PROCESS: u32 = 13;

// Cờ trong struct mitigation tương ứng (mỗi struct có 1 u32 Flags)
#[cfg(windows)]
mod mit_flags {
    // DynamicCode
    pub const DYN_PROHIBIT: u32 = 0x1;
    pub const DYN_ALLOW_THREAD_OPT_OUT: u32 = 0x2;
    // StrictHandleCheck
    pub const SH_RAISE_ON_INVALID: u32 = 0x1;
    pub const SH_PERMANENT: u32 = 0x2;
    // ExtensionPointDisable
    pub const EXT_DISABLE: u32 = 0x1;
    // ImageLoad
    pub const IMG_NO_LOW_MANDATORY_LABEL: u32 = 0x1;
    pub const IMG_NO_REMOTE_IMAGES: u32 = 0x2;
    // ChildProcess
    pub const CHILD_DENY: u32 = 0x1;
    pub const CHILD_AUDIT: u32 = 0x2;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetProcessMitigationPolicy(
        process_handle: isize,
        mitigation_policy: u32,
        buffer: *mut u8,
        buffer_length: usize,
    ) -> i32;
    fn SetProcessMitigationPolicy(
        mitigation_policy: u32,
        buffer: *const u8,
        buffer_length: usize,
    ) -> i32;
}

/// Trạng thái truy vấn được của 5 policy
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QueriedFlags {
    pub acg_prohibit: bool,
    pub ext_disabled: bool,
    pub img_no_low_label: bool,
    pub img_no_remote: bool,
    pub strict_raise: bool,
    pub child_deny: bool,
    pub all_queried: bool,
}

/// Truy vấn thô flags của một policy (dùng chéo bởi capability profiler)
#[cfg(windows)]
pub fn query_policy_flags(policy: u32) -> Option<u32> {
    query_policy_u32(policy)
}

#[cfg(windows)]
fn query_policy_u32(policy: u32) -> Option<u32> {
    // SAFETY: buffer 4 byte hợp lệ cho struct mitigation {u32 flags}
    unsafe {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut flags: u32 = 0;
        let ok = GetProcessMitigationPolicy(
            GetCurrentProcess(),
            policy,
            &mut flags as *mut u32 as *mut u8,
            std::mem::size_of::<u32>(),
        );
        if ok != 0 {
            Some(flags)
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn set_policy_u32(policy: u32, flags: u32) -> bool {
    // SAFETY: buffer 4 byte hợp lệ cho struct mitigation {u32 flags}
    unsafe {
        SetProcessMitigationPolicy(
            policy,
            &flags as *const u32 as *const u8,
            std::mem::size_of::<u32>(),
        ) != 0
    }
}

#[cfg(windows)]
fn query_all() -> QueriedFlags {
    let dyn_ = query_policy_u32(POLICY_DYNAMIC_CODE);
    let ext = query_policy_u32(POLICY_EXTENSION_POINT_DISABLE);
    let img = query_policy_u32(POLICY_IMAGE_LOAD);
    let sh = query_policy_u32(POLICY_STRICT_HANDLE_CHECK);
    let child = query_policy_u32(POLICY_CHILD_PROCESS);

    let all_queried =
        dyn_.is_some() && ext.is_some() && img.is_some() && sh.is_some() && child.is_some();
    QueriedFlags {
        acg_prohibit: dyn_.map(|f| f & mit_flags::DYN_PROHIBIT != 0).unwrap_or(false),
        ext_disabled: ext.map(|f| f & mit_flags::EXT_DISABLE != 0).unwrap_or(false),
        img_no_low_label: img
            .map(|f| f & mit_flags::IMG_NO_LOW_MANDATORY_LABEL != 0)
            .unwrap_or(false),
        img_no_remote: img
            .map(|f| f & mit_flags::IMG_NO_REMOTE_IMAGES != 0)
            .unwrap_or(false),
        strict_raise: sh
            .map(|f| f & mit_flags::SH_RAISE_ON_INVALID != 0)
            .unwrap_or(false),
        child_deny: child.map(|f| f & mit_flags::CHILD_DENY != 0).unwrap_or(false),
        all_queried,
    }
}

impl ProcessMitigationManager {
    /// Score thuần túy từ trạng thái đã truy vấn — cùng trọng số với spec,
    /// áp cho GIÁ TRỊ THẬT (không phải config yêu cầu).
    pub fn score_from_flags(q: &QueriedFlags) -> u32 {
        let mut score: u32 = 0;
        if q.acg_prohibit {
            score += 2000;
        }
        if q.ext_disabled {
            score += 2000;
        }
        if q.img_no_low_label {
            score += 2000;
        }
        if q.strict_raise {
            score += 1500;
        }
        if q.img_no_remote {
            score += 1500;
        }
        if !q.child_deny {
            score += 1000; // safe override cho updater/browser vẫn được phép
        }
        score.min(10000)
    }

    /// P1-3: Áp (best-effort) rồi VERIFY bằng truy vấn thật.
    /// Trạng thái báo cáo = GIÁ TRỊ TRUY VẤN trên tiến trình này.
    pub fn apply_and_verify(config: &ProcessMitigationConfig) -> ProcessMitigationStatus {
        #[cfg(windows)]
        {
            use mit_flags::*;

            // 1. Best-effort apply: set những policy config yêu cầu BẬT.
            //    Set thất bại (policy one-way/đã khóa) không tạo report giả —
            //    bước query phía dưới mới là nguồn sự thật.
            let _ = set_policy_u32(POLICY_DYNAMIC_CODE, DYN_PROHIBIT | DYN_ALLOW_THREAD_OPT_OUT);
            let _ = set_policy_u32(POLICY_EXTENSION_POINT_DISABLE, EXT_DISABLE);
            let mut img_flags = IMG_NO_LOW_MANDATORY_LABEL;
            if config.microsoft_whql_signatures_only {
                img_flags |= IMG_NO_REMOTE_IMAGES;
            }
            let _ = set_policy_u32(POLICY_IMAGE_LOAD, img_flags);
            let _ = set_policy_u32(
                POLICY_STRICT_HANDLE_CHECK,
                SH_RAISE_ON_INVALID | SH_PERMANENT,
            );
            if !config.allow_child_helpers {
                // Chỉ chặn khi cấu hình yêu cầu; default giữ safe override
                let _ = set_policy_u32(POLICY_CHILD_PROCESS, CHILD_DENY | CHILD_AUDIT);
            }

            // 2. QUERY thật — nguồn sự thật cho báo cáo
            let q = query_all();
            if !q.all_queried {
                return ProcessMitigationStatus {
                    is_acg_active: false,
                    is_extension_point_disabled: false,
                    is_image_load_restricted: false,
                    is_strict_handle_active: false,
                    is_whql_enforced: false,
                    allow_child_helpers: false,
                    is_verified: false,
                    mitigation_score: 0,
                    summary: "[UNVERIFIED — GetProcessMitigationPolicy failed; fail-closed] Mitigation state unknown: cannot claim hardening.".to_string(),
                };
            }

            let score = Self::score_from_flags(&q);
            ProcessMitigationStatus {
                is_acg_active: q.acg_prohibit,
                is_extension_point_disabled: q.ext_disabled,
                is_image_load_restricted: q.img_no_low_label,
                is_strict_handle_active: q.strict_raise,
                is_whql_enforced: q.img_no_remote,
                allow_child_helpers: !q.child_deny,
                is_verified: true,
                mitigation_score: score,
                summary: format!(
                    "[queried via GetProcessMitigationPolicy] Process Mitigations: ACG={}, ExtPts={}, ImageLoad={}, StrictHandle={}, WHQL(noRemoteImg)={}, ChildOverride={} (Score: {}/10000)",
                    q.acg_prohibit,
                    q.ext_disabled,
                    q.img_no_low_label,
                    q.strict_raise,
                    q.img_no_remote,
                    !q.child_deny,
                    score
                ),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = config;
            ProcessMitigationStatus {
                is_acg_active: false,
                is_extension_point_disabled: false,
                is_image_load_restricted: false,
                is_strict_handle_active: false,
                is_whql_enforced: false,
                allow_child_helpers: false,
                is_verified: false,
                mitigation_score: 0,
                summary:
                    "[UNVERIFIED — non-Windows platform; fail-closed] Mitigation state unknown."
                        .to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Score thuần túy phải khớp trọng số spec
    #[test]
    fn score_from_flags_matches_spec_weights() {
        // Mọi cờ on trừ child_deny (allow override) → 10000
        let full = QueriedFlags {
            acg_prohibit: true,
            ext_disabled: true,
            img_no_low_label: true,
            img_no_remote: true,
            strict_raise: true,
            child_deny: false,
            all_queried: true,
        };
        assert_eq!(ProcessMitigationManager::score_from_flags(&full), 10000);

        // Mất ACG (2000) + mất ImageLoad restrict (2000) → 6000 (khớp test_10 spec)
        let degraded = QueriedFlags {
            acg_prohibit: false,
            img_no_low_label: false,
            ..full
        };
        assert_eq!(ProcessMitigationManager::score_from_flags(&degraded), 6000);

        // Child bị deny hoàn toàn → mất 1000 bonus override
        let child_denied = QueriedFlags {
            acg_prohibit: true,
            img_no_low_label: true,
            child_deny: true,
            ..degraded
        };
        assert_eq!(ProcessMitigationManager::score_from_flags(&child_denied), 9000);
    }

    /// P1-3: trên Windows thật, query phải thành công (is_verified=true) và
    /// summary ghi rõ nguồn. Không assert giá trị cờ cụ thể vì phụ thuộc máy.
    #[test]
    fn apply_and_verify_reports_queried_state() {
        let status =
            ProcessMitigationManager::apply_and_verify(&ProcessMitigationConfig::default());
        if cfg!(windows) {
            assert!(status.is_verified, "{}", status.summary);
            assert!(status.summary.contains("queried"), "{}", status.summary);
            // Self-consistency: score phải = hàm thuần túy của chính cờ nó báo
            let q = QueriedFlags {
                acg_prohibit: status.is_acg_active,
                ext_disabled: status.is_extension_point_disabled,
                img_no_low_label: status.is_image_load_restricted,
                img_no_remote: status.is_whql_enforced,
                strict_raise: status.is_strict_handle_active,
                child_deny: !status.allow_child_helpers,
                all_queried: true,
            };
            assert_eq!(
                status.mitigation_score,
                ProcessMitigationManager::score_from_flags(&q)
            );
        } else {
            assert!(!status.is_verified);
            assert_eq!(status.mitigation_score, 0);
        }
    }

    /// Idempotent: gọi 2 lần cho kết quả nhất quán (sets không đổi trạng thái)
    #[test]
    fn apply_and_verify_is_idempotent() {
        let a = ProcessMitigationManager::apply_and_verify(&ProcessMitigationConfig::default());
        let b = ProcessMitigationManager::apply_and_verify(&ProcessMitigationConfig::default());
        if a.is_verified && b.is_verified {
            assert_eq!(a.mitigation_score, b.mitigation_score);
        }
    }
}
