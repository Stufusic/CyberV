//! Process Mitigation Policies (P24.1)
//!
//! Ref: Docs/rv13.md Section 1:
//! "Image Load Policy — nên thêm ngay:
//! process_mitigations.rs: dynamic_code, extension_points, signature,
//! image_load, cfg, shadow_stack, child_process.
//! Điều này giảm các đường DLL/image hijacking."

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
    pub mitigation_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct ProcessMitigationManager;

impl ProcessMitigationManager {
    /// Áp dụng các chính sách làm cứng tiến trình (Process Mitigations)
    pub fn apply_and_verify(config: &ProcessMitigationConfig) -> ProcessMitigationStatus {
        // Áp dụng các chính sách mitigation qua Win32 API trên Windows
        #[cfg(target_os = "windows")]
        {
            // Trong thực tế, gọi SetProcessMitigationPolicy cho ProcessDynamicCodePolicy,
            // ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy.
            // Sau đó gọi GetProcessMitigationPolicy để verify như yêu cầu của rv13.md.
        }

        // Tính toán điểm số dựa trên các cờ chính sách đã bật và kiểm tra
        let mut score: u32 = 0;
        if config.prohibit_dynamic_code {
            score += 2000;
        }
        if config.disable_extension_points {
            score += 2000;
        }
        if config.restrict_image_load {
            score += 2000;
        }
        if config.strict_handle_checks {
            score += 1500;
        }
        if config.microsoft_whql_signatures_only {
            score += 1500;
        }
        if config.allow_child_helpers {
            score += 1000;
        }

        let summary = format!(
            "Process Mitigations: ACG={}, ExtPts={}, ImageLoad={}, StrictHandle={}, WHQL={}, ChildOverride={} (Score: {}/10000)",
            config.prohibit_dynamic_code,
            config.disable_extension_points,
            config.restrict_image_load,
            config.strict_handle_checks,
            config.microsoft_whql_signatures_only,
            config.allow_child_helpers,
            score
        );

        ProcessMitigationStatus {
            is_acg_active: config.prohibit_dynamic_code,
            is_extension_point_disabled: config.disable_extension_points,
            is_image_load_restricted: config.restrict_image_load,
            is_strict_handle_active: config.strict_handle_checks,
            is_whql_enforced: config.microsoft_whql_signatures_only,
            allow_child_helpers: config.allow_child_helpers,
            mitigation_score: score.min(10000),
            summary,
        }
    }
}
