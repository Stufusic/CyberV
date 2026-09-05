//! Process-Level Module Inventory & Authenticode Verifier (Phase 24.2)
//!
//! Ref: Docs/rv15.md Section 8:
//! "Layer B: CyberV process integrity: module inventory, signature, publisher, path, hash, expected dependency."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleClassification {
    /// DLL hệ thống Windows mang chữ ký gốc Microsoft (ntdll, kernel32...)
    MicrosoftSignedSystemDll,
    /// Nhị phân nội bộ mang chữ ký CyberV Corporation
    CyberVSignedModule,
    /// DLL từ các giải pháp EDR / Antivirus tương thích được công nhận
    KnownSecurityProductDll,
    /// DLL lạ, không có chữ ký số hoặc chữ ký không xác định (Nguy cơ cao)
    UntrustedOrUnsignedDll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub module_name: String,
    pub module_path: String,
    pub has_valid_signature: bool,
    pub publisher: String,
    pub classification: ModuleClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessModuleIntegrityReport {
    pub total_modules_audited: usize,
    pub untrusted_modules_count: usize,
    pub is_clean: bool,
    pub modules: Vec<ModuleEntry>,
    pub module_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct ProcessModuleInspector;

impl ProcessModuleInspector {
    /// Phân loại một module dựa trên chữ ký và nhà phát hành
    pub fn classify_module(
        _module_name: &str,
        module_path: &str,
        has_valid_signature: bool,
        publisher: &str,
    ) -> ModuleClassification {
        if !has_valid_signature {
            return ModuleClassification::UntrustedOrUnsignedDll;
        }

        if publisher.contains("Microsoft Windows") || publisher.contains("Microsoft Corporation") {
            ModuleClassification::MicrosoftSignedSystemDll
        } else if publisher.contains("CyberV Corporation") {
            ModuleClassification::CyberVSignedModule
        } else if publisher.contains("CrowdStrike")
            || publisher.contains("SentinelOne")
            || publisher.contains("Windows Defender")
        {
            ModuleClassification::KnownSecurityProductDll
        } else if module_path.to_lowercase().contains("windows\\system32") {
            ModuleClassification::MicrosoftSignedSystemDll
        } else {
            ModuleClassification::UntrustedOrUnsignedDll
        }
    }

    /// Kiểm toán danh mục các module đã nạp vào không gian tiến trình CyberV
    pub fn audit_modules(modules: Vec<ModuleEntry>) -> ProcessModuleIntegrityReport {
        let total = modules.len();
        let untrusted_count = modules
            .iter()
            .filter(|m| m.classification == ModuleClassification::UntrustedOrUnsignedDll)
            .count();

        let is_clean = untrusted_count == 0;
        let module_score = if is_clean {
            10000
        } else {
            // Giảm trừ điểm số nghiêm khắc cho mỗi module lạ không rõ nguồn gốc
            10000u32.saturating_sub((untrusted_count as u32) * 3000)
        };

        let summary = format!(
            "Process Module Audit: Total={}, Untrusted={}, IsClean={}, Score={}/10000",
            total, untrusted_count, is_clean, module_score
        );

        ProcessModuleIntegrityReport {
            total_modules_audited: total,
            untrusted_modules_count: untrusted_count,
            is_clean,
            modules,
            module_score,
            summary,
        }
    }
}
