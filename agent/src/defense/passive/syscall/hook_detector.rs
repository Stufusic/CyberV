//! NTDLL Hook & Anomaly Classification Analyzer (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 4 & Section 18:
//! "NtdllIntegrityAnalyzer: entrypoint inspection, code-range verification,
//! instruction boundary validation, module ownership, anomaly classification.
//! EDR Coexistence: Phải phân biệt giữa EDR hợp lệ và mã độc, không tự đánh nhau với hệ thống bảo vệ khác."

use super::baseline::NtdllBaseline;
use super::stub_integrity::{StubIntegrityChecker, StubVariantAssessment};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookAssessment {
    Clean,
    Suspected {
        detour_type: String,
        target_displacement: i64,
    },
    KnownSecuritySoftwareInstrumentation {
        vendor_or_module: String,
    },
    Contradictory {
        detail: String,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionIntegrityObservation {
    pub function_name: String,
    pub stub_assessment: StubVariantAssessment,
    pub hook_assessment: HookAssessment,
    pub is_within_ntdll_range: bool,
}

pub struct NtdllIntegrityAnalyzer;

impl NtdllIntegrityAnalyzer {
    /// Phân tích tính toàn vẹn của một hàm Native API
    pub fn analyze_function(
        function_name: &str,
        code_bytes: &[u8],
        is_target_in_ntdll: bool,
        known_security_vendor: Option<&str>,
        baseline: &NtdllBaseline,
    ) -> FunctionIntegrityObservation {
        if code_bytes.is_empty() {
            return FunctionIntegrityObservation {
                function_name: function_name.to_string(),
                stub_assessment: StubVariantAssessment::Unknown {
                    reason: "Empty code buffer".to_string(),
                },
                hook_assessment: HookAssessment::Unknown {
                    reason: "No code bytes available to analyze".to_string(),
                },
                is_within_ntdll_range: is_target_in_ntdll,
            };
        }

        let stub_assessment = StubIntegrityChecker::assess_stub(code_bytes, baseline);

        // 1. Kiểm tra các mẫu Detour / Hook phổ biến
        let hook_assessment = if let Some(vendor) = known_security_vendor {
            // Nhận diện phần mềm bảo vệ đã biết (EDR/AV Coexistence - Section 18)
            HookAssessment::KnownSecuritySoftwareInstrumentation {
                vendor_or_module: vendor.to_string(),
            }
        } else if code_bytes[0] == 0xE9 && code_bytes.len() >= 5 {
            // JMP rel32 (E9 xx xx xx xx)
            let displacement =
                i32::from_le_bytes([code_bytes[1], code_bytes[2], code_bytes[3], code_bytes[4]])
                    as i64;
            if !is_target_in_ntdll {
                HookAssessment::Suspected {
                    detour_type: "JmpRel32OutsideModule".to_string(),
                    target_displacement: displacement,
                }
            } else {
                HookAssessment::Contradictory {
                    detail: "Internal jmp detour pointing within ntdll range".to_string(),
                }
            }
        } else if code_bytes.len() >= 6 && code_bytes[0..2] == [0xFF, 0x25] {
            // JMP qword ptr [rip + offset] (FF 25 xx xx xx xx)
            HookAssessment::Suspected {
                detour_type: "IndirectRipRelativeJmp".to_string(),
                target_displacement: 0,
            }
        } else if code_bytes.len() >= 12
            && code_bytes[0..2] == [0x48, 0xB8]
            && code_bytes[10..12] == [0xFF, 0xE0]
        {
            // MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
            HookAssessment::Suspected {
                detour_type: "MovRaxImm64JmpRax".to_string(),
                target_displacement: 0,
            }
        } else {
            match stub_assessment {
                StubVariantAssessment::KnownGood { .. }
                | StubVariantAssessment::ExpectedVariant { .. } => HookAssessment::Clean,
                StubVariantAssessment::Unexpected { .. } => {
                    if !is_target_in_ntdll {
                        HookAssessment::Suspected {
                            detour_type: "UnexpectedNonMatchingPreamble".to_string(),
                            target_displacement: 0,
                        }
                    } else {
                        HookAssessment::Contradictory {
                            detail: "Non-standard preamble within valid module space".to_string(),
                        }
                    }
                }
                StubVariantAssessment::Unknown { ref reason } => HookAssessment::Unknown {
                    reason: reason.clone(),
                },
            }
        };

        FunctionIntegrityObservation {
            function_name: function_name.to_string(),
            stub_assessment,
            hook_assessment,
            is_within_ntdll_range: is_target_in_ntdll,
        }
    }
}
