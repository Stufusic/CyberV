//! Instruction-Level Stub Integrity & Variant Analysis (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 3:
//! "Đừng biến expected_preamble == exact_bytes thành security truth.
//! Nên có: KNOWN_GOOD, EXPECTED_VARIANT, UNEXPECTED, UNKNOWN."

use super::baseline::NtdllBaseline;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StubVariantAssessment {
    KnownGood { ssn: u32 },
    ExpectedVariant { ssn: u32, variant_name: String },
    Unexpected { observed_bytes: Vec<u8> },
    Unknown { reason: String },
}

pub struct StubIntegrityChecker;

impl StubIntegrityChecker {
    /// Đánh giá stub lệnh của một hàm Native API (Nt*/Zw*) dựa trên baseline hệ thống
    pub fn assess_stub(code_bytes: &[u8], baseline: &NtdllBaseline) -> StubVariantAssessment {
        if code_bytes.len() < 8 {
            return StubVariantAssessment::Unknown {
                reason: format!("Buffer too short for x64 stub: {} bytes", code_bytes.len()),
            };
        }

        // 1. Biến thể 1: 4C 8B D1 B8 [SSN_LO, SSN_HI, 00, 00]
        // mov r10, rcx; mov eax, <ssn>
        if code_bytes.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8]) {
            let ssn =
                u32::from_le_bytes([code_bytes[4], code_bytes[5], code_bytes[6], code_bytes[7]]);
            return StubVariantAssessment::KnownGood { ssn };
        }

        // 2. Biến thể 2: B8 [SSN_LO, SSN_HI, 00, 00] 4C 8B D1
        // mov eax, <ssn>; mov r10, rcx (một số bản build cũ hoặc CPU tương thích)
        if code_bytes[0] == 0xB8 && code_bytes.len() >= 7 && code_bytes[5..7] == [0x4C, 0x8B] {
            let ssn =
                u32::from_le_bytes([code_bytes[1], code_bytes[2], code_bytes[3], code_bytes[4]]);
            return StubVariantAssessment::ExpectedVariant {
                ssn,
                variant_name: "MovEaxFirstVariant".to_string(),
            };
        }

        // 3. So khớp với các preambles được phê duyệt bổ sung trong baseline
        for approved in &baseline.approved_preambles {
            if code_bytes.starts_with(approved) {
                return StubVariantAssessment::ExpectedVariant {
                    ssn: 0,
                    variant_name: "BaselineApprovedGeneric".to_string(),
                };
            }
        }

        // 4. Nếu không khớp bất kỳ mẫu hợp lệ nào
        let sample_len = code_bytes.len().min(8);
        StubVariantAssessment::Unexpected {
            observed_bytes: code_bytes[..sample_len].to_vec(),
        }
    }
}
