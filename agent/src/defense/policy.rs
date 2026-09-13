//! Security Policy Engine & Evidence Fusion Integration (Phase 20)
//!
//! Ref: Docs/rv11.md Section 6, 7, 8:
//! Pipeline: Observation -> Evidence -> Commitment -> Fusion -> Policy
//! Decisions: ALLOW, STEP-UP, ISOLATE.
//! Weighted Integer Fusion (0 - 10000) across TPM, Kernel, DMA, Firmware, VBS.

use crate::defense::dma::DmaSecurityReport;
use crate::defense::enclave::EnclaveAttestationReport;
use crate::defense::firmware::FirmwareSecurityReport;
use crate::defense::kernel::AntiTamperReport;
use crate::security::assurance::AssuranceLevel;
use crate::security::freshness::EvidenceMetadata;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Cho phép truy cập bình thường (Trust verified)
    Allow,
    /// Yêu cầu xác thực tăng cường / ZKP / Re-attestation do nghi ngờ hoặc bằng chứng cũ
    StepUp {
        reason: String,
        required_assurance: AssuranceLevel,
    },
    /// Cô lập ngay lập tức: vô hiệu hóa phiên, hủy khóa, cô lập tiến trình
    Isolate { reason: String, severity: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub allow_threshold: u32,   // Mặc định: 8000
    pub step_up_threshold: u32, // Mặc định: 5000
    pub minimum_assurance: AssuranceLevel,
    pub half_life_secs: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow_threshold: 8000,
            step_up_threshold: 5000,
            minimum_assurance: AssuranceLevel::OSProtected,
            half_life_secs: 86400, // 24 giờ
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationReport {
    pub decision: PolicyDecision,
    pub composite_score: u32,
    pub achieved_assurance: AssuranceLevel,
    pub freshness_confidence: u16,
    pub rationales: Vec<String>,
    pub evaluated_at: u64,
}

pub struct SecurityPolicyEngine;

impl SecurityPolicyEngine {
    /// Đánh giá chính sách an ninh đa chiều từ tất cả các động cơ phòng thủ FSE
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        config: &PolicyConfig,
        tpm_score: u32,
        kernel_report: &AntiTamperReport,
        dma_report: &DmaSecurityReport,
        firmware_report: &FirmwareSecurityReport,
        enclave_report: &EnclaveAttestationReport,
        metadata: Option<&EvidenceMetadata>,
        now: u64,
    ) -> PolicyEvaluationReport {
        let mut rationales = Vec::new();

        // 1. Kiểm tra các điều kiện vi phạm nghiêm trọng không thể thương lượng (Non-negotiable Isolate)
        if (!kernel_report.telemetry.is_shield_active
            && kernel_report.telemetry.blocked_terminations > 0)
            || kernel_report.telemetry.driver_unload_attempts > 0
        {
            rationales.push("Phát hiện can thiệp Kernel: Driver bị ngắt kết nối hoặc có tiến trình cố gắng dừng agent/unload driver".to_string());
            return PolicyEvaluationReport {
                decision: PolicyDecision::Isolate {
                    reason: "Kernel Defense Tampered".to_string(),
                    severity: 9500,
                },
                composite_score: 0,
                achieved_assurance: AssuranceLevel::Unknown,
                freshness_confidence: 0,
                rationales,
                evaluated_at: now,
            };
        }

        // 2. Tính toán điểm số dung hợp số nguyên (Weighted Integer Fusion - 0 đến 10000):
        // TPM / Hardware Identity: 25% (2500)
        // Kernel Anti-Tamper:      20% (2000)
        // DMA / IOMMU:             20% (2000)
        // Firmware Integrity:      20% (2000)
        // VBS Enclave Core:        15% (1500)
        let weighted_sum = (tpm_score.min(10000) as u64 * 2500)
            + (kernel_report.defense_score.min(10000) as u64 * 2000)
            + (dma_report.dma_security_score.min(10000) as u64 * 2000)
            + (firmware_report.composite_score.min(10000) as u64 * 2000)
            + (enclave_report.composite_score.min(10000) as u64 * 1500);

        let mut composite_score = (weighted_sum / 10000) as u32;

        // 3. Đánh giá Cấp độ Đảm bảo An ninh (Assurance Level)
        let achieved_assurance = enclave_report.assurance_level;

        // 4. Đánh giá Độ tươi (Freshness) và Suy giảm độ tin cậy (Half-Life Decay)
        let mut freshness_confidence = 10000u16;
        if let Some(meta) = metadata {
            freshness_confidence = meta.effective_confidence(now, config.half_life_secs);
            if !meta.is_fresh(now) {
                rationales.push("Bằng chứng đã quá thời hạn hiệu lực (Expired)".to_string());
            } else if freshness_confidence < 5000 {
                rationales.push(format!(
                    "Độ tin cậy bằng chứng suy giảm do thời gian: {}/10000",
                    freshness_confidence
                ));
            }
        }

        // Áp dụng trọng số suy giảm độ tươi vào composite_score
        composite_score = ((composite_score as u64 * freshness_confidence as u64) / 10000) as u32;

        // 5. Quyết định chính sách (Policy Decision Logic)
        let decision = if composite_score < config.step_up_threshold {
            rationales.push(format!(
                "Điểm bảo mật {} dưới ngưỡng tối thiểu {}",
                composite_score, config.step_up_threshold
            ));
            PolicyDecision::Isolate {
                reason: "Composite Security Score Critically Degraded".to_string(),
                severity: 10000 - composite_score,
            }
        } else if !kernel_report.telemetry.is_shield_active || kernel_report.defense_score <= 3000 {
            // Bất biến INV-001: Không bao giờ ALLOW hoặc STEP-UP khi Kernel Shield không hoạt động hoặc driver bị gỡ
            rationales.push("Phát hiện can thiệp Kernel: Driver bị ngắt kết nối hoặc không phản hồi".to_string());
            composite_score = 0;
            PolicyDecision::Isolate {
                reason: "Kernel Defense Tampered".to_string(),
                severity: 9500,
            }
        } else if achieved_assurance < config.minimum_assurance {
            rationales.push(format!(
                "Cấp độ đảm bảo {} thấp hơn yêu cầu tối thiểu {}",
                achieved_assurance, config.minimum_assurance
            ));
            PolicyDecision::StepUp {
                reason: "Assurance Level Insufficient".to_string(),
                required_assurance: config.minimum_assurance,
            }
        } else if freshness_confidence < 6000 {
            rationales.push("Bằng chứng suy giảm độ tươi cần làm mới".to_string());
            PolicyDecision::StepUp {
                reason: "Evidence Freshness Decayed".to_string(),
                required_assurance: achieved_assurance,
            }
        } else if composite_score < config.allow_threshold {
            rationales.push(format!(
                "Điểm bảo mật {} ở mức cảnh báo (ngưỡng cho phép: {})",
                composite_score, config.allow_threshold
            ));
            PolicyDecision::StepUp {
                reason: "Security Score Below Allow Threshold".to_string(),
                required_assurance: achieved_assurance,
            }
        } else {
            rationales.push("Tất cả các chỉ số phòng thủ và cấp độ đảm bảo đạt chuẩn".to_string());
            PolicyDecision::Allow
        };

        PolicyEvaluationReport {
            decision,
            composite_score,
            achieved_assurance,
            freshness_confidence,
            rationales,
            evaluated_at: now,
        }
    }

    /// Đánh giá chính sách an ninh cục bộ tự trị khi Offline hoặc Worker bị cô lập (Phase 24.2 per Docs/rv15.md Section 13)
    /// Bất biến: Tuyệt đối không bao giờ Fail-Open / Default ALLOW khi phát hiện bất thường phần cứng.
    pub fn evaluate_autonomous_local(
        config: &PolicyConfig,
        tpm_counter_contradiction: bool,
        passive_report: &crate::defense::passive::PassiveDefenseReport,
        now: u64,
    ) -> PolicyEvaluationReport {
        let mut rationales = Vec::new();

        // 1. Vi phạm phần cứng cốt lõi không thể thương lượng: TPM Monotonic Counter Contradiction
        if tpm_counter_contradiction {
            rationales.push("Phát hiện bất nhất phần cứng: TPM NV Counter lớn hơn phiên bản phần mềm đĩa (Snapshot Rollback Attack)".to_string());
            return PolicyEvaluationReport {
                decision: PolicyDecision::Isolate {
                    reason: "Hardware Anti-Rollback Contradiction Detected".to_string(),
                    severity: 10000,
                },
                composite_score: 0,
                achieved_assurance: AssuranceLevel::Unknown,
                freshness_confidence: 0,
                rationales,
                evaluated_at: now,
            };
        }

        // 2. Vi phạm chữ ký Driver Kernel
        if !passive_report.driver.is_signer_valid {
            rationales
                .push("Driver Kernel không có chữ ký số hợp lệ hoặc bị can thiệp".to_string());
            return PolicyEvaluationReport {
                decision: PolicyDecision::Isolate {
                    reason: "Kernel Driver Untrusted".to_string(),
                    severity: 9000,
                },
                composite_score: 1000,
                achieved_assurance: AssuranceLevel::Unknown,
                freshness_confidence: 5000,
                rationales,
                evaluated_at: now,
            };
        }

        // 3. Vi phạm Module không rõ nguồn gốc (nếu có báo cáo WDAC Tầng B)
        if let Some(wdac) = &passive_report.wdac {
            if !wdac.process_modules.is_clean {
                rationales.push(format!(
                    "Phát hiện {} module lạ không rõ nguồn gốc trong tiến trình",
                    wdac.process_modules.untrusted_modules_count
                ));
                return PolicyEvaluationReport {
                    decision: PolicyDecision::Isolate {
                        reason: "Untrusted Foreign DLL Detected In Process Memory".to_string(),
                        severity: 8500,
                    },
                    composite_score: 2000,
                    achieved_assurance: AssuranceLevel::OSProtected,
                    freshness_confidence: 6000,
                    rationales,
                    evaluated_at: now,
                };
            }
        }

        // 4. Đánh giá điểm phòng ngự thụ động tổng hợp
        let composite = passive_report.composite_passive_score;
        let decision = if composite < config.step_up_threshold {
            rationales.push(format!(
                "Điểm phòng ngự thụ động cục bộ {} thấp hơn ngưỡng {}",
                composite, config.step_up_threshold
            ));
            PolicyDecision::Isolate {
                reason: "Passive Defense Degraded Offline".to_string(),
                severity: 10000 - composite,
            }
        } else if composite < config.allow_threshold {
            rationales.push(format!(
                "Điểm phòng ngự thụ động cục bộ {} cần làm mới",
                composite
            ));
            PolicyDecision::StepUp {
                reason: "Passive Defense Below Threshold Offline".to_string(),
                required_assurance: config.minimum_assurance,
            }
        } else {
            rationales
                .push("Tất cả chỉ số phòng thủ thụ động và phần cứng cục bộ toàn vẹn".to_string());
            PolicyDecision::Allow
        };

        PolicyEvaluationReport {
            decision,
            composite_score: composite,
            achieved_assurance: passive_report.assurance,
            freshness_confidence: passive_report.freshness,
            rationales,
            evaluated_at: now,
        }
    }
}
