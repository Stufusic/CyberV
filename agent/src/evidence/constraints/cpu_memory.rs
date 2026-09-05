//! CPU <-> Memory Physical Compatibility Constraint Evaluator
//!
//! Ref: Docs/rv9.md HCE-1:
//! "CPU memory capability: DDR generation & speed check.
//! CPU cũ (Intel Gen 10 trở xuống) không thể điều khiển RAM DDR5 -> INVALID.
//! Thiếu speed/generation -> UNKNOWN."

use super::rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
use crate::hardware::models::{ComponentType, HardwareSnapshot};

pub struct CpuMemoryConstraintEvaluator;

impl ConstraintEvaluator for CpuMemoryConstraintEvaluator {
    fn rule_id(&self) -> &'static str {
        "HCE-R02-CPU-MEMORY"
    }

    fn rule_name(&self) -> &'static str {
        "CPU & Memory Physical Compatibility"
    }

    fn evaluate(&self, snapshot: &HardwareSnapshot) -> ConstraintEvaluation {
        let cpu_opt = snapshot
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Cpu);
        let ram_modules: Vec<_> = snapshot
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::Memory)
            .collect();

        let cpu = match cpu_opt {
            Some(c) => c,
            None => {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Unknown {
                        missing_field: "CPU component missing".to_string(),
                    },
                    penalty: 0,
                    description: "Thiếu dữ liệu CPU để đối chiếu bộ nhớ".to_string(),
                };
            }
        };

        if ram_modules.is_empty() {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Unknown {
                    missing_field: "No RAM modules found".to_string(),
                },
                penalty: 0,
                description: "Thiếu dữ liệu thanh RAM để đối chiếu".to_string(),
            };
        }

        let cpu_model = cpu
            .attributes
            .get("model")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        // Kiểm tra xem RAM có module nào khai báo là DDR5 không (hoặc tốc độ >= 4800 MHz)
        let mut has_ddr5 = false;
        let mut has_speed_info = false;

        for ram in &ram_modules {
            let part = ram
                .attributes
                .get("part_number")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            let speed_mhz: u64 = ram
                .attributes
                .get("speed_mhz")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if speed_mhz > 0 {
                has_speed_info = true;
            }
            if part.contains("ddr5") || speed_mhz >= 4800 {
                has_ddr5 = true;
            }
        }

        if !has_speed_info && !has_ddr5 {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Unknown {
                    missing_field: "ram.speed_mhz / ram.part_number".to_string(),
                },
                penalty: 0,
                description: "Không đủ thông số tốc độ bus RAM để kết luận thế hệ DDR".to_string(),
            };
        }

        // Các CPU đời cũ chỉ hỗ trợ DDR3 / DDR4, không thể gắn DDR5
        // Ví dụ: Intel Core i7-7700, i7-8700, i7-9700, i7-10700, i7-11700 hoặc Ryzen 1000 - 5000
        let is_legacy_cpu_ddr4_only = cpu_model.contains("i7-7")
            || cpu_model.contains("i7-8")
            || cpu_model.contains("i7-9")
            || cpu_model.contains("i7-10")
            || cpu_model.contains("i5-10")
            || cpu_model.contains("i3-10")
            || cpu_model.contains("i7-11")
            || cpu_model.contains("i5-11")
            || cpu_model.contains("ryzen 5 3600")
            || cpu_model.contains("ryzen 7 3700")
            || cpu_model.contains("ryzen 5 5600")
            || cpu_model.contains("ryzen 7 5800")
            || cpu_model.contains("ryzen 9 5900")
            || cpu_model.contains("ryzen 9 5950");

        if is_legacy_cpu_ddr4_only && has_ddr5 {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Xung đột vật lý: CPU ({}) không có Memory Controller hỗ trợ RAM DDR5",
                        cpu_model
                    ),
                },
                penalty: 3500,
                description:
                    "Phát hiện giả mạo phần cứng: CPU thế hệ cũ không thể điều khiển RAM DDR5"
                        .to_string(),
            };
        }

        ConstraintEvaluation {
            rule_id: self.rule_id().to_string(),
            rule_name: self.rule_name().to_string(),
            rule_version: 1,
            result: ConstraintResult::Valid,
            penalty: 0,
            description: "CPU và cấu hình bộ nhớ RAM tương thích vật lý".to_string(),
        }
    }
}
