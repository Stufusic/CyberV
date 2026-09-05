//! CPU <-> Motherboard Physical Compatibility Constraint Evaluator
//!
//! Ref: Docs/rv9.md HCE-1:
//! "CPU socket = LGA1700, Board socket = LGA1700 -> VALID.
//! CPU Intel trên Board AMD -> INVALID.
//! Thiếu thông tin socket -> UNKNOWN."

use super::rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
use crate::hardware::models::{ComponentType, HardwareSnapshot};

pub struct CpuBoardConstraintEvaluator;

impl ConstraintEvaluator for CpuBoardConstraintEvaluator {
    fn rule_id(&self) -> &'static str {
        "HCE-R01-CPU-BOARD"
    }

    fn rule_name(&self) -> &'static str {
        "CPU & Motherboard Physical Compatibility"
    }

    fn evaluate(&self, snapshot: &HardwareSnapshot) -> ConstraintEvaluation {
        let cpu_opt = snapshot
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Cpu);
        let board_opt = snapshot
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Motherboard);

        let (cpu, board) = match (cpu_opt, board_opt) {
            (Some(c), Some(b)) => (c, b),
            (None, _) => {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Unknown {
                        missing_field: "CPU component missing from snapshot".to_string(),
                    },
                    penalty: 0,
                    description: "Không thể đối chiếu: Thiếu dữ liệu vi xử lý CPU".to_string(),
                };
            }
            (_, None) => {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Unknown {
                        missing_field: "Motherboard component missing from snapshot".to_string(),
                    },
                    penalty: 0,
                    description: "Không thể đối chiếu: Thiếu dữ liệu bo mạch chủ".to_string(),
                };
            }
        };

        let cpu_vendor = cpu
            .attributes
            .get("vendor")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let cpu_model = cpu
            .attributes
            .get("model")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let board_product = board
            .attributes
            .get("product")
            .or_else(|| board.attributes.get("model"))
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        if cpu_vendor.is_empty() && cpu_model.is_empty() {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Unknown {
                    missing_field: "cpu.vendor / cpu.model".to_string(),
                },
                penalty: 0,
                description: "Thiếu thông tin nhận diện kiến trúc CPU".to_string(),
            };
        }

        if board_product.is_empty() {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Unknown {
                    missing_field: "board.product / board.model".to_string(),
                },
                penalty: 0,
                description: "Thiếu thông tin định danh mẫu bo mạch chủ".to_string(),
            };
        }

        // 1. Kiểm tra chéo xung đột kiến trúc nền tảng (Intel CPU vs AMD Board hoặc ngược lại)
        let is_cpu_intel = cpu_vendor.contains("intel") || cpu_model.contains("intel");
        let is_cpu_amd =
            cpu_vendor.contains("amd") || cpu_model.contains("ryzen") || cpu_model.contains("epyc");

        let is_board_amd_chipset = board_product.contains("am4")
            || board_product.contains("am5")
            || board_product.contains("x670")
            || board_product.contains("b650")
            || board_product.contains("a620")
            || board_product.contains("x570")
            || board_product.contains("b550")
            || board_product.contains("a520")
            || board_product.contains("b450")
            || board_product.contains("x470");

        let is_board_intel_chipset = board_product.contains("lga1700")
            || board_product.contains("lga1200")
            || board_product.contains("z790")
            || board_product.contains("b760")
            || board_product.contains("h770")
            || board_product.contains("z690")
            || board_product.contains("b660")
            || board_product.contains("h610")
            || board_product.contains("z590")
            || board_product.contains("b560");

        if is_cpu_intel && is_board_amd_chipset {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Xung đột vật lý bất khả thi: CPU Intel ({}) không thể gắn trên bo mạch chủ AMD Chipset ({})",
                        cpu_model, board_product
                    ),
                },
                penalty: 4000,
                description: "Phát hiện giả mạo phần cứng: CPU và bo mạch chủ không cùng hệ sinh thái".to_string(),
            };
        }

        if is_cpu_amd && is_board_intel_chipset {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Xung đột vật lý bất khả thi: CPU AMD ({}) không thể gắn trên bo mạch chủ Intel Chipset ({})",
                        cpu_model, board_product
                    ),
                },
                penalty: 4000,
                description: "Phát hiện giả mạo phần cứng: CPU và bo mạch chủ không cùng hệ sinh thái".to_string(),
            };
        }

        // Hợp lệ hoặc không có xung đột
        ConstraintEvaluation {
            rule_id: self.rule_id().to_string(),
            rule_name: self.rule_name().to_string(),
            rule_version: 1,
            result: ConstraintResult::Valid,
            penalty: 0,
            description: "CPU và bo mạch chủ có kiến trúc nền tảng tương thích vật lý".to_string(),
        }
    }
}
