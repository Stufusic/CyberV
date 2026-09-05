//! Motherboard <-> Memory Physical Compatibility Constraint Evaluator
//!
//! Ref: Docs/rv9.md HCE-1:
//! "Board D4 (DDR4) không thể cắm thanh RAM DDR5 -> INVALID.
//! Bo mạch AM5 (chỉ hỗ trợ DDR5) cắm RAM DDR4 -> INVALID.
//! Thiếu thông số -> UNKNOWN."

use super::rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
use crate::hardware::models::{ComponentType, HardwareSnapshot};

pub struct BoardMemoryConstraintEvaluator;

impl ConstraintEvaluator for BoardMemoryConstraintEvaluator {
    fn rule_id(&self) -> &'static str {
        "HCE-R03-BOARD-MEMORY"
    }

    fn rule_name(&self) -> &'static str {
        "Motherboard & Memory Physical Compatibility"
    }

    fn evaluate(&self, snapshot: &HardwareSnapshot) -> ConstraintEvaluation {
        let board_opt = snapshot
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Motherboard);
        let ram_modules: Vec<_> = snapshot
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::Memory)
            .collect();

        let board = match board_opt {
            Some(b) => b,
            None => {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Unknown {
                        missing_field: "Motherboard component missing".to_string(),
                    },
                    penalty: 0,
                    description: "Thiếu dữ liệu bo mạch chủ".to_string(),
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
                description: "Thiếu dữ liệu thanh RAM".to_string(),
            };
        }

        let board_product = board
            .attributes
            .get("product")
            .or_else(|| board.attributes.get("model"))
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        let mut has_ddr5 = false;
        let mut has_ddr4 = false;

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

            if part.contains("ddr5") || speed_mhz >= 4800 {
                has_ddr5 = true;
            } else if part.contains("ddr4") || (2133..=3600).contains(&speed_mhz) {
                has_ddr4 = true;
            }
        }

        // 1. Bo mạch chủ chỉ hỗ trợ DDR4 (Ví dụ: tên chứa D4, DDR4, hoặc chipset B450/B550/Z390/Z490)
        let is_board_ddr4_only = board_product.contains(" d4")
            || board_product.contains("-d4")
            || board_product.contains("ddr4")
            || board_product.contains("b450")
            || board_product.contains("b550")
            || board_product.contains("a520")
            || board_product.contains("z390")
            || board_product.contains("z490");

        if is_board_ddr4_only && has_ddr5 {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Xung đột khe cắm: Bo mạch chủ DDR4 ({}) không thể cắm vừa chân thanh RAM DDR5",
                        board_product
                    ),
                },
                penalty: 4000,
                description: "Phát hiện giả mạo phần cứng: Khe cắm DIMM bo mạch không tương thích chân RAM DDR5".to_string(),
            };
        }

        // 2. Nền tảng AM5 chỉ hỗ trợ DDR5, không thể chạy DDR4
        let is_am5_board = board_product.contains("am5")
            || board_product.contains("b650")
            || board_product.contains("x670")
            || board_product.contains("a620");

        if is_am5_board && has_ddr4 && !has_ddr5 {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Xung đột khe cắm: Bo mạch chủ AM5 ({}) chỉ hỗ trợ DDR5, không tương thích RAM DDR4",
                        board_product
                    ),
                },
                penalty: 4000,
                description: "Phát hiện giả mạo phần cứng: Bo mạch thế hệ AM5 không tương thích RAM DDR4".to_string(),
            };
        }

        // 3. Kiểm tra số lượng thanh RAM bất thường (trên 8 thanh cho máy trạm thông thường)
        if ram_modules.len() > 8 {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Invalid {
                    reason: format!(
                        "Số lượng thanh RAM ({}) vượt quá số khe cắm vật lý tối đa của bo mạch",
                        ram_modules.len()
                    ),
                },
                penalty: 2500,
                description: "Số lượng thanh RAM vượt mức vật lý bo mạch hỗ trợ".to_string(),
            };
        }

        ConstraintEvaluation {
            rule_id: self.rule_id().to_string(),
            rule_name: self.rule_name().to_string(),
            rule_version: 1,
            result: ConstraintResult::Valid,
            penalty: 0,
            description: "Bo mạch chủ và cấu hình khe cắm RAM tương thích hoàn toàn".to_string(),
        }
    }
}
