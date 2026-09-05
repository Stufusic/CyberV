//! Storage <-> Platform Physical Compatibility Constraint Evaluator
//!
//! Ref: Docs/rv9.md HCE-1:
//! "Storage protocol vs Platform check.
//! Ổ cứng ảo hóa (QEMU, Msft Virtual) trên bo mạch chủ vật lý cao cấp -> Platform inconsistency."

use super::rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
use crate::hardware::models::{ComponentType, HardwareSnapshot};

pub struct StorageBusConstraintEvaluator;

impl ConstraintEvaluator for StorageBusConstraintEvaluator {
    fn rule_id(&self) -> &'static str {
        "HCE-R04-STORAGE-PLATFORM"
    }

    fn rule_name(&self) -> &'static str {
        "Storage & Platform Physical Compatibility"
    }

    fn evaluate(&self, snapshot: &HardwareSnapshot) -> ConstraintEvaluation {
        let storage_modules: Vec<_> = snapshot
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::Storage)
            .collect();
        let board_opt = snapshot
            .components
            .iter()
            .find(|c| c.component_type == ComponentType::Motherboard);

        if storage_modules.is_empty() {
            return ConstraintEvaluation {
                rule_id: self.rule_id().to_string(),
                rule_name: self.rule_name().to_string(),
                rule_version: 1,
                result: ConstraintResult::Unknown {
                    missing_field: "No storage devices found".to_string(),
                },
                penalty: 0,
                description: "Thiếu dữ liệu ổ đĩa lưu trữ".to_string(),
            };
        }

        let board_product = board_opt
            .and_then(|b| {
                b.attributes
                    .get("product")
                    .or_else(|| b.attributes.get("model"))
            })
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        let is_baremetal_enthusiast_board = board_product.contains("rog strix")
            || board_product.contains("aorus")
            || board_product.contains("tuf gaming")
            || board_product.contains("mpg carbon")
            || board_product.contains("mag tomahawk")
            || board_product.contains("taichi");

        for disk in &storage_modules {
            let model = disk
                .attributes
                .get("model")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            let interface = disk
                .attributes
                .get("interface")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            // 1. Kiểm tra mâu thuẫn giữa model và interface
            if model.contains("nvme") && interface == "ide" {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Invalid {
                        reason: "Ổ đĩa NVMe không thể chạy qua chuẩn giao tiếp cổ điển IDE"
                            .to_string(),
                    },
                    penalty: 3000,
                    description: "Phát hiện giả mạo giao tiếp lưu trữ".to_string(),
                };
            }

            // 2. Ổ đĩa ảo hóa thuần túy xuất hiện trên bo mạch chủ ép xung vật lý
            let is_virtual_disk = model.contains("qemu")
                || model.contains("msft virtual disk")
                || model.contains("vmware virtual");

            if is_virtual_disk && is_baremetal_enthusiast_board {
                return ConstraintEvaluation {
                    rule_id: self.rule_id().to_string(),
                    rule_name: self.rule_name().to_string(),
                    rule_version: 1,
                    result: ConstraintResult::Invalid {
                        reason: format!(
                            "Xung đột nền tảng: Ổ đĩa máy ảo ({}) chạy trên bo mạch chủ vật lý cao cấp ({})",
                            model, board_product
                        ),
                    },
                    penalty: 3500,
                    description: "Phát hiện bất thường môi trường: Ổ cứng ảo hóa cắm trên bo mạch vật lý cao cấp".to_string(),
                };
            }
        }

        ConstraintEvaluation {
            rule_id: self.rule_id().to_string(),
            rule_name: self.rule_name().to_string(),
            rule_version: 1,
            result: ConstraintResult::Valid,
            penalty: 0,
            description: "Giao tiếp ổ đĩa và nền tảng bo mạch tương thích hợp lệ".to_string(),
        }
    }
}
