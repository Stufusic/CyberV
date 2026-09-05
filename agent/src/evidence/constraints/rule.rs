//! CyberV Physical Constraint Rule Models (HCE-1)
//!
//! Ref: Docs/rv9.md HCE-1 & Rule.md Điều 4, 15, 23, 27:
//! "Không chỉ hỏi CPU hash có đúng không, mà hỏi các observations có nhất quán với nhau không?
//! VALID / INVALID / UNKNOWN. Unknown cực kỳ quan trọng (thiếu dữ liệu không đồng nghĩa giả mạo)."

use crate::hardware::models::HardwareSnapshot;
use serde::{Deserialize, Serialize};

/// Kết quả kiểm tra một luật ràng buộc vật lý
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintResult {
    /// Cấu hình vật lý hoàn toàn hợp lệ và nhất quán
    Valid,
    /// Xung đột vật lý bất khả thi (ví dụ: CPU Intel chạy trên main AMD, DDR5 trên main DDR4)
    Invalid { reason: String },
    /// Thiếu dữ liệu để đối chiếu (ví dụ: WMI không báo socket, OEM không lộ chipset)
    Unknown { missing_field: String },
}

/// Báo cáo đánh giá chi tiết của một luật ràng buộc
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEvaluation {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_version: u32,
    pub result: ConstraintResult,
    pub penalty: u32,
    pub description: String,
}

/// Trait chung cho mọi bộ kiểm tra ràng buộc vật lý
pub trait ConstraintEvaluator: Send + Sync {
    fn rule_id(&self) -> &'static str;
    fn rule_name(&self) -> &'static str;
    fn evaluate(&self, snapshot: &HardwareSnapshot) -> ConstraintEvaluation;
}
