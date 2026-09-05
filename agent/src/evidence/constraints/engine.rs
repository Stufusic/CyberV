//! Physical Constraint Engine Coordinator (HCE-1)
//!
//! Ref: Docs/rv9.md HCE-1 & Rule.md Điều 4, 15:
//! "Constraint Evaluation -> Virtual Constraint Nodes -> Virtual Evidence Points (0-10000)."

use super::board_memory::BoardMemoryConstraintEvaluator;
use super::cpu_board::CpuBoardConstraintEvaluator;
use super::cpu_memory::CpuMemoryConstraintEvaluator;
use super::rule::{ConstraintEvaluation, ConstraintEvaluator, ConstraintResult};
use super::storage_bus::StorageBusConstraintEvaluator;
use crate::fingerprint::canonical::CanonicalEncoder;
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use crate::hardware::models::HardwareSnapshot;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

pub const DERIVATION_VERSION: u32 = 1;

/// Kết quả tổng thể sau khi thẩm định toàn bộ hệ luật ràng buộc vật lý
#[derive(Debug, Clone)]
pub struct PhysicalConstraintReport {
    pub evaluations: Vec<ConstraintEvaluation>,
    pub is_physically_valid: bool,
    pub has_invalid_conflicts: bool,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
}

pub struct PhysicalConstraintEngine {
    evaluators: Vec<Box<dyn ConstraintEvaluator>>,
}

impl Default for PhysicalConstraintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalConstraintEngine {
    pub fn new() -> Self {
        Self {
            evaluators: vec![
                Box::new(CpuBoardConstraintEvaluator),
                Box::new(CpuMemoryConstraintEvaluator),
                Box::new(BoardMemoryConstraintEvaluator),
                Box::new(StorageBusConstraintEvaluator),
            ],
        }
    }

    /// Thẩm định toàn bộ ràng buộc trên snapshot phần cứng
    pub fn evaluate(&self, snapshot: &HardwareSnapshot) -> PhysicalConstraintReport {
        let mut evaluations = Vec::new();
        let mut has_invalid = false;
        let mut total_penalty = 0u32;

        for eval in &self.evaluators {
            let res = eval.evaluate(snapshot);
            if let ConstraintResult::Invalid { .. } = res.result {
                has_invalid = true;
                total_penalty += res.penalty;
            }
            evaluations.push(res);
        }

        // Tính điểm ảo platform_consistency (thang điểm 10000, số nguyên)
        let consistency_score = if total_penalty >= 10000 {
            0
        } else {
            10000 - total_penalty as i64
        };

        let virtual_points = vec![VirtualPoint::new(
            "point:platform_consistency",
            consistency_score,
            10000,
            DERIVATION_VERSION,
        )];

        // Sinh các Virtual Nodes tương ứng
        let mut virtual_nodes = Vec::new();
        for eval in &evaluations {
            let mut attrs = BTreeMap::new();
            attrs.insert("rule_id".to_string(), eval.rule_id.clone());
            attrs.insert("rule_name".to_string(), eval.rule_name.clone());
            match &eval.result {
                ConstraintResult::Valid => {
                    attrs.insert("status".to_string(), "VALID".to_string());
                }
                ConstraintResult::Invalid { reason } => {
                    attrs.insert("status".to_string(), "INVALID".to_string());
                    attrs.insert("reason".to_string(), reason.clone());
                }
                ConstraintResult::Unknown { missing_field } => {
                    attrs.insert("status".to_string(), "UNKNOWN".to_string());
                    attrs.insert("missing_field".to_string(), missing_field.clone());
                }
            }

            let vnode_id = format!("vnode:{}", eval.rule_id.to_lowercase().replace('-', "_"));
            let virtual_hash = compute_virtual_node_hash(&vnode_id, &attrs);

            virtual_nodes.push(VirtualNode {
                id: vnode_id,
                virtual_type: "PHYSICAL_CONSTRAINT".to_string(),
                derivation_version: DERIVATION_VERSION,
                input_commitments: Vec::new(),
                virtual_hash,
                attributes: attrs,
            });
        }

        // Virtual Node tổng hợp độ nhất quán nền tảng
        let mut platform_attrs = BTreeMap::new();
        platform_attrs.insert(
            "platform_validity".to_string(),
            if has_invalid {
                "INVALID".to_string()
            } else {
                "VALID".to_string()
            },
        );
        platform_attrs.insert(
            "consistency_score".to_string(),
            consistency_score.to_string(),
        );
        let platform_hash =
            compute_virtual_node_hash("vnode:platform_consistency", &platform_attrs);

        virtual_nodes.push(VirtualNode {
            id: "vnode:platform_consistency".to_string(),
            virtual_type: "PLATFORM_CONSISTENCY".to_string(),
            derivation_version: DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: platform_hash,
            attributes: platform_attrs,
        });

        PhysicalConstraintReport {
            evaluations,
            is_physically_valid: !has_invalid,
            has_invalid_conflicts: has_invalid,
            virtual_nodes,
            virtual_points,
        }
    }
}

fn compute_virtual_node_hash(id: &str, attrs: &BTreeMap<String, String>) -> String {
    let mut encoder = CanonicalEncoder::new();
    encoder.add_field("virtual_id", id);
    for (k, v) in attrs {
        encoder.add_field(k, v);
    }
    let canonical = encoder.to_canonical_bytes();
    let mut hasher = Sha512::new();
    hasher.update(b"CYBERV/DBS/VIRTUAL_CONSTRAINT/v1\0");
    hasher.update(canonical);
    format!("{:x}", hasher.finalize())
}
