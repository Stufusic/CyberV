//! Temporal Trajectory Engine Builder (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5 Section 17 & 19:
//! "Virtual Node: vnode:storage_trajectory, Virtual Point: point:temporal_consistency."

use super::anomaly::TemporalAnomalyDetector;
use super::collector::StorageTelemetryCollector;
use super::model::{StorageTrajectory, TemporalEvaluation};
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use std::collections::BTreeMap;

pub const TEMPORAL_DERIVATION_VERSION: u32 = 1;

pub struct TemporalTrajectoryReport {
    pub evaluations: Vec<TemporalEvaluation>,
    pub overall_score: u32,
    pub has_anomalies: bool,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
}

pub struct TemporalTrajectoryEngine<C: StorageTelemetryCollector> {
    collector: C,
}

impl<C: StorageTelemetryCollector> TemporalTrajectoryEngine<C> {
    pub fn new(collector: C) -> Self {
        Self { collector }
    }

    /// Đánh giá toàn bộ danh sách ổ đĩa hiện tại so với lịch sử quan sát trước đó
    pub fn evaluate_trajectories(
        &self,
        current_disks: &[String],
        previous_trajectories: &BTreeMap<String, StorageTrajectory>,
        current_time: u64,
    ) -> TemporalTrajectoryReport {
        let mut evaluations = Vec::new();
        let mut total_score: u64 = 0;
        let mut has_anomalies = false;

        for disk_id in current_disks {
            let current_telemetry = self
                .collector
                .collect_telemetry(disk_id)
                .unwrap_or_else(|| StorageTrajectory::new(disk_id.clone(), current_time));

            let prev = previous_trajectories.get(disk_id);
            let eval = TemporalAnomalyDetector::evaluate_drift(&current_telemetry, prev);

            if eval.penalty > 0 {
                has_anomalies = true;
            }
            total_score += eval.consistency_score as u64;
            evaluations.push(eval);
        }

        let overall_score = if evaluations.is_empty() {
            10000
        } else {
            (total_score / evaluations.len() as u64) as u32
        };

        // 1. Tạo Virtual Point cho Temporal Consistency
        let virtual_points = vec![VirtualPoint::new(
            "point:temporal_consistency",
            overall_score as i64,
            10000,
            TEMPORAL_DERIVATION_VERSION,
        )];

        // 2. Tạo Virtual Node cho Storage Trajectory
        let mut node_attrs = BTreeMap::new();
        node_attrs.insert("overall_score".to_string(), overall_score.to_string());
        node_attrs.insert("has_anomalies".to_string(), has_anomalies.to_string());
        node_attrs.insert("evaluated_disks".to_string(), evaluations.len().to_string());

        let input_commitments = evaluations
            .iter()
            .map(|e| e.commitment_hash.clone())
            .collect();

        let vnode = VirtualNode {
            id: "vnode:storage_trajectory".to_string(),
            virtual_type: "STORAGE_TRAJECTORY".to_string(),
            derivation_version: TEMPORAL_DERIVATION_VERSION,
            input_commitments,
            virtual_hash: evaluations
                .first()
                .map(|e| e.commitment_hash.clone())
                .unwrap_or_default(),
            attributes: node_attrs,
        };

        TemporalTrajectoryReport {
            evaluations,
            overall_score,
            has_anomalies,
            virtual_nodes: vec![vnode],
            virtual_points,
        }
    }
}
