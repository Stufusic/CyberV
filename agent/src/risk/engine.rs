//! CyberV Multi-Signal Risk Engine & Decision Matrix
//!
//! Ref: Pipeline.md Section 29, Plan.md Section 19, Rule.md Điều 4, 15:
//! "Không dùng một tỷ lệ similarity duy nhất để ra quyết định...
//! Tính điểm số nguyên 0-10000, không dùng float...
//! Phân định rạch ròi AutoPromote vs RequiresUserApproval vs Rejected."

use super::models::{PolicyDecision, RiskAssessment, RiskLevel, RiskSignal};
use crate::fingerprint::graph::diff::{EvidenceGraphDiff, GraphChangeOp};
use crate::fingerprint::graph::models::DeviceEvidenceGraph;
use crate::hardware::models::{CollectionSource, ComponentStatus};
use std::collections::BTreeMap;

// Trọng số phạt điểm rủi ro số nguyên (trên thang 10000)
pub const PENALTY_ROLLBACK: u32 = 10000;
pub const PENALTY_VERSION_JUMP: u32 = 1000;
pub const PENALTY_RAM_MUTATION: u32 = 1500;
pub const PENALTY_STORAGE_MUTATION: u32 = 2500;
pub const PENALTY_CPU_MUTATION: u32 = 4000;
pub const PENALTY_MOTHERBOARD_MUTATION: u32 = 5500;
pub const PENALTY_SOURCE_DEGRADED: u32 = 1500;
pub const PENALTY_PARTIAL_STATUS: u32 = 1000;

/// Evaluates multi-dimensional risk from graph diff, evidence points, and transition parameters
pub fn evaluate_risk(
    diff: &EvidenceGraphDiff,
    old_graph: &DeviceEvidenceGraph,
    new_graph: &DeviceEvidenceGraph,
    old_version: u32,
    new_version: u32,
) -> RiskAssessment {
    let mut signals = Vec::new();
    let mut breakdown = BTreeMap::new();
    let mut total_score = 0u32;

    // 1. Tín hiệu Kiểm soát Phiên bản Trạng thái (Rollback & Version Jump Protection)
    if new_version <= old_version {
        let penalty = PENALTY_ROLLBACK;
        total_score += penalty;
        signals.push(RiskSignal {
            code: "ROLLBACK_ATTACK_DETECTED".to_string(),
            penalty,
            description: format!(
                "Tấn công rollback phiên bản: new_version ({}) <= old_version ({})",
                new_version, old_version
            ),
        });
        breakdown.insert("rollback".to_string(), penalty);
    } else if new_version > old_version + 1 {
        let penalty = PENALTY_VERSION_JUMP;
        total_score += penalty;
        signals.push(RiskSignal {
            code: "VERSION_JUMP_ANOMALY".to_string(),
            penalty,
            description: format!(
                "Nhảy cóc phiên bản không liên tục: từ {} lên {}",
                old_version, new_version
            ),
        });
        breakdown.insert("version_jump".to_string(), penalty);
    }

    // 2. Tín hiệu Biến động Linh kiện Vật lý (Hardware Mutation Signals)
    let mut has_ram_change = false;
    let mut has_storage_change = false;
    let mut has_cpu_change = false;
    let mut has_board_change = false;

    for change in &diff.changes {
        match change.operation {
            GraphChangeOp::NodeModified | GraphChangeOp::NodeAdded | GraphChangeOp::NodeRemoved => {
                if change.target_id.starts_with("ram:") {
                    has_ram_change = true;
                } else if change.target_id.starts_with("disk:") {
                    has_storage_change = true;
                } else if change.target_id.starts_with("cpu:") {
                    has_cpu_change = true;
                } else if change.target_id.starts_with("board:") {
                    has_board_change = true;
                }
            }
            _ => {}
        }
    }

    if has_ram_change {
        total_score += PENALTY_RAM_MUTATION;
        signals.push(RiskSignal {
            code: "MUTATION_RAM".to_string(),
            penalty: PENALTY_RAM_MUTATION,
            description: "Phát hiện thay đổi cấu hình bộ nhớ RAM (nâng cấp hoặc hoán đổi mô-đun)"
                .to_string(),
        });
        breakdown.insert("ram_mutation".to_string(), PENALTY_RAM_MUTATION);
    }

    if has_storage_change {
        total_score += PENALTY_STORAGE_MUTATION;
        signals.push(RiskSignal {
            code: "MUTATION_STORAGE".to_string(),
            penalty: PENALTY_STORAGE_MUTATION,
            description: "Phát hiện thay đổi hoặc bổ sung ổ đĩa lưu trữ (Disk/SSD)".to_string(),
        });
        breakdown.insert("storage_mutation".to_string(), PENALTY_STORAGE_MUTATION);
    }

    if has_cpu_change {
        total_score += PENALTY_CPU_MUTATION;
        signals.push(RiskSignal {
            code: "MUTATION_CPU".to_string(),
            penalty: PENALTY_CPU_MUTATION,
            description: "Phát hiện thay thế vi xử lý chính (CPU)".to_string(),
        });
        breakdown.insert("cpu_mutation".to_string(), PENALTY_CPU_MUTATION);
    }

    if has_board_change {
        total_score += PENALTY_MOTHERBOARD_MUTATION;
        signals.push(RiskSignal {
            code: "MUTATION_MOTHERBOARD".to_string(),
            penalty: PENALTY_MOTHERBOARD_MUTATION,
            description:
                "Phát hiện thay đổi bo mạch chủ (Motherboard swap - Biến động nền tảng lớn)"
                    .to_string(),
        });
        breakdown.insert("board_mutation".to_string(), PENALTY_MOTHERBOARD_MUTATION);
    }

    // 3. Tín hiệu Điểm Bằng chứng Ảo (Virtual Points Degradation)
    let old_points: BTreeMap<&str, i64> = old_graph
        .virtual_points
        .iter()
        .map(|p| (p.id.as_str(), p.normalized_ratio()))
        .collect();

    for new_p in &new_graph.virtual_points {
        if let Some(&old_ratio) = old_points.get(new_p.id.as_str()) {
            let new_ratio = new_p.normalized_ratio();
            if new_ratio < old_ratio {
                let diff_points = (old_ratio - new_ratio) as u32;
                total_score += diff_points;
                signals.push(RiskSignal {
                    code: format!("POINT_DEGRADATION_{}", new_p.id),
                    penalty: diff_points,
                    description: format!(
                        "Điểm bằng chứng ảo {} suy giảm từ {} xuống {}",
                        new_p.id, old_ratio, new_ratio
                    ),
                });
                breakdown.insert(format!("degrade_{}", new_p.id), diff_points);
            }
        }
    }

    // 4. Tín hiệu Nguồn Quan sát & Độ Hoàn thiện (Observation Source Integrity)
    let old_has_wmi = old_graph
        .nodes
        .iter()
        .any(|n| n.source == CollectionSource::WindowsWmi);
    let new_only_sysinfo = new_graph
        .nodes
        .iter()
        .all(|n| n.source == CollectionSource::Sysinfo);

    if old_has_wmi && new_only_sysinfo {
        total_score += PENALTY_SOURCE_DEGRADED;
        signals.push(RiskSignal {
            code: "SOURCE_CONFIDENCE_DEGRADED".to_string(),
            penalty: PENALTY_SOURCE_DEGRADED,
            description: "Nguồn quan sát bị hạ cấp từ WindowsWmi xuống Sysinfo fallback"
                .to_string(),
        });
        breakdown.insert("source_degraded".to_string(), PENALTY_SOURCE_DEGRADED);
    }

    let has_partial = new_graph
        .nodes
        .iter()
        .any(|n| n.status == ComponentStatus::Partial);
    if has_partial {
        total_score += PENALTY_PARTIAL_STATUS;
        signals.push(RiskSignal {
            code: "PARTIAL_HARDWARE_ATTRIBUTES".to_string(),
            penalty: PENALTY_PARTIAL_STATUS,
            description: "Một số linh kiện thiếu thuộc tính định danh đầy đủ (Partial status)"
                .to_string(),
        });
        breakdown.insert("partial_attributes".to_string(), PENALTY_PARTIAL_STATUS);
    }

    // Giới hạn điểm trần ở 10000
    let final_score = total_score.min(10000);

    // 5. Phân Loại Cấp Độ Rủi Ro (Risk Level)
    let level = if final_score <= 1000 {
        RiskLevel::Low
    } else if final_score <= 3000 {
        RiskLevel::Medium
    } else if final_score <= 7000 {
        RiskLevel::High
    } else {
        RiskLevel::Critical
    };

    // 6. Ra Quyết Định Ma Trận (Decision Matrix)
    let decision = if final_score == 0 {
        PolicyDecision::Trusted
    } else if new_version <= old_version {
        PolicyDecision::Rejected
    } else if (has_board_change && has_cpu_change) || (has_board_change && has_storage_change) {
        // Thay đổi đồng thời bo mạch chủ và CPU/Storage: dấu hiệu tráo đổi máy hoàn toàn hoặc clone VM
        PolicyDecision::Rejected
    } else if final_score <= 3000 && !has_cpu_change && !has_board_change {
        // Biến động lành tính chỉ gồm RAM hoặc 1 Disk phụ
        PolicyDecision::AutoPromote
    } else if final_score <= 7000 {
        // Cần người dùng chủ động duyệt
        PolicyDecision::RequiresUserApproval
    } else {
        PolicyDecision::Rejected
    };

    RiskAssessment {
        score: final_score,
        level,
        decision,
        signals,
        breakdown,
    }
}
