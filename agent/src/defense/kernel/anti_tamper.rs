//! Anti-Tamper Orchestration & Degradation Detection (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Driver unload / service tampering: Nếu attacker cố stop driver, disable service,
//! replace driver -> tạo vnode:kernel_defense_degraded chứ không phải agent chết im."

use super::registration::ProtectedProcessRegistration;
use super::telemetry::ShieldTelemetry;
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const KERNEL_TAMPER_DERIVATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiTamperReport {
    pub registration: ProtectedProcessRegistration,
    pub telemetry: ShieldTelemetry,
    pub is_tampering_detected: bool,
    pub defense_score: u32, // 0 - 10000
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub summary: String,
}

pub struct AntiTamperManager;

impl AntiTamperManager {
    /// Đánh giá tình trạng tự vệ và phát hiện hành vi can thiệp nhân / tiến trình
    pub fn evaluate(
        registration: &ProtectedProcessRegistration,
        telemetry: &ShieldTelemetry,
        driver_reachable: bool,
    ) -> AntiTamperReport {
        let mut virtual_nodes = Vec::new();
        let mut defense_score: u32 = 10000;
        let mut is_tampering_detected = false;

        // 1. Kiểm tra xem driver có bị gỡ bỏ hoặc dịch vụ bị dừng hay không
        if !driver_reachable {
            is_tampering_detected = true;
            defense_score = 3000; // Giáng điểm nặng khi driver bị triệt tiêu

            let mut attrs = BTreeMap::new();
            attrs.insert("tamper_type".to_string(), "DRIVER_UNREACHABLE".to_string());
            attrs.insert("tamper_alert".to_string(), "true".to_string());
            attrs.insert(
                "description".to_string(),
                "Driver bảo vệ Ring-0 không phản hồi hoặc đã bị can thiệp gỡ bỏ".to_string(),
            );

            virtual_nodes.push(VirtualNode {
                id: "vnode:kernel_defense_degraded".to_string(),
                virtual_type: "KERNEL_DEFENSE_DEGRADED".to_string(),
                derivation_version: KERNEL_TAMPER_DERIVATION_VERSION,
                input_commitments: Vec::new(),
                virtual_hash: "tamper_driver_degraded_hash".to_string(),
                attributes: attrs,
            });
        }

        // 2. Kiểm tra các nỗ lực can thiệp handle trái phép bị chặn
        if telemetry.has_tampering_attempts() {
            is_tampering_detected = true;
            let penalty = (telemetry.total_blocked() * 500)
                .max(telemetry.driver_unload_attempts * 2000)
                .min(5000);
            defense_score = defense_score.saturating_sub(penalty);

            let mut attrs = BTreeMap::new();
            attrs.insert(
                "blocked_terminations".to_string(),
                telemetry.blocked_terminations.to_string(),
            );
            attrs.insert(
                "blocked_vm_reads".to_string(),
                telemetry.blocked_vm_reads.to_string(),
            );
            attrs.insert(
                "blocked_vm_writes".to_string(),
                telemetry.blocked_vm_writes.to_string(),
            );
            attrs.insert(
                "driver_unload_attempts".to_string(),
                telemetry.driver_unload_attempts.to_string(),
            );
            attrs.insert("tamper_alert".to_string(), "true".to_string());

            virtual_nodes.push(VirtualNode {
                id: "vnode:process_tamper_attempt".to_string(),
                virtual_type: "PROCESS_TAMPER_ATTEMPT".to_string(),
                derivation_version: KERNEL_TAMPER_DERIVATION_VERSION,
                input_commitments: Vec::new(),
                virtual_hash: format!("tamper_events_{}", telemetry.total_blocked()),
                attributes: attrs,
            });
        }

        // 3. Tạo virtual point phản ánh điểm kháng cự can thiệp
        let virtual_point = VirtualPoint::new(
            "point:kernel_tamper_resistance",
            defense_score as i64,
            10000,
            KERNEL_TAMPER_DERIVATION_VERSION,
        );

        let summary = if is_tampering_detected {
            format!(
                "CẢNH BÁO CAN THIỆP: Phát hiện nỗ lực tấn công tiến trình hoặc driver! Điểm kháng cự: {}/10000",
                defense_score
            )
        } else {
            format!(
                "Trạng thái tự vệ Kernel Tamper Resistance ổn định (PID {}), Điểm: 10000/10000",
                registration.pid
            )
        };

        AntiTamperReport {
            registration: registration.clone(),
            telemetry: telemetry.clone(),
            is_tampering_detected,
            defense_score,
            virtual_nodes,
            virtual_points: vec![virtual_point],
            summary,
        }
    }
}
