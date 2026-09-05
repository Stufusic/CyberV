//! Firmware Evidence Fusion Engine (FSE-3)
//!
//! Ref: Docs/rv11.md Section 4:
//! Decoupled 4 distinct evidence domains:
//! Secure Boot (with dbx precedence), Platform Boot Integrity (Boot Guard/PSB),
//! SMM Security, Firmware Configuration.

use super::boot_guard::BootGuardReport;
use super::config::FirmwareConfigReport;
use super::secure_boot::SecureBootDbReport;
use super::smm::SmmSecurityReport;
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FIRMWARE_DERIVATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareSecurityReport {
    pub composite_score: u32, // 0 - 10000
    pub is_firmware_trusted: bool,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub summary: String,
}

pub struct FirmwareEvidenceFusionEngine;

impl FirmwareEvidenceFusionEngine {
    pub fn evaluate(
        secure_boot: &SecureBootDbReport,
        boot_guard: &BootGuardReport,
        smm: &SmmSecurityReport,
        config: &FirmwareConfigReport,
    ) -> FirmwareSecurityReport {
        let score_sb = secure_boot.security_score();
        let score_bg = boot_guard.security_score();
        let score_smm = smm.security_score();
        let score_cfg = config.security_score();

        // Trọng số số nguyên (Weighted integer fusion):
        // Secure Boot: 30%, Boot Guard: 30%, SMM: 20%, Config: 20%
        let weighted_sum = (score_sb as u64 * 3000)
            + (score_bg as u64 * 3000)
            + (score_smm as u64 * 2000)
            + (score_cfg as u64 * 2000);
        let composite_score = (weighted_sum / 10000) as u32;

        let is_firmware_trusted = composite_score >= 8000;

        // Virtual Points
        let p_sb = VirtualPoint::new(
            "point:firmware_secure_boot",
            score_sb as i64,
            10000,
            FIRMWARE_DERIVATION_VERSION,
        );
        let p_bg = VirtualPoint::new(
            "point:firmware_boot_guard",
            score_bg as i64,
            10000,
            FIRMWARE_DERIVATION_VERSION,
        );
        let p_smm = VirtualPoint::new(
            "point:firmware_smm",
            score_smm as i64,
            10000,
            FIRMWARE_DERIVATION_VERSION,
        );
        let p_cfg = VirtualPoint::new(
            "point:firmware_config",
            score_cfg as i64,
            10000,
            FIRMWARE_DERIVATION_VERSION,
        );
        let p_fw = VirtualPoint::new(
            "point:firmware_security",
            composite_score as i64,
            10000,
            FIRMWARE_DERIVATION_VERSION,
        );

        // Virtual Nodes
        let mut sb_attrs = BTreeMap::new();
        sb_attrs.insert(
            "secure_boot_enabled".to_string(),
            secure_boot.is_secure_boot_enabled.to_string(),
        );
        sb_attrs.insert("dbx_count".to_string(), secure_boot.dbx_count.to_string());
        let vn_sb = VirtualNode {
            id: "vnode:secure_boot_integrity".to_string(),
            virtual_type: "SECURE_BOOT_INTEGRITY".to_string(),
            derivation_version: FIRMWARE_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("sb_vhash_{:04}", score_sb),
            attributes: sb_attrs,
        };

        let mut bg_attrs = BTreeMap::new();
        bg_attrs.insert(
            "boot_guard_fused".to_string(),
            boot_guard.is_fused.to_string(),
        );
        bg_attrs.insert(
            "verified_boot".to_string(),
            boot_guard.verified_boot_enabled.to_string(),
        );
        let vn_bg = VirtualNode {
            id: "vnode:platform_boot_integrity".to_string(),
            virtual_type: "PLATFORM_BOOT_INTEGRITY".to_string(),
            derivation_version: FIRMWARE_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("bg_vhash_{:04}", score_bg),
            attributes: bg_attrs,
        };

        let mut smm_attrs = BTreeMap::new();
        smm_attrs.insert(
            "smm_lockdown".to_string(),
            smm.smm_core_lockdown.to_string(),
        );
        smm_attrs.insert(
            "smi_confidence".to_string(),
            smm.smi_telemetry_confidence.to_string(),
        );
        let vn_smm = VirtualNode {
            id: "vnode:smm_security".to_string(),
            virtual_type: "SMM_SECURITY".to_string(),
            derivation_version: FIRMWARE_DERIVATION_VERSION,
            input_commitments: Vec::new(),
            virtual_hash: format!("smm_vhash_{:04}", score_smm),
            attributes: smm_attrs,
        };

        let summary = format!(
            "Firmware Security Score: {}/10000 (SB: {}, BootGuard: {}, SMM: {}, Config: {})",
            composite_score, score_sb, score_bg, score_smm, score_cfg
        );

        FirmwareSecurityReport {
            composite_score,
            is_firmware_trusted,
            virtual_nodes: vec![vn_sb, vn_bg, vn_smm],
            virtual_points: vec![p_sb, p_bg, p_smm, p_cfg, p_fw],
            summary,
        }
    }
}
