//! Cross-Layer Validator (Userland WMI vs Kernel Probe) (HCE-6)
//!
//! Ref: Docs/rv10.md HCE-6 Section 29:
//! "CrossLayerValidator: CONSISTENT, PARTIALLY_CONSISTENT, CONTRADICTORY, UNKNOWN.
//! Phát hiện WMI Spoofer khi Userland và Kernel mâu thuẫn."

use super::client::KernelProbeProvider;
use super::protocol::KernelPciDevice;
use crate::fingerprint::graph::models::{VirtualNode, VirtualPoint};
use crate::hardware::models::{ComponentType, HardwareSnapshot, NormalizedComponent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const KERNEL_DERIVATION_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Hai tầng quan sát trùng khớp hoàn toàn
    Consistent,
    /// Trùng khớp phần lớn, có sai khác nhỏ về định dạng/chuỗi
    PartiallyConsistent,
    /// Mâu thuẫn nghiêm trọng (WMI bị can thiệp nhưng Kernel thấy phần cứng thật -> Spoofer detected!)
    Contradictory {
        component_id: String,
        userland_detail: String,
        kernel_detail: String,
    },
    /// Không có Driver Kernel (Graceful Fallback: UNKNOWN != INVALID)
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossLayerValidationReport {
    pub status: ValidationStatus,
    pub consistency_score: u32, // 0 - 10000
    pub penalty: u32,
    pub virtual_nodes: Vec<VirtualNode>,
    pub virtual_points: Vec<VirtualPoint>,
    pub description: String,
}

pub struct CrossLayerValidator;

impl CrossLayerValidator {
    /// Đối chiếu chéo thông tin giữa HardwareSnapshot (Userland WMI) và Kernel Probe
    pub fn validate<K: KernelProbeProvider>(
        snapshot: &HardwareSnapshot,
        kernel_provider: &K,
    ) -> CrossLayerValidationReport {
        if !kernel_provider.is_driver_available() {
            let vnode = create_kernel_vnode("UNKNOWN", 10000);
            let point = VirtualPoint::new(
                "point:kernel_consistency",
                10000,
                10000,
                KERNEL_DERIVATION_VERSION,
            );
            return CrossLayerValidationReport {
                status: ValidationStatus::Unknown,
                consistency_score: 10000,
                penalty: 0,
                virtual_nodes: vec![vnode],
                virtual_points: vec![point],
                description:
                    "Không có Driver Kernel (Hoạt động ở chế độ Userland baseline an toàn)"
                        .to_string(),
            };
        }

        let kernel_obs = match kernel_provider.query_kernel_observation() {
            Some(obs) => obs,
            None => {
                let vnode = create_kernel_vnode("UNKNOWN", 10000);
                let point = VirtualPoint::new(
                    "point:kernel_consistency",
                    10000,
                    10000,
                    KERNEL_DERIVATION_VERSION,
                );
                return CrossLayerValidationReport {
                    status: ValidationStatus::Unknown,
                    consistency_score: 10000,
                    penalty: 0,
                    virtual_nodes: vec![vnode],
                    virtual_points: vec![point],
                    description: "Driver Kernel không phản hồi dữ liệu".to_string(),
                };
            }
        };

        // Đối chiếu các thiết bị lưu trữ (Storage/NVMe)
        let storage_disks: Vec<_> = snapshot
            .components
            .iter()
            .filter(|c| c.component_type == ComponentType::Storage)
            .collect();

        for disk in &storage_disks {
            let raw_user_serial = disk.attributes.get("serial").cloned().unwrap_or_default();
            let clean_user = raw_user_serial
                .trim()
                .to_lowercase()
                .replace(['-', ' '], "");

            // Tìm thiết bị tương ứng trong Kernel Probe
            for kdev in &kernel_obs.devices {
                if !pci_matches_disk(kdev, disk) {
                    continue;
                }

                if let Some(k_serial) = &kdev.serial_number {
                    let clean_kernel = k_serial.trim().to_lowercase().replace(['-', ' '], "");

                    // Nếu thiết bị khớp nhưng Serial bị sai lệch nghiêm trọng -> Spoofer!
                    if !clean_user.is_empty()
                        && !clean_kernel.is_empty()
                        && clean_user != clean_kernel
                    {
                        let vnode = create_kernel_vnode("CONTRADICTORY", 1500);
                        let point = VirtualPoint::new(
                            "point:kernel_consistency",
                            1500,
                            10000,
                            KERNEL_DERIVATION_VERSION,
                        );
                        return CrossLayerValidationReport {
                            status: ValidationStatus::Contradictory {
                                component_id: disk.canonical_id.clone(),
                                userland_detail: format!("WMI Serial: {}", raw_user_serial),
                                kernel_detail: format!("Kernel Serial: {}", k_serial),
                            },
                            consistency_score: 1500,
                            penalty: 8500,
                            virtual_nodes: vec![vnode],
                            virtual_points: vec![point],
                            description: "Phát hiện mâu thuẫn chéo giữa WMI và Kernel: Serial bị giả mạo ở Userland".to_string(),
                        };
                    }
                }
            }
        }

        let vnode = create_kernel_vnode("CONSISTENT", 10000);
        let point = VirtualPoint::new(
            "point:kernel_consistency",
            10000,
            10000,
            KERNEL_DERIVATION_VERSION,
        );
        CrossLayerValidationReport {
            status: ValidationStatus::Consistent,
            consistency_score: 10000,
            penalty: 0,
            virtual_nodes: vec![vnode],
            virtual_points: vec![point],
            description: "Quan sát từ Userland WMI và Kernel Probe trùng khớp 100%".to_string(),
        }
    }
}

fn create_kernel_vnode(status: &str, score: u32) -> VirtualNode {
    let mut attrs = BTreeMap::new();
    attrs.insert("validation_status".to_string(), status.to_string());
    attrs.insert("consistency_score".to_string(), score.to_string());

    VirtualNode {
        id: "vnode:kernel_cross_validation".to_string(),
        virtual_type: "KERNEL_CROSS_VALIDATION".to_string(),
        derivation_version: KERNEL_DERIVATION_VERSION,
        input_commitments: Vec::new(),
        virtual_hash: format!("kernel_vhash_{:04}", score),
        attributes: attrs,
    }
}

fn pci_matches_disk(kdev: &KernelPciDevice, disk: &NormalizedComponent) -> bool {
    let loc = kdev.location_str();
    if disk.canonical_id.contains(&loc) {
        return true;
    }

    // Không match với các GPU vendor phổ biến nếu disk là ổ đĩa
    if kdev.vendor_id == 0x10de || (kdev.vendor_id == 0x1002 && kdev.device_id > 0x5000) {
        return false;
    }

    let model = disk
        .attributes
        .get("model")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let vendor = disk
        .attributes
        .get("vendor")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let canonical = disk.canonical_id.to_lowercase();

    let vendor_match = match kdev.vendor_id {
        0x144d => {
            model.contains("samsung") || vendor.contains("samsung") || canonical.contains("samsung")
        }
        0x15b7 => {
            model.contains("wd")
                || model.contains("western")
                || vendor.contains("wd")
                || canonical.contains("wd")
        }
        0x8086 => {
            model.contains("intel") || vendor.contains("intel") || canonical.contains("intel")
        }
        0x1344 => {
            model.contains("micron") || model.contains("crucial") || vendor.contains("micron")
        }
        0x1987 => model.contains("phison") || vendor.contains("phison"),
        0x1c5c => model.contains("hynix") || vendor.contains("hynix"),
        _ => false,
    };

    if vendor_match {
        return true;
    }

    if kdev.device_class == 0x01
        && (model.contains("nvme")
            || disk.attributes.get("interface").map(|s| s.as_str()) == Some("nvme"))
    {
        return true;
    }

    false
}
