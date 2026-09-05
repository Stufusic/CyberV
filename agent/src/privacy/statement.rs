//! Device Statement & Policy Specification (HCE-7)
//!
//! Ref: Docs/rv10.md HCE-7 Section 34 & 35:
//! Public Statement, Policy requirements (CPU, RAM, TPM, Kernel), Nonce, Circuit Version.

use serde::{Deserialize, Serialize};

/// Chính sách ràng buộc phần cứng thiết bị của hệ thống (Device Policy)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePolicy {
    pub policy_id: String,
    pub version: u32,
    /// Danh sách họ CPU được phép (VD: ["intel", "amd", "6"])
    pub allowed_cpu_families: Vec<String>,
    /// Dung lượng RAM tối thiểu (bytes)
    pub min_memory_bytes: u64,
    /// Yêu cầu có TPM 2.0 hoạt động hợp lệ
    pub require_tpm: bool,
    /// Yêu cầu tính nhất quán giữa Kernel Probe và Userland WMI
    pub require_kernel_consistent: bool,
}

impl DevicePolicy {
    pub fn enterprise_baseline() -> Self {
        Self {
            policy_id: "pol:enterprise_baseline_v1".to_string(),
            version: 1,
            allowed_cpu_families: vec!["intel".to_string(), "amd".to_string(), "6".to_string()],
            min_memory_bytes: 8 * 1024 * 1024 * 1024, // 8 GB
            require_tpm: true,
            require_kernel_consistent: true,
        }
    }

    pub fn permissive() -> Self {
        Self {
            policy_id: "pol:permissive_v1".to_string(),
            version: 1,
            allowed_cpu_families: Vec::new(),
            min_memory_bytes: 0,
            require_tpm: false,
            require_kernel_consistent: false,
        }
    }
}

/// Mệnh đề phần cứng công khai (Public Statement)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatement {
    pub statement_id: String,
    /// Gốc Merkle công khai của đồ thị phần cứng (SHA-512 hex)
    pub public_root: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub nonce: String,
    pub circuit_version: u32,
    pub issued_at: u64,
}

impl DeviceStatement {
    pub fn new(
        statement_id: impl Into<String>,
        public_root: impl Into<String>,
        policy: &DevicePolicy,
        nonce: impl Into<String>,
        circuit_version: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            statement_id: statement_id.into(),
            public_root: public_root.into(),
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
            nonce: nonce.into(),
            circuit_version,
            issued_at: now,
        }
    }
}
