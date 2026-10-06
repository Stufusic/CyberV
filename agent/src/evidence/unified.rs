// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! Unified Evidence Object (HCE Section 51)
//!
//! Ref: Docs/rv10.md Section 51:
//! "Tất cả HCE phải trả về một format chung: EvidenceItem.
//! TPM evidence, Temporal evidence, Kernel evidence, Constraint evidence,
//! Topology evidence, Merkle evidence đều trở thành EvidenceItem."

use crate::hardware::models::Confidence;
use serde::{Deserialize, Serialize};

/// Phân lớp bằng chứng (Evidence Classes - Section 52)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceClass {
    Cryptographic,
    Hardware,
    Structural,
    Temporal,
    Platform,
    Behavioral,
}

impl std::fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceClass::Cryptographic => write!(f, "CRYPTOGRAPHIC"),
            EvidenceClass::Hardware => write!(f, "HARDWARE"),
            EvidenceClass::Structural => write!(f, "STRUCTURAL"),
            EvidenceClass::Temporal => write!(f, "TEMPORAL"),
            EvidenceClass::Platform => write!(f, "PLATFORM"),
            EvidenceClass::Behavioral => write!(f, "BEHAVIORAL"),
        }
    }
}

/// 5-State Taxonomy cho Bằng chứng Phần cứng (Docs/GATE0_SECURITY_CONTRACT_FREEZE.md §1.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HardwareEvidenceState {
    /// TPM 2.0 phần cứng + IOMMU bật + Kernel Bus trực tiếp khớp danh sách thiết bị
    Physical,
    /// Nhận diện cờ Hypervisor hợp lệ (CPUID leaf hypervisor, vTPM 2.0, synthetic bus)
    Virtual,
    /// Probe không thể chạy hoặc thiết bị không phản hồi (INV-007, is_hardware_verified = false)
    #[default]
    Unknown,
    /// Cổng I/O hoặc thiết bị phần cứng bị ngắt kết nối vật lý
    Unavailable,
    /// Mâu thuẫn chéo giữa các tầng (WMI vs Kernel mismatch, Spoofer detected -> ISOLATE)
    Conflicted,
}


impl HardwareEvidenceState {
    /// Điểm tin cậy tối đa dựa trên trạng thái phân loại
    pub fn base_confidence(&self) -> u32 {
        match self {
            Self::Physical => 10000,
            Self::Virtual => 7500,
            Self::Unavailable => 5000,
            Self::Unknown => 0,
            Self::Conflicted => 0,
        }
    }

    /// Trạng thái này có mâu thuẫn cần kích hoạt ISOLATE ngay lập tức không?
    pub fn is_conflicted(&self) -> bool {
        matches!(self, Self::Conflicted)
    }

    /// Trạng thái này có được coi là phần cứng xác thực hay không?
    pub fn is_hardware_verified(&self) -> bool {
        matches!(self, Self::Physical)
    }
}

/// Trọng số tin cậy tối đa cho các nguồn bằng chứng (Docs/GATE0_SECURITY_CONTRACT_FREEZE.md §1.3)
pub const MAX_CONFIDENCE_TPM_QUOTE: u32 = 10000;
pub const MAX_CONFIDENCE_KERNEL_BUS: u32 = 8500;
pub const MAX_CONFIDENCE_STORAGE_PNP: u32 = 7000;
pub const MAX_CONFIDENCE_MESH_QUORUM: u32 = 6000;
pub const MAX_CONFIDENCE_USER_WMI: u32 = 2000;

/// Trọng số nguồn thu thập bằng chứng theo ma trận tin cậy chống giả mạo
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSourceWeight {
    TpmQuote,
    KernelBusType0,
    StoragePnpDescriptor,
    MeshQuorumCorroboration,
    UserModeWmiOrRegistry,
}

impl EvidenceSourceWeight {
    pub fn max_confidence(&self) -> u32 {
        match self {
            Self::TpmQuote => MAX_CONFIDENCE_TPM_QUOTE,
            Self::KernelBusType0 => MAX_CONFIDENCE_KERNEL_BUS,
            Self::StoragePnpDescriptor => MAX_CONFIDENCE_STORAGE_PNP,
            Self::MeshQuorumCorroboration => MAX_CONFIDENCE_MESH_QUORUM,
            Self::UserModeWmiOrRegistry => MAX_CONFIDENCE_USER_WMI,
        }
    }
}


/// Nguồn gốc bằng chứng
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    TpmRootOfTrust,
    TemporalDrift,
    KernelObservation,
    PhysicalConstraints,
    HardwareTopology,
    MerkleGraph,
    VerifiableLog,
    ZeroKnowledgeProof,
    // FSE-1 to FSE-4 Defense Engines
    KernelTamperResistance,
    DmaIommuProtection,
    FirmwarePlatformIntegrity,
    VbsEnclaveCore,
    // Passive Defense Foundation (Phase 24)
    PassiveProcessMitigation,
}

/// Thực thể bằng chứng hợp nhất (Unified Evidence Item)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub evidence_type: String,
    pub evidence_class: EvidenceClass,
    pub schema_version: u32,
    pub derivation_version: u32,
    pub source: EvidenceSource,
    /// Cam kết mật mã (SHA-512 Hex)
    pub commitment: String,
    pub confidence: Confidence,
    /// Điểm đánh giá (0 - 10000)
    pub score: u32,
}

impl EvidenceItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        evidence_type: impl Into<String>,
        evidence_class: EvidenceClass,
        schema_version: u32,
        derivation_version: u32,
        source: EvidenceSource,
        commitment: impl Into<String>,
        confidence: Confidence,
        score: u32,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            evidence_type: evidence_type.into(),
            evidence_class,
            schema_version,
            derivation_version,
            source,
            commitment: commitment.into(),
            confidence,
            score: score.min(10000),
        }
    }
}
