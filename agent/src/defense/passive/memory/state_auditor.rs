//! Dynamic Memory State & W^X Observation Auditor (Phase 24.1)
//!
//! Ref: Docs/rv14.md Section 5 & Section 6:
//! "VirtualQuery/VirtualQueryEx cung cấp thông tin region, protection và state của virtual memory.
//! MEM_PRIVATE + executable != malicious (có thể là legitimate private mappings).
//! RWX -> high-signal anomaly.
//! RX + MEM_PRIVATE -> low/medium-signal anomaly.
//! Bỏ memory_integrity_score khỏi scanner! Scanner chỉ nên trả về MemoryObservation[]."

use serde::{Deserialize, Serialize};

// Các hằng số cờ bộ nhớ chuẩn của Windows
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_IMAGE: u32 = 0x1000000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_PRIVATE: u32 = 0x20000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySignalStrength {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryAnomalyClass {
    RwxRegion,
    ExecutablePrivateRegion,
    UnexpectedProtectionTransition,
    UnknownExecutableSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryObservation {
    /// Độ lệch tương đối trong không gian tiến trình (không dùng con trỏ tuyệt đối để bảo vệ privacy)
    pub region_base_offset: u64,
    pub region_size: usize,
    pub protection_flags: u32,
    pub memory_type: u32,
    pub anomaly_class: Option<MemoryAnomalyClass>,
    pub signal_strength: Option<AnomalySignalStrength>,
    pub first_seen: u64,
    pub last_seen: u64,
}

pub struct MemoryStateAuditor;

impl MemoryStateAuditor {
    /// Đánh giá một vùng bộ nhớ ảo thu thập được và phân loại hiện trạng
    pub fn assess_region(
        region_base_offset: u64,
        region_size: usize,
        protection_flags: u32,
        memory_type: u32,
        timestamp: u64,
    ) -> MemoryObservation {
        let (anomaly_class, signal_strength) = if (protection_flags & PAGE_EXECUTE_READWRITE) != 0
            || (protection_flags & PAGE_EXECUTE_WRITECOPY) != 0
        {
            // Vi phạm W^X nghiêm trọng: Cho phép vừa ghi vừa thực thi mã
            (
                Some(MemoryAnomalyClass::RwxRegion),
                Some(AnomalySignalStrength::High),
            )
        } else if (memory_type & MEM_PRIVATE) != 0
            && ((protection_flags & PAGE_EXECUTE) != 0
                || (protection_flags & PAGE_EXECUTE_READ) != 0)
        {
            // Vùng nhớ thực thi Private (không ánh xạ từ Image file đĩa cứng)
            // Tín hiệu trung bình/thấp: có thể là JIT/runtime engine hoặc reflective loading
            (
                Some(MemoryAnomalyClass::ExecutablePrivateRegion),
                Some(AnomalySignalStrength::Medium),
            )
        } else {
            // Vùng nhớ thông thường hợp lệ
            (None, None)
        };

        MemoryObservation {
            region_base_offset,
            region_size,
            protection_flags,
            memory_type,
            anomaly_class,
            signal_strength,
            first_seen: timestamp,
            last_seen: timestamp,
        }
    }

    /// Quét một tập hợp danh sách các vùng nhớ ảo và trả về danh sách quan sát thuần túy
    pub fn audit_regions(
        raw_regions: &[(u64, usize, u32, u32)],
        timestamp: u64,
    ) -> Vec<MemoryObservation> {
        raw_regions
            .iter()
            .map(|&(offset, size, prot, mem_type)| {
                Self::assess_region(offset, size, prot, mem_type, timestamp)
            })
            .collect()
    }
}
