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
//! Assurance Level Definition (Phase 15.5)
//!
//! Ref: Docs/rv11.md Section 7:
//! "AssuranceLevel: Unknown, Software, OSProtected, HardwareBacked, Attested.
//! Giúp phân loại cấp độ đảm bảo thực tế của từng nguồn bằng chứng."

use serde::{Deserialize, Serialize};

/// Cấp độ đảm bảo an ninh của bằng chứng (Assurance Level)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssuranceLevel {
    /// Chưa xác định hoặc không đủ thông tin tin cậy
    Unknown = 0,
    /// Bằng chứng thu thập từ tầng Userland, phần mềm thuần túy (dễ bị can thiệp)
    Software = 1,
    /// Bằng chứng được bảo vệ bởi ranh giới hệ điều hành (OS / Kernel / Driver)
    OSProtected = 2,
    /// Bằng chứng được bảo vệ trực tiếp bởi vi mạch phần cứng chuyên dụng (TPM 2.0 / IOMMU)
    HardwareBacked = 3,
    /// Bằng chứng đã qua kiểm định đo lường mã hóa không thể chối bỏ (ZKP / TPM Quote / Measured Boot)
    Attested = 4,
}

impl AssuranceLevel {
    /// Quy đổi cấp độ đảm bảo sang điểm số nguyên (0 - 10000)
    pub fn score(&self) -> u32 {
        match self {
            AssuranceLevel::Unknown => 0,
            AssuranceLevel::Software => 2500,
            AssuranceLevel::OSProtected => 5000,
            AssuranceLevel::HardwareBacked => 8000,
            AssuranceLevel::Attested => 10000,
        }
    }

    pub fn is_hardware_or_better(&self) -> bool {
        matches!(
            self,
            AssuranceLevel::HardwareBacked | AssuranceLevel::Attested
        )
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssuranceLevel::Unknown => write!(f, "UNKNOWN"),
            AssuranceLevel::Software => write!(f, "SOFTWARE"),
            AssuranceLevel::OSProtected => write!(f, "OS_PROTECTED"),
            AssuranceLevel::HardwareBacked => write!(f, "HARDWARE_BACKED"),
            AssuranceLevel::Attested => write!(f, "ATTESTED"),
        }
    }
}
