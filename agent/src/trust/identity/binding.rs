// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
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
//! Hybrid Device Identity Binding (HCE-4)
//!
//! Ref: Docs/rv10.md HCE-4 Section 5:
//! "Binding: Primary TPM key or Graceful Fallback to Software Vault."

use super::hardware_identity::HardwareIdentity;
use super::software_identity::SoftwareIdentity;
use crate::trust::tpm::TpmError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssuranceLevel {
    /// Mức tin cậy tối đa: Khóa sinh và niêm phong trong chip TPM 2.0 (10000)
    HardwareTpm,
    /// Mức tin cậy phần mềm: Khóa lưu trong DPAPI AES-256-GCM Vault (6000)
    SoftwareVault,
    /// Mức tin cậy suy giảm (3000)
    Degraded,
}

impl AssuranceLevel {
    pub fn score(&self) -> u32 {
        match self {
            AssuranceLevel::HardwareTpm => 10000,
            AssuranceLevel::SoftwareVault => 6000,
            AssuranceLevel::Degraded => 3000,
        }
    }
}

/// Danh tính lai tự động thích ứng với năng lực phần cứng máy
#[derive(Clone)]
pub enum HybridDeviceIdentity {
    Hardware(HardwareIdentity),
    Software(SoftwareIdentity),
}

impl HybridDeviceIdentity {
    /// Mức đảm bảo báo TRUNG THỰC theo cờ thực của khóa: chỉ khi khóa thực sự
    /// được quản lý bởi TPM non-exportable mới được tính HardwareTpm.
    /// Khóa mô phỏng phần mềm (dù nằm trong variant Hardware) bị hạ xuống
    /// SoftwareVault — chặn việc máy clone mượn danh "TPM-backed".
    pub fn assurance_level(&self) -> AssuranceLevel {
        match self {
            HybridDeviceIdentity::Hardware(hw) if hw.key.is_hardware_backed => {
                AssuranceLevel::HardwareTpm
            }
            HybridDeviceIdentity::Hardware(_) | HybridDeviceIdentity::Software(_) => {
                AssuranceLevel::SoftwareVault
            }
        }
    }

    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, HybridDeviceIdentity::Hardware(_))
    }

    pub fn public_key_hex(&self) -> String {
        match self {
            HybridDeviceIdentity::Hardware(hw) => hw.public_key_hex(),
            HybridDeviceIdentity::Software(sw) => sw.public_key_hex(),
        }
    }

    pub fn sign_attestation(&self, data: &[u8]) -> Result<String, TpmError> {
        match self {
            HybridDeviceIdentity::Hardware(hw) => hw.sign(data),
            HybridDeviceIdentity::Software(sw) => Ok(sw.sign(data)),
        }
    }
}
