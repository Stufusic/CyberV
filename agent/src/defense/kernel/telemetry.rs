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
//! Shield Telemetry & Handle Operations (FSE-1)
//!
//! Ref: Docs/rv11.md Section 2:
//! "Handle-operation telemetry: Đừng chỉ block. Phân biệt ALLOW, DENY, SUSPICIOUS, UNKNOWN
//! và đưa event vào Evidence Graph."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandleOperationResult {
    Allow,
    Deny,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldTelemetry {
    pub protected_pid: u32,
    pub blocked_terminations: u32,
    pub blocked_vm_reads: u32,
    pub blocked_vm_writes: u32,
    pub suspicious_attempts: u32,
    pub driver_unload_attempts: u32,
    pub is_shield_active: bool,
}

impl ShieldTelemetry {
    pub fn active(protected_pid: u32) -> Self {
        Self {
            protected_pid,
            blocked_terminations: 0,
            blocked_vm_reads: 0,
            blocked_vm_writes: 0,
            suspicious_attempts: 0,
            driver_unload_attempts: 0,
            is_shield_active: true,
        }
    }

    pub fn inactive() -> Self {
        Self {
            protected_pid: 0,
            blocked_terminations: 0,
            blocked_vm_reads: 0,
            blocked_vm_writes: 0,
            suspicious_attempts: 0,
            driver_unload_attempts: 0,
            is_shield_active: false,
        }
    }

    pub fn total_blocked(&self) -> u32 {
        // Counters den tu kernel co the rat lon khi bi spam open-process;
        // cong sat thay vi cong thuan de tranh overflow (panic debug / wrap release).
        self.blocked_terminations
            .saturating_add(self.blocked_vm_reads)
            .saturating_add(self.blocked_vm_writes)
    }

    pub fn has_tampering_attempts(&self) -> bool {
        self.total_blocked() > 0 || self.suspicious_attempts > 0 || self.driver_unload_attempts > 0
    }
}
