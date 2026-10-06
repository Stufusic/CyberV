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
//! Memory Controller & Channel Interleaving Topology (HCE-2)
//!
//! Ref: Docs/rv9.md HCE-2:
//! "CPU Memory Controller -> Channel A / Channel B -> DIMM 0 / DIMM 1.
//! Topology Consistency & Dual-Channel Detection."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryChannelMode {
    SingleChannel,
    DualChannel,
    TripleChannel,
    QuadChannel,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySlotInfo {
    pub slot_id: String, // "DIMM_0", "DIMM_1"
    pub bank_label: String,
    pub populated: bool,
    pub module_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryChannel {
    pub channel_id: String, // "Channel_A", "Channel_B"
    pub slots: Vec<MemorySlotInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryTopology {
    pub controller_id: String,
    pub channels: Vec<MemoryChannel>,
    pub channel_mode: MemoryChannelMode,
    pub total_slots: usize,
    pub populated_slots: usize,
    pub commitment_hash: String,
}
