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
