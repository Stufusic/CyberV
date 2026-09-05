//! Network Surface Hardening & Inbound Audit (P24.6)
//!
//! Ref: Docs/rv13.md & Docs/rv12.md Section 2:
//! "No inbound listening service by default (không viết network attack surface = 0).
//! Agent chỉ kết nối outbound với payload giới hạn và timeout nghiêm ngặt."

use serde::{Deserialize, Serialize};

pub const MAX_OUTBOUND_PAYLOAD_SIZE: usize = 1048576; // 1 MB Maximum bounded payload
pub const STRICT_NETWORK_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSurfaceReport {
    pub has_inbound_listener: bool,
    pub inbound_ports: Vec<u16>,
    pub is_outbound_constrained: bool,
    pub max_payload_bytes: usize,
    pub timeout_seconds: u64,
    pub network_surface_score: u32, // 0 - 10000
    pub summary: String,
}

pub struct NetworkSurfaceInspector;

impl NetworkSurfaceInspector {
    /// Kiểm toán bề mặt mạng của tiến trình (Inbound port scan)
    pub fn audit_network_surface(listening_ports: Vec<u16>) -> NetworkSurfaceReport {
        let has_inbound_listener = !listening_ports.is_empty();

        // Điểm số: Nếu không có listening port (inbound = 0) -> 10000, nếu có -> 2000 (bị trừ nặng)
        let network_surface_score = if !has_inbound_listener { 10000 } else { 2000 };

        let summary = format!(
            "Network Surface: NoInboundListener={}, ListeningPorts={:?}, MaxOutboundPayload={}B (Score: {}/10000)",
            !has_inbound_listener,
            listening_ports,
            MAX_OUTBOUND_PAYLOAD_SIZE,
            network_surface_score
        );

        NetworkSurfaceReport {
            has_inbound_listener,
            inbound_ports: listening_ports,
            is_outbound_constrained: true,
            max_payload_bytes: MAX_OUTBOUND_PAYLOAD_SIZE,
            timeout_seconds: STRICT_NETWORK_TIMEOUT_SECS,
            network_surface_score,
            summary,
        }
    }
}
