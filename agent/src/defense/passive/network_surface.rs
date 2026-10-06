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
//! Network Surface Hardening & Inbound Audit (P24.6)
//!
//! Ref: Docs/rv13.md & Docs/rv12.md Section 2:
//! "No inbound listening service by default (không viết network attack surface = 0).
//! Agent chỉ kết nối outbound với payload giới hạn và timeout nghiêm ngặt."
//!
//! P1-3: `audit_network_surface()` thực hiện:
//! - Enumerate TCP LISTEN rows của CHÍNH tiến trình này qua GetExtendedTcpTable
//!   (không dùng param caller cung cấp nữa — dữ liệu phải đo được thật)
//! - `is_outbound_constrained` = cả 3 profile Windows Firewall đang bật
//!   (đọc registry — firewall biên hơn nữa nằm ngoài scope điểm cuối)

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

#[cfg(windows)]
mod win {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER,
    };

    pub const MIB_TCP_STATE_LISTEN: i32 = 2;
    pub const AF_INET: u32 = 2;

    /// Enumerate các port TCP đang LISTEN do CHÍNH tiến trình này sở hữu
    pub fn own_listening_ports() -> Vec<u16> {
        let pid = std::process::id();
        let mut size: u32 = 0;

        // Lần 1: hỏi kích thước buffer cần thiết
        // SAFETY: buffer null hợp lệ khi chỉ hỏi size
        let _ = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if size == 0 {
            return Vec::new();
        }

        let mut buf = vec![0u8; size as usize];
        // Lần 2: đọc bảng thật
        // SAFETY: buf đủ lớn theo size trả về từ lần hỏi trước
        let ok = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if ok != 0 {
            // ERROR_INSUFFICIENT_BUFFER/other: không đọc được bảng
            return Vec::new();
        }

        // MIB_TCPTABLE_OWNER_PID: { DWORD dwNumEntries; MIB_TCPROW_OWNER_PID table[]; }
        // MIB_TCPROW_OWNER_PID (24B): { state, localAddr, localPort(net-order),
        //                               remoteAddr, remotePort, dwOwningPid }
        if buf.len() < 4 {
            return Vec::new();
        }
        let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let mut ports = Vec::new();
        for i in 0..count {
            let off = 4 + i * 24;
            if off + 24 > buf.len() {
                break;
            }
            let state = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
            if state != MIB_TCP_STATE_LISTEN {
                continue;
            }
            let local_port_raw = u16::from_ne_bytes(buf[off + 8..off + 10].try_into().unwrap());
            let local_port = local_port_raw.swap_bytes(); // network byte order
            let owning_pid = u32::from_ne_bytes(buf[off + 20..off + 24].try_into().unwrap());
            if owning_pid == pid {
                ports.push(local_port);
            }
        }
        ports
    }

    /// Đọc EnableFirewall của 3 profile (Domain/Standard/Public) từ registry.
    /// Trả None nếu KHÔNG đọc được profile nào (không xác nhận được gì).
    pub fn all_firewall_profiles_enabled() -> Option<bool> {
        use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};

        let profile_keys = [
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
        ];

        let mut any_read = false;
        let mut all_enabled = true;
        for sub in profile_keys {
            let sub_utf16: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let value_name: Vec<u16> = "EnableFirewall"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut data: u32 = 0;
            let mut data_size: u32 = 4;
            // SAFETY: buffer u32 hợp lệ với RRF_RT_REG_DWORD
            let rc = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    sub_utf16.as_ptr(),
                    value_name.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut u32 as *mut _,
                    &mut data_size,
                )
            };
            if rc == 0 {
                any_read = true;
                if data == 0 {
                    all_enabled = false;
                }
            } else {
                // Profile không đọc được → không thể xác nhận "constrained"
                all_enabled = false;
            }
        }
        if any_read {
            Some(all_enabled)
        } else {
            None
        }
    }
}

impl NetworkSurfaceInspector {
    /// P1-3: Kiểm toán bề mặt mạng THẬT của tiến trình:
    /// - inbound = các TCP LISTEN port sở hữu bởi PID hiện tại (GetExtendedTcpTable)
    /// - outbound constrained = 3 profile Windows Firewall cùng bật (registry)
    ///
    /// Không đọc được firewall registry → `is_outbound_constrained: false`
    /// (fail-closed: không claim bị giới hạn khi không có bằng chứng).
    pub fn audit_network_surface() -> NetworkSurfaceReport {
        #[cfg(windows)]
        let listening_ports = win::own_listening_ports();
        #[cfg(not(windows))]
        let listening_ports: Vec<u16> = Vec::new();

        let has_inbound_listener = !listening_ports.is_empty();

        #[cfg(windows)]
        let is_outbound_constrained = win::all_firewall_profiles_enabled().unwrap_or(false);
        #[cfg(not(windows))]
        let is_outbound_constrained = false;

        // Điểm số: không listener + constrained → 10000;
        // không listener nhưng không chứng minh được firewall → 5000;
        // có listener → 2000 (bị trừ nặng)
        let network_surface_score = match (has_inbound_listener, is_outbound_constrained) {
            (false, true) => 10000,
            (false, false) => 5000,
            (true, _) => 2000,
        };

        let summary = format!(
            "[queried via GetExtendedTcpTable + FirewallPolicy registry] Network Surface: NoInboundListener={}, ListeningPorts={:?}, OutboundConstrained={}, MaxOutboundPayload={}B (Score: {}/10000)",
            !has_inbound_listener,
            listening_ports,
            is_outbound_constrained,
            MAX_OUTBOUND_PAYLOAD_SIZE,
            network_surface_score
        );

        NetworkSurfaceReport {
            has_inbound_listener,
            inbound_ports: listening_ports,
            is_outbound_constrained,
            max_payload_bytes: MAX_OUTBOUND_PAYLOAD_SIZE,
            timeout_seconds: STRICT_NETWORK_TIMEOUT_SECS,
            network_surface_score,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1-3: report phải self-consistent + ghi rõ nguồn đo
    #[test]
    fn audit_reports_honest_state() {
        let report = NetworkSurfaceInspector::audit_network_surface();
        assert_eq!(
            report.has_inbound_listener,
            !report.inbound_ports.is_empty()
        );
        assert!(report.summary.contains("queried"), "{}", report.summary);

        // Agent outbound-only: tiến trình test không được mở inbound listener
        assert!(
            !report.has_inbound_listener,
            "test process KHÔNG được mở inbound listener: {:?}",
            report.inbound_ports
        );
    }
}
