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
//! WiFi Direct Tier B (M-3) — gói shim WFD; data path là TCP thuần.
//!
//! Ref: M-PLAN §4 + plan NSG §10 (Tier B experimental, flag tắt mặc định).
//! Kiến trúc đúng HYBRID §1.1: shim C++ chỉ transliterate WinRT
//! (`WiFiDirectAdvertisementPublisher`/`Watcher`/`WiFiDirectDevice`) — TOÀN
//! BỘ logic (framing, AEAD, handshake, graph) nằm Rust. Phiên WFD cấp
//! endpoint pair (IP:port) — Rust tự TCP connect trên đó và tái dụng
//! `TcpLink` với `path_class(WiFiDirect, subnet)` ⇒ path diversity thật
//! cho quorum (khác class với TCP LAN cùng segment).
//!
//! Trung thực: WFD không có sẵn trên mọi máy (adapter/radio) — shim trả
//! RADIO_OFF/OS_ERROR, tầng này nổi lên làm `MeshError`, không giả vờ thấy
//! peer. Fault-injection carrier thật (ngắt sóng giữa handshake) cần 2 máy
//! vật lý — operator-level; tại đây boundary test + fault ở tầng connect
//! (timeout → E_TIMEOUT → link không được đăng ký).

use std::net::SocketAddr;

use super::super::MeshError;
use super::shim;
use super::{Endpoint, TransportId};

/// Kết quả poll ConnectionRequested: (requests mới, số entry drop do trần).
pub type PollConnectionsResult = Result<(Vec<String>, u64), super::super::MeshError>;

/// Transport Tier B — engine giữ một instance advertise (ConnectionRequested
/// buffer phía accept); initiator kết nối theo device_id đã pin enrollment.
#[derive(Debug, Default)]
pub struct WfdTransport {
    advertising: bool,
}

/// Endpoint mà shim WFD trả về — family marker khớp `subnet_scope`:
/// byte 0 = 4 (IPv4, 4 octet theo sau) hoặc 6 (IPv6, 8 nhóm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfdEndpoint {
    pub addr: SocketAddr,
}

/// Giải mã endpoint từ shim (buffer 17 byte: marker + IP) → SocketAddr.
/// Dữ liệu do shim WinRT cấp (không phải mạng thô) nhưng vẫn bounds-kiểm:
/// family marker sai = lỗi rõ.
pub fn decode_endpoint(ip_buf: &[u8; 17], port: u16) -> Result<WfdEndpoint, MeshError> {
    let std_ip = match ip_buf[0] {
        4 => {
            let octets = [ip_buf[1], ip_buf[2], ip_buf[3], ip_buf[4]];
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip_buf[1..17]);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        other => {
            return Err(MeshError::InvalidEndpoint(format!(
                "family marker endpoint WFD lạ: {other}"
            )))
        }
    };
    if port == 0 {
        return Err(MeshError::InvalidEndpoint("port WFD = 0".into()));
    }
    Ok(WfdEndpoint { addr: SocketAddr::new(std_ip, port) })
}

impl WfdTransport {
    /// Bật quảng bá discoverability (peer tìm thấy mình). Shim lỗi → nổi lên.
    pub fn advertise(&mut self) -> Result<(), MeshError> {
        if self.advertising {
            return Err(MeshError::InvalidEndpoint("WFD advertise đã bật".into()));
        }
        let res = shim::wfd_advertise_start();
        if res.status != shim::ShimStatus::Ok {
            return Err(res.to_mesh_error("wfd_advertise_start"));
        }
        self.advertising = true;
        Ok(())
    }

    pub fn advertise_stop(&mut self) -> Result<(), MeshError> {
        if !self.advertising {
            return Err(MeshError::InvalidEndpoint("WFD advertise chưa bật".into()));
        }
        let res = shim::wfd_advertise_stop();
        self.advertising = false;
        if res.status != shim::ShimStatus::Ok {
            return Err(res.to_mesh_error("wfd_advertise_stop"));
        }
        Ok(())
    }

    /// Poll ConnectionRequested mới (peer yêu cầu phiên tới mình — phía
    /// accept). Số drop do trần queue đọc được — không drop âm thầm.
    /// Kết quả poll: (device_id requests mới, số entry bị drop do trần queue).
    pub fn poll_connections(&mut self) -> PollConnectionsResult {
        if !self.advertising {
            return Err(MeshError::InvalidEndpoint("WFD advertise chưa bật".into()));
        }
        let dropped = shim::wfd_requests_dropped()
            .map_err(|r| r.to_mesh_error("wfd_requests_dropped"))?;
        let mut requests = Vec::new();
        while let Some(device_id) = shim::wfd_requests_next()
            .map_err(|r| r.to_mesh_error("wfd_requests_next"))?
        {
            requests.push(device_id);
        }
        Ok((requests, dropped))
    }

    pub fn is_advertising(&self) -> bool {
        self.advertising
    }
}

/// Thiết lập phiên WFD tới peer (hoặc ACCEPT kết nối đến — cùng WinRT API)
/// và trả endpoint TCP thuần để Rust tự connect + handshake.
pub fn establish_endpoint(device_id_utf16: &[u16], timeout_ms: u32) -> Result<WfdEndpoint, MeshError> {
    if device_id_utf16.is_empty() {
        return Err(MeshError::InvalidEndpoint("device_id WFD rỗng".into()));
    }
    let (ip16, port) = shim::wfd_connect(device_id_utf16, timeout_ms)
        .map_err(|r| r.to_mesh_error("wfd_connect"))?;
    decode_endpoint(&ip16, port)
}

pub fn endpoint_of(transport: TransportId, addr: SocketAddr) -> Endpoint {
    Endpoint { transport, addr }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_decode_ipv4_and_family_guards() {
        let mut ip_buf = [0u8; 17];
        ip_buf[0] = 4;
        ip_buf[1..5].copy_from_slice(&[192, 168, 137, 7]);
        let ep = decode_endpoint(&ip_buf, 49152).unwrap();
        assert_eq!(ep.addr.to_string(), "192.168.137.7:49152");

        // Family marker lạ → lỗi rõ (không đoán).
        let mut bad = ip_buf;
        bad[0] = 9;
        assert!(matches!(decode_endpoint(&bad, 1000), Err(MeshError::InvalidEndpoint(_))));
        // Port 0 → lỗi.
        assert!(matches!(decode_endpoint(&ip_buf, 0), Err(MeshError::InvalidEndpoint(_))));

        // IPv6: marker 6 + đủ 16 octet sau marker.
        let mut ip6 = [0u8; 17];
        ip6[0] = 6;
        ip6[2] = 0xFD;
        let ep6 = decode_endpoint(&ip6, 80).unwrap();
        assert!(ep6.addr.is_ipv6());
    }

    #[test]
    fn wfd_path_class_differs_from_tcp_lan_same_ip() {
        // Điểm MỤC ĐÍCH của Tier B: cùng địa chỉ IP nhưng qua transport khác
        // nhau → path_class khác nhau (đa dạng đường cho quorum).
        use super::super::{path_class, subnet_scope};
        let scope = subnet_scope("192.168.137.7".parse().unwrap());
        assert_ne!(
            path_class(TransportId::TcpLan, scope),
            path_class(TransportId::WiFiDirect, scope),
        );
    }
}
