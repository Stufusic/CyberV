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
//! mDNS Discovery (NSG-2b — M-PLAN M-2): quảng bá + tìm peer trên LAN
//!
//! Ref: plan v2 §7.1 UC-1 bước 1, §10 Tier A ("mDNS discovery + TCP"),
//! M-PLAN §3. mDNS là nguồn **discovery** của Tier A — không mang frame
//! trust: beacon chỉ chứa node_id + vk (privacy, plan T6), peer mới chỉ vào
//! `Discovered`; attest phải qua bắt tay chữ ký thật (INV-012). Mất mDNS
//! không rớt link đã có (offline-first).
//!
//! Beacon đi qua TXT property dạng hex — decode bounds nghiêm ngặt, mọi
//! beacon rác bị bỏ qua + đếm (không bao giờ nâng trust từ beacon).

use std::collections::HashMap;
use std::net::SocketAddr;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use super::super::discovery::{MeshBeacon, BEACON_VERSION};
use super::super::graph::NodeId;
use super::super::MeshError;

/// Loại dịch vụ mDNS của mesh CyberV (RFC 6763: TCP transport bắt buộc dùng _tcp).
pub const MDNS_SERVICE_TYPE: &str = "_cyberv-mesh._tcp.local.";
/// Key TXT chứa beacon hex.
pub const MDNS_TXT_BEACON: &str = "beacon";
/// Prefix instance name — "cyberv-" + 8 hex của node_id = 15 ký tự, đúng
/// trần RFC 6763 §7.2 (mdns-sd mặc định 15).
pub const MDNS_INSTANCE_PREFIX: &str = "cyberv-";
/// Trần số peer giữ trong cache discovery (INV-015).
pub const DEFAULT_MAX_MDNS_PEERS: usize = 512;

/// Tên instance mDNS cho một node — "cyberv-" + 8 hex đầu của node_id.
pub fn instance_name(node_id: &NodeId) -> String {
    let mut name = String::from(MDNS_INSTANCE_PREFIX);
    for byte in node_id.iter().take(4) {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Beacon → hex để nhét vào TXT (mdns-sd property là chuỗi).
pub fn encode_beacon_txt(beacon: &MeshBeacon) -> String {
    let mut out = String::with_capacity(super::super::discovery::BEACON_LEN * 2);
    for byte in beacon.encode() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Hex → beacon — decode an toàn theo byte (không panic với input ngoài).
pub fn decode_beacon_txt(hex_str: &str) -> Result<MeshBeacon, MeshError> {
    let chars: Vec<u8> = hex_str.as_bytes().to_vec();
    if !chars.len().is_multiple_of(2) {
        return Err(MeshError::Frame("beacon hex lẻ ký tự".into()));
    }
    let mut wire = Vec::with_capacity(chars.len() / 2);
    for pair in chars.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| MeshError::Frame("beacon hex có ký tự lạ".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| MeshError::Frame("beacon hex có ký tự lạ".into()))?;
        wire.push((hi * 16 + lo) as u8);
    }
    MeshBeacon::decode(&wire)
}

/// Nguồn discovery mDNS — daemon mdns-sd + cache peer bounded. Không mang
/// frame: link thật vẫn do TCP transport mở (`node::MeshNode::connect_peer`).
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    receiver: mdns_sd::Receiver<ServiceEvent>,
    peers: HashMap<String, (MeshBeacon, SocketAddr)>,
    max_peers: usize,
    dropped_peers: u64,
    malformed_beacons: u64,
    removed_peers: u64,
}

impl MdnsDiscovery {
    /// Tạo daemon + bắt đầu browse dịch vụ mesh.
    pub fn new() -> Result<Self, MeshError> {
        Self::with_policy(DEFAULT_MAX_MDNS_PEERS)
    }

    pub fn with_policy(max_peers: usize) -> Result<Self, MeshError> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| MeshError::TransportIo(format!("mDNS daemon khởi động thất bại: {e}")))?;
        let receiver = daemon
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| MeshError::TransportIo(format!("mDNS browse thất bại: {e}")))?;
        Ok(Self {
            daemon,
            receiver,
            peers: HashMap::new(),
            max_peers,
            dropped_peers: 0,
            malformed_beacons: 0,
            removed_peers: 0,
        })
    }

    /// Quảng bá beacon cục bộ kèm port TCP listener. `enable_addr_auto` để
    /// daemon tự điền địa chỉ interface thật (không hard-code IP).
    pub fn advertise(&self, beacon: &MeshBeacon, port: u16) -> Result<(), MeshError> {
        if beacon.wire_version != BEACON_VERSION {
            return Err(MeshError::Frame(format!(
                "beacon wire version lạ: {}",
                beacon.wire_version
            )));
        }
        let instance = instance_name(&beacon.node_id);
        let host = format!("{instance}.local.");
        let txt = encode_beacon_txt(beacon);
        // Bind tường thành slice — impl IntoTxtProperties chỉ có cho &[T].
        let props: &[(&str, &str)] = &[(MDNS_TXT_BEACON, txt.as_str())];
        let info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &instance,
            &host,
            "",
            port,
            props,
        )
        .map_err(|e| MeshError::InvalidEndpoint(format!("ServiceInfo mDNS: {e}")))?
        .enable_addr_auto();
        // register chờ verdict trong block này — không fire-and-forget âm thầm.
        self.daemon
            .register(info)
            .map_err(|e| MeshError::TransportIo(format!("mDNS register: {e}")))?;
        Ok(())
    }

    /// Poll không chặn các sự kiện browse → cập nhật cache; trả snapshot
    /// (beacon, endpoint) các peer đang thấy. Được gọi định kỳ từ engine.
    pub fn browse(&mut self) -> Vec<(MeshBeacon, SocketAddr)> {
        while let Ok(event) = self.receiver.try_recv() {
            self.handle_event(event);
        }
        self.peers.values().cloned().collect()
    }

    fn handle_event(&mut self, event: ServiceEvent) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let Some(hex) = info.get_property_val_str(MDNS_TXT_BEACON) else {
                    self.malformed_beacons = self.malformed_beacons.saturating_add(1);
                    return;
                };
                let Ok(beacon) = decode_beacon_txt(hex) else {
                    self.malformed_beacons = self.malformed_beacons.saturating_add(1);
                    return;
                };
                // Endpoint: ưu tiên địa chỉ IPv4 không loopback, fallback địa
                // chỉ đầu tiên — scope mdns-sd 0.21 (ScopedIp) về IpAddr chuẩn.
                let addrs: Vec<_> = info.get_addresses().iter().collect();
                let chosen = addrs
                    .iter()
                    .find(|a| a.is_ipv4() && !a.is_loopback())
                    .or_else(|| addrs.first());
                let Some(scoped) = chosen else {
                    self.malformed_beacons = self.malformed_beacons.saturating_add(1);
                    return;
                };
                let endpoint = SocketAddr::new(scoped.to_ip_addr(), info.get_port());
                if self.peers.len() >= self.max_peers && !self.peers.contains_key(info.get_fullname()) {
                    self.dropped_peers = self.dropped_peers.saturating_add(1);
                    return;
                }
                self.peers.insert(info.get_fullname().to_string(), (beacon, endpoint));
            }
            ServiceEvent::ServiceRemoved(_, fullname)
                if self.peers.remove(fullname.as_str()).is_some() =>
            {
                self.removed_peers = self.removed_peers.saturating_add(1);
            }
            // ServiceRemoved nhưng peer không có trong cache — không đếm.
            _ => {}
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn dropped_peers(&self) -> u64 {
        self.dropped_peers
    }

    pub fn malformed_beacons(&self) -> u64 {
        self.malformed_beacons
    }

    /// Dừng quảng bá + browse (offline-first: link TCP đã có không đụng).
    pub fn shutdown(&self) {
        let _ = self.daemon.stop_browse(MDNS_SERVICE_TYPE);
        let _ = self.daemon.unregister(&format!(
            "{MDNS_INSTANCE_PREFIX}._{MDNS_SERVICE_TYPE}"
        ));
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_beacon() -> MeshBeacon {
        MeshBeacon { node_id: [0x11; 32], vk: [0x22; 32], wire_version: BEACON_VERSION }
    }

    #[test]
    fn instance_name_is_within_rfc_limit() {
        let name = instance_name(&[0xAB; 32]);
        assert!(name.starts_with(MDNS_INSTANCE_PREFIX));
        assert_eq!(name.len(), 15, "cyberv- (7) + 8 hex");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn beacon_txt_roundtrip() {
        let hex = encode_beacon_txt(&sample_beacon());
        assert_eq!(hex.len(), super::super::super::discovery::BEACON_LEN * 2);
        let decoded = decode_beacon_txt(&hex).unwrap();
        assert_eq!(decoded.node_id, [0x11; 32]);
        assert_eq!(decoded.vk, [0x22; 32]);
        assert_eq!(decoded.wire_version, BEACON_VERSION);
    }

    #[test]
    fn beacon_txt_rejects_garbage() {
        assert!(matches!(decode_beacon_txt("abc"), Err(MeshError::Frame(_))));
        assert!(matches!(decode_beacon_txt("zz"), Err(MeshError::Frame(_))));
        assert!(matches!(decode_beacon_txt(""), Err(MeshError::Frame(_))));
        // Hex đúng nhưng nội dung sai magic/độ dài → MeshBeacon::decode chặn.
        let mut hex = encode_beacon_txt(&sample_beacon());
        hex.truncate(hex.len() - 2);
        assert!(matches!(decode_beacon_txt(&hex), Err(MeshError::Frame(_))));
    }
}
