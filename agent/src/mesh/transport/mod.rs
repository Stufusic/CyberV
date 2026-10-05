//! Mesh Transport v2 — đa giao thức phía sau trait chung (M-PLAN M-1, NSG-2b/§10)
//!
//! Ref: `Docs/M_PLAN_MULTI_TRANSPORT_ISOLATION.md` §1 + plan NSG v2 §10
//! (Tier A/B/C). Điểm thiết kế:
//!
//! 1. **Transport không biết gì về mật mã** — `MeshLink` chỉ là ống frame
//!    (đã length-prefixed); bắt tay mesh 3 bước + phiên AEAD (`session.rs`)
//!    chạy **TRÊN** link. Vì vậy tier B/C cắm vào không đụng core.
//! 2. **path_class chuẩn hóa** (M-PLAN §1.2): `hash(transport_id,
//!    subnet_scope)` — hai vote đến qua cùng transport + cùng segment mạng
//!    bị coi là **CÙNG đường** trong điều kiện 5 của quorum independence
//!    ("đánh giá thật thay vì đường khác nhau trên giấy"). Hệ quả trung thực:
//!    mesh phẳng một subnet + một transport **không tự đủ** quorum — quorum
//!    cần đa dạng đường (khác transport hoặc khác segment); đó là thanh
//!    an ninh chủ ý, không phải lỗi.
//! 3. **TransportManager** là sổ registry (policy cap link/peer + accounting
//!    đường) — session/link thật thuộc sở hữu connection task trong `node.rs`
//!    để không phải chia sẻ &mut qua lock khi I/O.

pub mod mdns;
pub mod tcp;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use sha2::{Digest, Sha512};

use super::discovery::MeshBeacon;
use super::graph::NodeId;
use super::MeshError;

/// Loại transport — giá trị bám wire (vào path_class, không đổi sau khi phát hành).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportId {
    /// Tier A — TCP trên LAN (production target).
    TcpLan = 1,
    /// Tier B — WiFi Direct (experimental, flag tắt mặc định).
    WiFiDirect = 2,
    /// Tier C — BLE advertisement (discovery only, zero trust).
    Ble = 3,
    /// Kênh rendezvous (out-of-band, future).
    Rendezvous = 4,
}

impl TransportId {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(TransportId::TcpLan),
            2 => Some(TransportId::WiFiDirect),
            3 => Some(TransportId::Ble),
            4 => Some(TransportId::Rendezvous),
            _ => None,
        }
    }
}

/// Địa chỉ một peer trên một transport cụ thể. M-1 chỉ có TCP (SocketAddr);
/// tier B/C mở rộng trường riêng khi wire (không tái dùng SocketAddr cho
/// dữ liệu không phải IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub transport: TransportId,
    pub addr: SocketAddr,
}

/// Miền băm path_class — cách ly khỏi mọi domain khác của dự án.
pub const DOMAIN_MESH_PATH_CLASS: &[u8] = b"CYBERV/MESH/PATHCLASS/v1";

/// Scope segment mạng của một địa chỉ: IPv4 → /24, IPv6 → /64.
/// Toàn bộ loopback (127/8, ::1) là **một scope** — cùng một máy là cùng
/// một đường (vote hai process trên một máy chỉ tính một nguồn).
pub fn subnet_scope(addr: IpAddr) -> [u8; 16] {
    let mut scope = [0u8; 16];
    match addr {
        IpAddr::V4(v4) => {
            scope[0] = 4; // family marker — không trùng scope IPv6 thật
            if v4.is_loopback() {
                scope[1] = 127;
                return scope;
            }
            let o = v4.octets();
            scope[1..4].copy_from_slice(&o[..3]); // /24 — octet cuối về 0
        }
        IpAddr::V6(v6) => {
            scope[0] = 6;
            if v6.is_loopback() {
                return scope; // ::1 → toàn 0 sau marker
            }
            let o = v6.octets();
            scope[1..9].copy_from_slice(&o[..8]); // /64
        }
    }
    scope
}

/// path_class = SHA-512(domain || transport_id || subnet_scope)[..8].
/// Hai phiếu cùng path_class bị coi là cùng đường — quorum điều kiện 5.
pub fn path_class(transport: TransportId, scope: [u8; 16]) -> u64 {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_MESH_PATH_CLASS);
    hasher.update([0x00]);
    hasher.update([transport.as_u8()]);
    hasher.update(scope);
    let out = hasher.finalize();
    // Slice 8 byte từ digest 64 byte — bất biến kiểu, không phải dữ liệu ngoài.
    u64::from_be_bytes(out[..8].try_into().expect("SHA-512 đủ 64 byte"))
}

/// path_class cho một endpoint TCP — tiện dùng chung cho link + test.
pub fn tcp_path_class(remote: IpAddr) -> u64 {
    path_class(TransportId::TcpLan, subnet_scope(remote))
}

/// Frame type duy nhất của M-1: payload là một `NsgEvent` wire
/// (`events::NsgEvent::to_wire`) — gossip/vote/report/alert đều là event.
pub const FRAME_GOSSIP_EVENT: u8 = 1;

/// Future của link — boxed để `MeshLink` dyn-compatible (trait object trong
/// TransportManager/connection task). `Send` vì link được sở hữu bởi tokio task.
pub type LinkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MeshError>> + Send + 'a>>;
pub type ConnectFuture<'a> = LinkFuture<'a, Box<dyn MeshLink>>;

/// Một liên kết đã nối — chỉ chuyên chở frame (đã length-prefixed bởi lớp
/// trên: bắt tay `HandshakeMessage::encode` hoặc `MeshSession::seal`).
/// `read_frame`/`write_frame` bắt buộc **cancel-safe**: hủy giữa chừng
/// (tokio::select!/timeout) không được làm lệch byte trên link.
pub trait MeshLink: Send {
    fn transport_id(&self) -> TransportId;
    fn peer_addr(&self) -> SocketAddr;
    /// Đường mạng của link — stamp lên mọi event nhận qua link này.
    fn path_class(&self) -> u64;
    /// Đọc đúng một frame đầy đủ (prefix 4 byte + thân). EOF ⇒ `LinkClosed`.
    /// Cancel-safe: hủy giữa chừng không được làm mất byte.
    fn read_frame(&mut self) -> LinkFuture<'_, Vec<u8>>;
    /// Ghi đúng một frame đầy đủ. Impl tự copy frame vào owned buffer (≤
    /// MAX_FRAME_SIZE) — future chỉ mượn `&mut self`. KHÔNG được gọi chồng
    /// lấn với read/write khác trên cùng link.
    fn write_frame(&mut self, frame: &[u8]) -> LinkFuture<'_, ()>;
}

/// Luồng link inbound từ một transport đã `listen`.
pub struct InboundLinks {
    rx: tokio::sync::mpsc::UnboundedReceiver<Box<dyn MeshLink>>,
}

impl InboundLinks {
    pub async fn next(&mut self) -> Option<Box<dyn MeshLink>> {
        self.rx.recv().await
    }
}

/// Transport cắm vào manager — Tier B/C hiện thực trait này không đụng core
/// (plan §10). `connect` trả future borrowing `&mut self` — caller giữ guard
/// transport lock trong lúc await (op hiếm, không nóng).
pub trait MeshTransport: Send {
    fn id(&self) -> TransportId;
    /// Bật quảng bá beacon. Transport không có kênh quảng bá riêng (TCP thuần)
    /// chỉ lưu beacon để tầng discovery phát hộ — trung thực, không giả vờ.
    fn advertise(&mut self, beacon: &MeshBeacon) -> Result<(), MeshError>;
    /// Quét peer đang thấy. Transport không có discovery (TCP thuần) trả rỗng.
    fn browse(&mut self) -> Vec<(MeshBeacon, Endpoint)>;
    fn connect(&mut self, ep: Endpoint) -> ConnectFuture<'_>;
    /// Bật lắng nghe — link inbound đẩy vào channel trả về. Gọi lần hai = lỗi.
    fn listen(&mut self) -> Result<InboundLinks, MeshError>;
}

/// Số link tối đa trên một peer (INV-015 — placeholder policy, NSG-3 chuyển
/// signed policy). ≥2 để sẵn sàng failover Tier A → B (M-3).
pub const DEFAULT_MAX_LINKS_PER_PEER: usize = 2;
/// Trần tổng link toàn node (INV-015).
pub const DEFAULT_MAX_TOTAL_LINKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPolicy {
    pub max_links_per_peer: usize,
    pub max_total_links: usize,
}

impl Default for TransportPolicy {
    fn default() -> Self {
        Self {
            max_links_per_peer: DEFAULT_MAX_LINKS_PER_PEER,
            max_total_links: DEFAULT_MAX_TOTAL_LINKS,
        }
    }
}

/// Bản ghi một link trong registry — bookkeeping (không nắm session/link thật).
/// `conn_id` là định danh duy nhất mỗi link trong node (hai link cùng peer
/// qua cùng đường có CÙNG path_class nhưng KHÔNG bao giờ cùng conn_id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRecord {
    pub conn_id: u64,
    pub path: u64,
    pub transport: TransportId,
    /// Địa chỉ socket đối tác — WFP (I-2) dùng để block per-IP.
    pub addr: SocketAddr,
    pub since_mono_ms: u64,
    pub last_seen_mono_ms: u64,
}

/// Registry đường truyền: cap link/peer + cap tổng + accounting mọi loại bỏ
/// (không drop âm thầm — INV-010/015). Registry KHÔNG sở hữu link thật;
/// `node.rs` connection task sở hữu, registry chỉ phản ánh.
#[derive(Debug)]
pub struct TransportManager {
    policy: TransportPolicy,
    entries: HashMap<NodeId, Vec<LinkRecord>>,
    dropped_over_cap: u64,
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::with_policy(TransportPolicy::default())
    }
}

impl TransportManager {
    pub fn with_policy(policy: TransportPolicy) -> Self {
        Self { policy, entries: HashMap::new(), dropped_over_cap: 0 }
    }

    pub fn policy(&self) -> &TransportPolicy {
        &self.policy
    }

    pub fn total_links(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    pub fn dropped_over_cap(&self) -> u64 {
        self.dropped_over_cap
    }

    pub fn records_of(&self, peer: &NodeId) -> &[LinkRecord] {
        self.entries.get(peer).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Các path_class đang sống của một peer (distinct — nhiều link cùng
    /// đường chỉ đếm một đường) — phục vụ chẩn đoán + failover.
    pub fn paths_of(&self, peer: &NodeId) -> Vec<u64> {
        let mut paths: Vec<u64> = self.records_of(peer).iter().map(|r| r.path).collect();
        paths.sort_unstable();
        paths.dedup();
        paths
    }

    /// Pre-check cap: có vượt cap nếu nhận thêm link (dùng TRƯỚC khi bắt tay
    /// để link thừa bị cắt sớm, không tốn mật mã — admit vẫn là chốt cuối).
    pub fn would_exceed_cap(&self, peer: &NodeId) -> bool {
        let peer_count = self.entries.get(peer).map_or(0, Vec::len);
        peer_count >= self.policy.max_links_per_peer
            || self.total_links() >= self.policy.max_total_links
    }

    /// Nhận một link mới. Vượt cap (peer hoặc tổng) → `Err` rõ ràng + đếm.
    pub fn admit(
        &mut self,
        peer: NodeId,
        record: LinkRecord,
    ) -> Result<(), MeshError> {
        let total = self.total_links();
        let peer_count = self.entries.get(&peer).map_or(0, Vec::len);
        if peer_count >= self.policy.max_links_per_peer
            || total >= self.policy.max_total_links
        {
            self.dropped_over_cap = self.dropped_over_cap.saturating_add(1);
            return Err(MeshError::LimitExceeded {
                kind: "mesh-link",
                dropped: self.dropped_over_cap,
            });
        }
        self.entries.entry(peer).or_default().push(record);
        Ok(())
    }

    /// Nhả một link (theo conn_id). Trả false nếu không tìm thấy — caller log.
    pub fn release(&mut self, peer: &NodeId, conn_id: u64) -> bool {
        let Some(records) = self.entries.get_mut(peer) else {
            return false;
        };
        let before = records.len();
        records.retain(|r| r.conn_id != conn_id);
        let removed = records.len() != before;
        if records.is_empty() {
            self.entries.remove(peer);
        }
        removed
    }

    /// Refresh last_seen khi có frame đi qua link.
    pub fn refresh(&mut self, peer: &NodeId, conn_id: u64, now_mono_ms: u64) {
        if let Some(records) = self.entries.get_mut(peer) {
            for r in records.iter_mut().filter(|r| r.conn_id == conn_id) {
                r.last_seen_mono_ms = now_mono_ms;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(seed: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = seed;
        n
    }

    #[test]
    fn same_transport_same_subnet_is_same_path() {
        let a = tcp_path_class("192.168.1.5".parse().unwrap());
        let b = tcp_path_class("192.168.1.99".parse().unwrap());
        assert_eq!(a, b, "cùng /24 + cùng transport = cùng đường");

        let other_subnet = tcp_path_class("10.0.0.1".parse().unwrap());
        assert_ne!(a, other_subnet, "khác segment = khác đường");
    }

    #[test]
    fn different_transport_same_scope_is_different_path() {
        let scope = subnet_scope("192.168.1.5".parse().unwrap());
        assert_ne!(
            path_class(TransportId::TcpLan, scope),
            path_class(TransportId::WiFiDirect, scope),
            "khác transport = khác đường (đa dạng đường cần cho quorum)"
        );
    }

    #[test]
    fn loopback_is_one_scope_and_ipv6_separate() {
        let l1 = subnet_scope("127.0.0.1".parse().unwrap());
        let l2 = subnet_scope("127.9.9.9".parse().unwrap());
        assert_eq!(l1, l2, "toàn bộ 127/8 là một máy");
        // IPv6 loopback scope = marker 6 + zeros; khác mọi scope IPv4.
        assert_eq!(subnet_scope("::1".parse().unwrap()), {
            let mut s = [0u8; 16];
            s[0] = 6;
            s
        });
        assert_ne!(l1, subnet_scope("::1".parse().unwrap()));
        // fd00::1 và fd00:...:abcd::1 CÙNG /64 (abcd thuộc phần interface ID);
        // khác segment thật sự là khác nhóm đầu (fd00:: vs fd01::).
        assert_ne!(
            subnet_scope("fd00::1".parse().unwrap()),
            subnet_scope("fd01::1".parse().unwrap()),
            "IPv6 khác /64 = khác segment",
        );
        assert_eq!(
            subnet_scope("fd00::1".parse().unwrap()),
            subnet_scope("fd00:0:0:0:abcd::1".parse().unwrap()),
            "cùng /64 dù khác interface ID = cùng segment",
        );
    }

    #[test]
    fn manager_caps_enforced_with_accounting() {
        let mut mgr = TransportManager::with_policy(TransportPolicy {
            max_links_per_peer: 1,
            max_total_links: 2,
        });
        let now = 100u64;
        let addr = "192.0.2.1:7000".parse().unwrap();
        let rec = |conn_id, path| LinkRecord {
            conn_id,
            path,
            transport: TransportId::TcpLan,
            addr,
            since_mono_ms: now,
            last_seen_mono_ms: now,
        };

        mgr.admit(nid(1), rec(1, 11)).unwrap();
        // Link thứ hai cùng peer — vượt cap per-peer, đếm rõ ràng.
        assert!(matches!(
            mgr.admit(nid(1), rec(2, 11)),
            Err(MeshError::LimitExceeded { kind: "mesh-link", .. })
        ));
        assert!(mgr.would_exceed_cap(&nid(1)));
        assert_eq!(mgr.dropped_over_cap(), 1);

        // Peer khác — cap tổng 2: peer 2 vào được, peer 3 bị chặn.
        mgr.admit(nid(2), rec(3, 21)).unwrap();
        assert!(matches!(
            mgr.admit(nid(3), rec(4, 31)),
            Err(MeshError::LimitExceeded { kind: "mesh-link", .. })
        ));
        assert_eq!(mgr.total_links(), 2);

        // Release đúng conn_id → slot mở lại; release sai conn_id = false.
        assert!(mgr.release(&nid(1), 1));
        assert!(!mgr.release(&nid(1), 1), "release lần hai = false, không âm thầm");
        mgr.admit(nid(3), rec(5, 31)).unwrap();
        assert_eq!(mgr.total_links(), 2);
        assert_eq!(mgr.paths_of(&nid(3)), vec![31]);
    }

    #[test]
    fn manager_two_links_same_path_distinct_conn_ids() {
        // Hai link cùng peer cùng path_class (loopback) — phải sống độc lập.
        let mut mgr = TransportManager::default();
        let now = 5u64;
        let addr = "192.0.2.1:7000".parse().unwrap();
        let rec = |conn_id| LinkRecord {
            conn_id,
            path: 777,
            transport: TransportId::TcpLan,
            addr,
            since_mono_ms: now,
            last_seen_mono_ms: now,
        };
        mgr.admit(nid(1), rec(1)).unwrap();
        mgr.admit(nid(1), rec(2)).unwrap();
        assert_eq!(mgr.total_links(), 2);
        assert_eq!(mgr.paths_of(&nid(1)), vec![777], "paths distinct — một đường hai link");

        // Nhả conn 1 → conn 2 phải còn nguyên (path-keyed release đã từng
        // xóa nhầm cả hai — đây là regression test).
        assert!(mgr.release(&nid(1), 1));
        assert_eq!(mgr.total_links(), 2 - 1);
        mgr.refresh(&nid(1), 2, 50);
        let rec2 = mgr.records_of(&nid(1))[0];
        assert_eq!(rec2.conn_id, 2);
        assert_eq!(rec2.last_seen_mono_ms, 50);
    }

    #[test]
    fn manager_refresh_updates_only_matching_link() {
        let mut mgr = TransportManager::default();
        let now = 5u64;
        let addr = "192.0.2.1:7000".parse().unwrap();
        let rec = |conn_id, path| LinkRecord {
            conn_id,
            path,
            transport: TransportId::TcpLan,
            addr,
            since_mono_ms: now,
            last_seen_mono_ms: now,
        };
        mgr.admit(nid(1), rec(1, 1)).unwrap();
        mgr.admit(nid(1), rec(2, 2)).unwrap();
        mgr.refresh(&nid(1), 2, 50);
        let records = mgr.records_of(&nid(1));
        assert_eq!(records.iter().find(|r| r.conn_id == 1).unwrap().last_seen_mono_ms, 5);
        assert_eq!(records.iter().find(|r| r.conn_id == 2).unwrap().last_seen_mono_ms, 50);
    }
}
