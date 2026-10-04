//! NSG Event Model — mọi sự kiện mesh là bản ghi bất biến có chữ ký (plan §6.1)
//!
//! Ref: plan v2 §6 (event_id/origin_seq/epoch/causal_parent/evidence_root/
//! expiry/signature) + §8 M5 (dedupe, flood accounting) + M2 (chống replay).
//! Ký theo quy ước dự án: canonical bytes length-prefixed + domain separator
//! riêng (mẫu `protocol::challenge`). Event log bound cứng — vượt → từ chối +
//! đếm (INV-015 planned, không drop âm thầm).

use sha2::{Digest, Sha512};

use crate::identity::keypair::DeviceIdentityKey;

use super::graph::NodeId;
use super::MeshError;

/// Miền ký cho sự kiện mesh — cách ly khỏi mọi domain khác của dự án.
pub const DOMAIN_MESH_EVENT: &[u8] = b"CYBERV/MESH/EVENT/v1";

/// Miền băm event_id (bóc tách khỏi miền ký — một đường hash, một đường sig).
pub const DOMAIN_MESH_EVENT_ID: &[u8] = b"CYBERV/MESH/EVENT_ID/v1";

/// Phiên bản wire format của event — tăng khi đổi canonical encoding.
pub const MESH_EVENT_VERSION: u32 = 1;

/// Loại sự kiện mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Node tố một subject có chỉ báo tấn công (kèm evidence_root).
    Report,
    /// Node bỏ phiếu corroboration sau IOC sweep cục bộ.
    Vote,
    /// Heartbeat sống động thường.
    Heartbeat,
    /// Dấu mốc chuyển epoch (consistency.rs phát khi partition/merge).
    EpochMarker,
    /// Sự kiện khôi phục có chữ ký authority (INV-014).
    Recovery,
}

impl EventKind {
    pub const fn as_u8(&self) -> u8 {
        match self {
            EventKind::Report => 1,
            EventKind::Vote => 2,
            EventKind::Heartbeat => 3,
            EventKind::EpochMarker => 4,
            EventKind::Recovery => 5,
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(EventKind::Report),
            2 => Some(EventKind::Vote),
            3 => Some(EventKind::Heartbeat),
            4 => Some(EventKind::EpochMarker),
            5 => Some(EventKind::Recovery),
            _ => None,
        }
    }
}

/// Phân loại tín hiệu — bắt buộc ghi rõ trên mọi Report/Vote (INV-009 planned,
/// roadmap v2 §1.2: không pha trộn verified với heuristic khi trình bày).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalClass {
    /// Có neo mật mã/cơ chế OS — đủ sức feeding quorum.
    Verified,
    /// Telemetry suy diễn — chỉ đủ tạo alert, không tự hành động.
    Heuristic,
}

impl SignalClass {
    pub const fn as_u8(&self) -> u8 {
        match self {
            SignalClass::Verified => 1,
            SignalClass::Heuristic => 2,
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(SignalClass::Verified),
            2 => Some(SignalClass::Heuristic),
            _ => None,
        }
    }
}

/// Kênh quan sát gốc của tín hiệu — điều kiện 2 của quorum independence
/// (plan §5): hai vote cùng kênh chỉ tính một nguồn. Tên khớp các probe
/// thật của dự án (P1-3) + ETW (D2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObsChannel {
    Kernel,
    ProcessMitigations,
    FilesystemAcl,
    NetworkSurface,
    EtwTelemetry,
    Privilege,
    Wdac,
    Other,
}

impl ObsChannel {
    pub const fn as_u8(&self) -> u8 {
        match self {
            ObsChannel::Kernel => 1,
            ObsChannel::ProcessMitigations => 2,
            ObsChannel::FilesystemAcl => 3,
            ObsChannel::NetworkSurface => 4,
            ObsChannel::EtwTelemetry => 5,
            ObsChannel::Privilege => 6,
            ObsChannel::Wdac => 7,
            ObsChannel::Other => 8,
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ObsChannel::Kernel),
            2 => Some(ObsChannel::ProcessMitigations),
            3 => Some(ObsChannel::FilesystemAcl),
            4 => Some(ObsChannel::NetworkSurface),
            5 => Some(ObsChannel::EtwTelemetry),
            6 => Some(ObsChannel::Privilege),
            7 => Some(ObsChannel::Wdac),
            8 => Some(ObsChannel::Other),
            _ => None,
        }
    }
}

/// Bản ghi sự kiện NSG. `signature` phủ TOÀN BỘ trường còn lại qua canonical
/// encoding; `event_id` = hash domain-separate của canonical bytes — tự nhiên
/// làm chìa khóa dedupe (idempotent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsgEvent {
    pub event_id: [u8; 32],
    pub origin_id: NodeId,
    /// Thứ tự toàn phần theo nguồn — monotonic, lùi = replay.
    pub origin_seq: u64,
    pub epoch: u64,
    /// Cha nhân quả (DAG) — điều kiện 4 của quorum independence.
    pub causal_parents: Vec<[u8; 32]>,
    /// Merkle root của evidence pack. Vote/Report KHÔNG có root = không đủ
    /// provenance → không vào quorum (chỉ là telemetry L0 — plan §3).
    pub evidence_root: Option<[u8; 32]>,
    pub created_wall_ms: u64,
    /// Sau mốc này event chỉ còn giá trị điều tra, không feeding quyết định.
    pub expiry_wall_ms: u64,
    pub kind: EventKind,
    pub signal_class: Option<SignalClass>,
    /// Node bị tố (Report/Vote) hoặc node được phục hồi (Recovery).
    pub subject: Option<NodeId>,
    pub obs_channel: Option<ObsChannel>,
    pub signature: [u8; 64],
}

impl NsgEvent {
    /// Canonical bytes phủ toàn bộ trường nội dung (không gồm signature).
    /// Quy ước: domain || version || các trường fixed-width BE, mảng có độ dài
    /// prefix u32 — chống mọi dạng nối chuỗi mơ hồ (quy tắc AGENTS.md §2).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(DOMAIN_MESH_EVENT);
        b.push(0x00);
        b.extend_from_slice(&MESH_EVENT_VERSION.to_be_bytes());
        b.push(0x00);
        b.push(self.kind.as_u8());
        b.push(0x00);
        b.push(self.signal_class.map_or(0, |c| c.as_u8()));
        b.push(0x00);
        b.extend_from_slice(&self.origin_id);
        b.extend_from_slice(&self.origin_seq.to_be_bytes());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.created_wall_ms.to_be_bytes());
        b.extend_from_slice(&self.expiry_wall_ms.to_be_bytes());
        // Optional fields: 0x00 = vắng, 0x01 + nội dung = có.
        match &self.subject {
            None => b.push(0x00),
            Some(s) => {
                b.push(0x01);
                b.extend_from_slice(s);
            }
        }
        match &self.evidence_root {
            None => b.push(0x00),
            Some(r) => {
                b.push(0x01);
                b.extend_from_slice(r);
            }
        }
        b.push(self.obs_channel.map_or(0, |c| c.as_u8()));
        b.extend_from_slice(&(self.causal_parents.len() as u32).to_be_bytes());
        for parent in &self.causal_parents {
            b.extend_from_slice(parent);
        }
        b
    }

    /// event_id = SHA-512/32 domain-separate của canonical bytes.
    pub fn compute_event_id(canonical: &[u8]) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_MESH_EVENT_ID);
        hasher.update([0x00]);
        hasher.update(canonical);
        let out = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&out[..32]);
        id
    }

    /// Ký và gắn event_id. Phải gọi trước khi phát — event chưa ký không được
    /// chấp nhận vào log (accept verify trước khi lưu).
    pub fn sign(&mut self, key: &DeviceIdentityKey) {
        let canonical = self.canonical_bytes();
        self.event_id = Self::compute_event_id(&canonical);
        self.signature = key.sign(&canonical);
    }

    /// Xác minh chữ ký + ràng buộc event_id với nội dung (chống tráo id giữa
    /// hai event khác nội dung).
    pub fn verify(&self, vk: &ed25519_dalek::VerifyingKey) -> Result<(), MeshError> {
        let canonical = self.canonical_bytes();
        if self.event_id != Self::compute_event_id(&canonical) {
            return Err(MeshError::EventRejected(
                "event_id không khớp nội dung canonical".into(),
            ));
        }
        DeviceIdentityKey::verify(vk, &canonical, &self.signature)
            .map_err(|e| MeshError::EventRejected(format!("chữ ký sự kiện sai: {e}")))
    }

    /// Thời hạn còn hiệu lực cho quyết định (điều tra vẫn dùng được sau đó).
    pub fn is_decision_fresh(&self, now_wall_ms: u64) -> bool {
        now_wall_ms < self.expiry_wall_ms
    }
}

/// Kết quả accept vào log — trùng event đã biết là **idempotent**, không lỗi
/// (gossip nhận lại cùng event là chuyện bình thường).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    Accepted,
    Duplicate,
}

/// Giới hạn mặc định log cục bộ (INV-015 planned — sẽ chuyển signed policy).
pub const MAX_LOG_EVENTS: usize = 4096;

/// Log sự kiện cục bộ: dedupe theo event_id, chặn replay theo `origin_seq`
/// monotonic per-origin, bound cứng + accounting.
#[derive(Debug)]
pub struct EventLog {
    max_events: usize,
    events: std::collections::HashMap<[u8; 32], NsgEvent>,
    max_origin_seq: std::collections::HashMap<NodeId, u64>,
    dropped_count: u64,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(MAX_LOG_EVENTS)
    }
}

impl EventLog {
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events,
            events: std::collections::HashMap::new(),
            max_origin_seq: std::collections::HashMap::new(),
            dropped_count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    pub fn get(&self, event_id: &[u8; 32]) -> Option<&NsgEvent> {
        self.events.get(event_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &NsgEvent> {
        self.events.values()
    }

    /// Nhận event mới. Thứ tự kiểm tra: dedupe → xác thực (event_id + chữ ký)
    /// → hết hạn → epoch hợp lý → anti-replay per-origin → bound.
    /// Mọi từ chối đều là nhánh `Err` — không có đường âm thầm.
    pub fn accept(
        &mut self,
        event: NsgEvent,
        vk: &ed25519_dalek::VerifyingKey,
        now_wall_ms: u64,
        current_epoch: u64,
    ) -> Result<AcceptOutcome, MeshError> {
        // 1. Ràng buộc id ↔ nội dung TRƯỚC dedupe — event bị sửa nội dung sau
        //    khi ký (poison clone) phải bộc lộ là EventRejected, không được
        //    lọt qua cửa "Duplicate" rồi biến mất âm thầm.
        let canonical = event.canonical_bytes();
        if event.event_id != NsgEvent::compute_event_id(&canonical) {
            return Err(MeshError::EventRejected(
                "event_id không khớp nội dung canonical".into(),
            ));
        }

        // 2. Idempotent dedupe — tới được đây nghĩa là id chắc chắn là hash
        //    nội dung thật; trùng id = trùng nội dung đã xác minh trước đó.
        if self.events.contains_key(&event.event_id) {
            return Ok(AcceptOutcome::Duplicate);
        }

        // 3. Xác thực mật mã cho event mới (dedupe đã verify ở lần đầu).
        event.verify(vk)?;

        // 3. Hết hạn → từ chối (đếm qua dropped phía caller nếu cần; tại đây
        //    trả lỗi rõ ràng).
        if !event.is_decision_fresh(now_wall_ms) {
            return Err(MeshError::StaleEvent("sự kiện đã hết hạn".into()));
        }

        // 4. Epoch hợp lý: quá khứ gần vẫn nhận (lịch sử điều tra); tương lai
        //    xa (> +1) là dữ liệu xấu — từ chối.
        if event.epoch > current_epoch.saturating_add(1) {
            return Err(MeshError::StaleEvent(format!(
                "epoch tương lai bất hợp lệ: {} > {} + 1",
                event.epoch, current_epoch
            )));
        }

        // 5. Anti-replay per-origin: seq phải tăng nghiêm ngặt — variant riêng
        // để gossip phân loại thống kê (replay ≠ stale thường).
        let seq_ok = self
            .max_origin_seq
            .get(&event.origin_id)
            .is_none_or(|max_seq| event.origin_seq > *max_seq);
        if !seq_ok {
            return Err(MeshError::ReplayRejected(format!(
                "origin_seq không tăng (replay): {}",
                event.origin_seq
            )));
        }

        // 6. Bound cứng — đầy → từ chối + đếm (không evict ngầm mất bằng chứng).
        if self.events.len() >= self.max_events {
            self.dropped_count = self.dropped_count.saturating_add(1);
            return Err(MeshError::LimitExceeded { kind: "event", dropped: self.dropped_count });
        }

        self.max_origin_seq
            .entry(event.origin_id)
            .and_modify(|m| *m = (*m).max(event.origin_seq))
            .or_insert(event.origin_seq);
        self.events.insert(event.event_id, event);
        Ok(AcceptOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::rng::OsCryptoRng;
    use crate::mesh::graph::NodeId;

    fn make_key() -> DeviceIdentityKey {
        DeviceIdentityKey::generate(&mut OsCryptoRng).unwrap()
    }

    fn node_of(key: &DeviceIdentityKey) -> NodeId {
        key.verifying_key().to_bytes()
    }

    fn unsigned_vote(key: &DeviceIdentityKey, seq: u64, subject: NodeId) -> NsgEvent {
        let mut ev = NsgEvent {
            event_id: [0u8; 32],
            origin_id: node_of(key),
            origin_seq: seq,
            epoch: 0,
            causal_parents: Vec::new(),
            evidence_root: Some([0xAA; 32]),
            created_wall_ms: 1_000,
            expiry_wall_ms: 60_000,
            kind: EventKind::Vote,
            signal_class: Some(SignalClass::Verified),
            subject: Some(subject),
            obs_channel: Some(ObsChannel::Kernel),
            signature: [0u8; 64],
        };
        ev.sign(key);
        ev
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = make_key();
        let ev = unsigned_vote(&key, 1, [0x11; 32]);
        ev.verify(key.verifying_key()).unwrap();
    }

    #[test]
    fn tampered_field_breaks_verification() {
        let key = make_key();
        let mut ev = unsigned_vote(&key, 1, [0x11; 32]);
        ev.origin_seq = 2; // sửa sau khi ký
        let err = ev.verify(key.verifying_key()).unwrap_err();
        assert!(matches!(err, MeshError::EventRejected(_)));
    }

    #[test]
    fn swapped_event_id_rejected() {
        let key = make_key();
        let mut ev = unsigned_vote(&key, 1, [0x11; 32]);
        ev.event_id = [0xFF; 32];
        let err = ev.verify(key.verifying_key()).unwrap_err();
        assert!(matches!(err, MeshError::EventRejected(_)));
    }

    #[test]
    fn wrong_signer_rejected() {
        let key = make_key();
        let other = make_key();
        let ev = unsigned_vote(&key, 1, [0x11; 32]);
        let err = ev.verify(other.verifying_key()).unwrap_err();
        assert!(matches!(err, MeshError::EventRejected(_)));
    }

    #[test]
    fn replay_origin_seq_rejected() {
        let key = make_key();
        let subject = [0x22; 32];
        let mut log = EventLog::new(16);
        log
            .accept(unsigned_vote(&key, 5, subject), key.verifying_key(), 2_000, 0)
            .unwrap();
        // Cùng seq, nội dung khác → event_id khác → phải bị chặn là replay.
        let mut second = unsigned_vote(&key, 5, [0x33; 32]);
        second.sign(&key);
        let err = log
            .accept(second, key.verifying_key(), 2_000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::ReplayRejected(_)));
    }

    #[test]
    fn duplicate_event_id_is_idempotent() {
        let key = make_key();
        let mut log = EventLog::new(16);
        let ev = unsigned_vote(&key, 1, [0x22; 32]);
        log.accept(ev.clone(), key.verifying_key(), 2_000, 0).unwrap();
        let outcome = log.accept(ev, key.verifying_key(), 2_000, 0).unwrap();
        assert_eq!(outcome, AcceptOutcome::Duplicate);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn expired_event_rejected() {
        let key = make_key();
        let mut log = EventLog::new(16);
        let err = log
            .accept(unsigned_vote(&key, 1, [0x22; 32]), key.verifying_key(), 61_000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::StaleEvent(_)));
    }

    #[test]
    fn far_future_epoch_rejected() {
        let key = make_key();
        let mut log = EventLog::new(16);
        let mut ev = unsigned_vote(&key, 1, [0x22; 32]);
        ev.epoch = 99;
        ev.sign(&key);
        let err = log.accept(ev, key.verifying_key(), 2_000, 0).unwrap_err();
        assert!(matches!(err, MeshError::StaleEvent(_)));
    }

    #[test]
    fn log_bound_drops_are_counted() {
        let key = make_key();
        let mut log = EventLog::new(2);
        for seq in 1..=2u64 {
            log
                .accept(unsigned_vote(&key, seq, [0x22; 32]), key.verifying_key(), 2_000, 0)
                .unwrap();
        }
        let err = log
            .accept(unsigned_vote(&key, 3, [0x22; 32]), key.verifying_key(), 2_000, 0)
            .unwrap_err();
        assert!(matches!(err, MeshError::LimitExceeded { kind: "event", dropped: 1 }));
        assert_eq!(log.dropped_count(), 1);
    }
}
