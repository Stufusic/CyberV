//! Mesh Node Engine — wire transport thật vào handshake → GossipInbox → Graph
//! (M-PLAN M-1, NSG-2)
//!
//! Ref: `Docs/M_PLAN_MULTI_TRANSPORT_ISOLATION.md` §1-2. Engine là vòng đời
//! một node mesh: TCP listener (Tier A) → bắt tay 3 bước mutual → phiên AEAD
//! → GossipInbox (flood-limit per-peer) → MeshGraph (state machine fail-closed).
//!
//! Kiến trúc luồng:
//! - **Connection task sở hữu session + link** (không chia sẻ &mut qua lock
//!   khi I/O) — engine chỉ giữ handle xếp hàng payload outbound.
//! - Outbound xả queue TRƯỚC mỗi lượt đọc; `read_frame` là cancel-safe nên
//!   idle-timeout không mất byte, write không bao giờ bị hủy giữa chừng.
//! - Mọi event nhận được gắn `path_class` từ link → quorum điều kiện 5 đánh
//!   giá đường mạng thật (M-PLAN §1.2).
//!
//! Ranh giới trung thực (INV-007/012): presence/beacon không nâng trust —
//! chỉ bắt tay chữ ký thật mới cho `Attested`; vote của node tự thân không
//! có trọng số (ReputationLedger không có hồ sơ self); đề nghị isolate khi
//! quorum đạt chỉ GHI vào ShadowLedger, không thực thi (NSG-3/I-2).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::identity::keypair::DeviceIdentityKey;
use crate::identity::rng::OsCryptoRng;

use sha2::{Digest, Sha512};

use super::discovery::{MeshBeacon, BEACON_VERSION};
use super::events::{AcceptOutcome, EventKind, EventLog, NsgEvent, SignalClass};
use super::gossip::{GossipInbox, GossipPolicy};
use super::graph::{GcReport, MeshGraph, NodeId, NodeState, ISOLATION_TTL_MS};
use super::isolation::{
    DecisionAction, DecisionEntry, DecisionLog, EnforcementMode, IsolationDesk,
    IsolationProposal, MAX_REASON_LEN,
};
use super::quorum::{evaluate_quorum, Ballot, QuorumOutcome, QuorumPolicy, QuorumVerdict};
use super::reputation::ReputationLedger;
use super::session::{
    HandshakeConfig, HandshakeMessage, Initiator, MeshSession, Responder, MESH_WIRE_VERSION,
};
use super::shadow::ShadowLedger;
use tokio::net::TcpStream;

use super::transport::ble::{self, BleBeacon26, BleDiscovery};
use super::transport::mdns::MdnsDiscovery;
use super::transport::tcp::{TcpLanTransport, TcpLink};
use super::transport::wfd::{self, WfdTransport};
use super::transport::{
    Endpoint, InboundLinks, LinkRecord, MeshLink, MeshTransport, TransportId, TransportPolicy,
    FRAME_GOSSIP_EVENT,
};
use super::MeshError;

// ---------------------------------------------------------------------------
// Đồng hồ — mono ms + wall ms do caller kiểm soát (test deterministic)
// ---------------------------------------------------------------------------

/// Nguồn thời gian của engine. Mono dùng cho TTL/GC, wall dùng cho freshness
/// event — tách riêng đúng nguyên tắc "nguồn monotonic" của roadmap v2 §4.
pub trait MeshClock: Send + Sync {
    fn now_mono_ms(&self) -> u64;
    fn now_wall_ms(&self) -> u64;
}

/// Đồng hồ thật: mono = elapsed từ lúc dựng (Instant monotonic), wall = UNIX ms.
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshClock for SystemClock {
    fn now_mono_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn now_wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// Đồng hồ thủ công cho test — đẩy thời gian deterministically.
pub struct ManualClock {
    mono: AtomicU64,
    wall: AtomicU64,
}

impl ManualClock {
    pub fn new(mono_ms: u64, wall_ms: u64) -> Self {
        Self { mono: AtomicU64::new(mono_ms), wall: AtomicU64::new(wall_ms) }
    }

    pub fn advance_mono(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn set(&self, mono_ms: u64, wall_ms: u64) {
        self.mono.store(mono_ms, Ordering::SeqCst);
        self.wall.store(wall_ms, Ordering::SeqCst);
    }
}

impl MeshClock for ManualClock {
    fn now_mono_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }

    fn now_wall_ms(&self) -> u64 {
        self.wall.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Cấu hình + thống kê
// ---------------------------------------------------------------------------

/// Poll outbound mặc định (ms) — độ trễ tối đa của gossip khi link idle.
pub const DEFAULT_OUTBOUND_POLL_MS: u64 = 250;
/// Trần lỗi mật mã trên một link trước khi cắt (frame giả liên tục = tấn công).
pub const DEFAULT_MAX_CRYPTO_FAULTS_PER_LINK: u32 = 8;
/// TTL sổ arrival (ms) — lâu hơn thế, đường nhận của event không còn giá trị
/// quyết định (vote đã cũ theo expiry event).
pub const DEFAULT_ARRIVAL_TTL_MS: u64 = 3_600_000;
/// Trần cứng sổ arrival (INV-015) — đầy → evict cũ nhất, có chủ đích.
pub const MAX_ARRIVAL_ENTRIES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshNodeConfig {
    /// Địa chỉ listener TCP. Mặc định loopback — an toàn nhất nếu caller quên.
    pub listen_addr: SocketAddr,
    pub max_links_per_peer: usize,
    pub max_total_links: usize,
    pub connect_timeout_ms: u64,
    pub outbound_poll_ms: u64,
    pub max_crypto_faults_per_link: u32,
    /// TTL isolation mặc định khi quorum đạt (plan §9 — deadline tuyệt đối).
    pub isolation_ttl_ms: u64,
    /// I-2 grace de-escalation: sau isolation, node re-attest phải ở Suspect
    /// qua N tick sạch mới được Attested.
    pub probation_ticks: u32,
    /// M-3 Tier B (WiFi Direct) — plan §10: flag riêng, TẮT MẶC ĐỊNH.
    pub wifi_direct_enabled: bool,
    /// M-4 Tier C (BLE beacon) — discovery only, TẮT MẶC ĐỊNH.
    pub ble_discovery_enabled: bool,
    pub arrival_ttl_ms: u64,
    pub quorum: QuorumPolicy,
    pub gossip: GossipPolicy,
    pub admission: super::admission::MeshAdmissionPolicy,
}

impl Default for MeshNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().expect("loopback:0 hợp lệ"),
            max_links_per_peer: super::transport::DEFAULT_MAX_LINKS_PER_PEER,
            max_total_links: super::transport::DEFAULT_MAX_TOTAL_LINKS,
            connect_timeout_ms: 3_000,
            outbound_poll_ms: DEFAULT_OUTBOUND_POLL_MS,
            max_crypto_faults_per_link: DEFAULT_MAX_CRYPTO_FAULTS_PER_LINK,
            isolation_ttl_ms: ISOLATION_TTL_MS,
            probation_ticks: 3,
            wifi_direct_enabled: false,
            ble_discovery_enabled: false,
            arrival_ttl_ms: DEFAULT_ARRIVAL_TTL_MS,
            quorum: QuorumPolicy::default(),
            gossip: GossipPolicy::default(),
            admission: super::admission::MeshAdmissionPolicy::default(),
        }
    }
}

/// Thống kê vận hành node — mọi con số truy vấn được, không có drop ẩn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeshNodeStats {
    pub links_established: u64,
    pub links_closed: u64,
    pub links_dropped_unknown_peer: u64,
    pub links_dropped_over_cap: u64,
    pub gossip_in_accepted: u64,
    pub gossip_in_duplicate: u64,
    pub gossip_in_rejected: u64,
    pub gossip_out_frames: u64,
    pub crypto_faults: u64,
    pub quorum_reached: u64,
    pub shadow_dropped: u64,
    pub beacons_rejected: u64,
    /// Inbound handshake bị từ chối vì node ĐANG tự cách ly.
    pub inbound_rejected_isolated: u64,
    /// M-3: số ConnectionRequested WFD thấy (phía accept).
    pub wfd_requests_seen: u64,
    /// M-4: số BLE sample hợp lệ absorb vào sổ presence.
    pub ble_samples_seen: u64,
    /// M-4: BLE payload không decode được.
    pub ble_beacons_malformed: u64,
    /// M-4: sổ presence đầy → evict đếm được.
    pub ble_presence_dropped: u64,
}

/// path_class của event NODE TỰ PHÁT — không đi qua mạng. Giá trị đặc biệt
/// không trộn với đường thật của peer nào (hash path_class va chạm ở đây với
/// xác suất 2^-64 — chấp nhận được cho mục đích đánh dấu).
pub const LOCAL_PATH: u64 = u64::MAX;

/// Bản ghi đường nhận một event — nguồn cho quorum điều kiện 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArrivalRecord {
    path: u64,
    received_mono_ms: u64,
}

/// Handle engine giữ cho một connection — task thật sở hữu session/link.
/// `conn_id` duy nhất trong node: hai link cùng peer cùng đường (cùng
/// path_class) vẫn phân biệt được khi release/retain.
struct ConnHandle {
    conn_id: u64,
    payload_tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Trạng thái engine — mọi mutation serialize qua một tokio Mutex.
struct NodeCore {
    manager: super::transport::TransportManager,
    connections: HashMap<NodeId, Vec<ConnHandle>>,
    graph: MeshGraph,
    inbox: GossipInbox,
    reputation: ReputationLedger,
    shadow: ShadowLedger,
    /// Neo pinning từ enrollment (plan §2.3) — peer không có neo = từ chối.
    pinned: HashMap<NodeId, VerifyingKey>,
    /// I-1: node đang TỰ cách ly — deadline mono tuyệt đối (None = không).
    /// Đang isolated: từ chối inbound handshake, không advertise.
    self_isolated_until: Option<u64>,
    /// I-2: sổ quyết định của operator (approve/lift/reject) — audit trail.
    decisions: DecisionLog,
    /// M-3: pinning device_id WFD → NodeId (kênh enrollment; bounded).
    wfd_pins: HashMap<String, NodeId>,
    /// M-4: BLE presence — node_prefix → mono ms thấy gần đây (zero trust).
    ble_seen: HashMap<[u8; 8], u64>,
    ble_seen_order: VecDeque<[u8; 8]>,
    /// I-2 grace de-escalation: subject → số tick sạch còn lại trước khi
    /// được hạ từ Suspect lên Attested.
    probation: HashMap<NodeId, u32>,
    epoch: u64,
    next_origin_seq: u64,
    next_conn_id: u64,
    arrival: HashMap<[u8; 32], ArrivalRecord>,
    arrival_order: VecDeque<[u8; 32]>,
    stats: MeshNodeStats,
    /// Gate 4: Bộ kiểm soát nhập môn (Admission Gate) và State Machine.
    admission: super::admission::MeshAdmissionController,
}

/// Một node mesh chạy thật trên transport TCP (Tier A).
#[derive(Clone)]
pub struct MeshNode {
    identity: Arc<DeviceIdentityKey>,
    self_id: NodeId,
    config: MeshNodeConfig,
    clock: Arc<dyn MeshClock>,
    transport: Arc<Mutex<TcpLanTransport>>,
    /// Nguồn discovery mDNS (M-2) — None khi chưa bật.
    discovery: Arc<Mutex<Option<MdnsDiscovery>>>,
    /// I-2: desk thực thi cách ly (WFP thật hoặc logic-only trung thực).
    desk: Arc<Mutex<IsolationDesk>>,
    /// M-3 Tier B — None khi flag tắt / chưa bật.
    wfd: Arc<Mutex<Option<WfdTransport>>>,
    /// M-4 Tier C — None khi flag tắt / chưa bật.
    ble: Arc<Mutex<Option<BleDiscovery>>>,
    core: Arc<Mutex<NodeCore>>,
}

impl MeshNode {
    pub fn new(
        identity: DeviceIdentityKey,
        pinned_peers: HashMap<NodeId, VerifyingKey>,
        config: MeshNodeConfig,
    ) -> Self {
        Self::with_clock(identity, pinned_peers, config, Arc::new(SystemClock::new()))
    }

    pub fn with_clock(
        identity: DeviceIdentityKey,
        pinned_peers: HashMap<NodeId, VerifyingKey>,
        config: MeshNodeConfig,
        clock: Arc<dyn MeshClock>,
    ) -> Self {
        let self_id = identity.verifying_key().to_bytes();
        let mut graph = MeshGraph::new();
        // Node CỦA CHÍNH MÌNH vào graph: Discovered → Attested ngay khi dựng —
        // engine giữ identity key cục bộ, "attested" ở đây nghĩa là identity
        // đã được xác thực nội bộ (không phải claim từ bên ngoài).
        let mono = clock.now_mono_ms();
        let _ = graph.observe(self_id, mono);
        let _ = graph.transition(&self_id, NodeState::Attested);

        let transport = TcpLanTransport::new(Duration::from_millis(config.connect_timeout_ms));
        let policy = TransportPolicy {
            max_links_per_peer: config.max_links_per_peer,
            max_total_links: config.max_total_links,
        };
        let gossip_policy = config.gossip.clone();
        let mut admission = super::admission::MeshAdmissionController::new(config.admission.clone());
        for &peer_id in pinned_peers.keys() {
            admission.authorize_peer(peer_id);
        }
        Self {
            identity: Arc::new(identity),
            self_id,
            config,
            clock,
            transport: Arc::new(Mutex::new(transport)),
            discovery: Arc::new(Mutex::new(None)),
            desk: Arc::new(Mutex::new(IsolationDesk::open())),
            wfd: Arc::new(Mutex::new(None)),
            ble: Arc::new(Mutex::new(None)),
            core: Arc::new(Mutex::new(NodeCore {
                manager: super::transport::TransportManager::with_policy(policy),
                connections: HashMap::new(),
                graph,
                inbox: GossipInbox::with_log(gossip_policy, EventLog::default()),
                reputation: ReputationLedger::default(),
                shadow: ShadowLedger::new(),
                pinned: pinned_peers,
                self_isolated_until: None,
                decisions: DecisionLog::new(),
                wfd_pins: HashMap::new(),
                ble_seen: HashMap::new(),
                ble_seen_order: VecDeque::new(),
                probation: HashMap::new(),
                epoch: 0,
                next_origin_seq: 1,
                next_conn_id: 1,
                arrival: HashMap::new(),
                arrival_order: VecDeque::new(),
                stats: MeshNodeStats::default(),
                admission,
            })),
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.self_id
    }

    pub fn config(&self) -> &MeshNodeConfig {
        &self.config
    }

    /// Trạng thái thực thi hiện hành của nút (Gate 4).
    pub async fn enforcement_state(&self) -> super::admission::MeshEnforcementState {
        self.core.lock().await.admission.state()
    }

    /// Thiết lập trạng thái thực thi cho nút.
    pub async fn set_enforcement_state(&self, state: super::admission::MeshEnforcementState) {
        self.core.lock().await.admission.set_state(state);
    }

    /// Thêm peer được ủy quyền vào Admission Gate và Pinned map.
    pub async fn authorize_peer(&self, peer: NodeId, vk: VerifyingKey) {
        let mut core = self.core.lock().await;
        core.admission.authorize_peer(peer);
        core.pinned.insert(peer, vk);
    }

    /// Bind listener (nếu chưa) + bật accept loop. Gọi lần hai → lỗi rõ ràng
    /// (transport đã lắng nghe) — không idempotent âm thầm.
    pub async fn start(&self) -> Result<(), MeshError> {
        self.ensure_listener_bound().await?;
        let inbound = {
            let mut t = self.transport.lock().await;
            t.listen()?
        };
        tokio::spawn(self.clone().accept_loop(inbound));
        tracing::info!(addr = ?self.transport.lock().await.local_addr(), "mesh node lắng nghe TCP (Tier A)");
        Ok(())
    }

    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.transport.lock().await.local_addr()
    }

    /// Kết nối outbound tới một peer ĐÃ PIN neo (vk từ enrollment — plan §2.3).
    /// Peer chưa pin = `UnknownPeer`, không bao giờ trust-on-first-use.
    pub async fn connect_peer(&self, peer: NodeId, addr: SocketAddr) -> Result<(), MeshError> {
        // I-1: node đang TỰ cách ly không chủ động mở link mới (outbound).
        {
            let core = self.core.lock().await;
            let isolated_now = core
                .self_isolated_until
                .is_some_and(|until| self.clock.now_mono_ms() < until);
            if isolated_now {
                return Err(MeshError::LinkClosed("node đang tự cách ly".into()));
            }
        }
        let vk = {
            self.core
                .lock()
                .await
                .pinned
                .get(&peer)
                .copied()
        }
        .ok_or_else(|| MeshError::UnknownPeer(hex_short(&peer)))?;

        let ep = Endpoint { transport: TransportId::TcpLan, addr };
        let link = {
            let mut t = self.transport.lock().await;
            t.connect(ep).await?
        };
        self.establish_outbound(peer, vk, link).await
    }

    /// Bắt tay 3 bước phía initiator trên một link đã nối (TCP-LAN hoặc WFD)
    /// rồi đăng ký connection — dùng chung cho mọi transport.
    async fn establish_outbound(
        &self,
        peer: NodeId,
        vk: VerifyingKey,
        mut link: Box<dyn MeshLink>,
    ) -> Result<(), MeshError> {
        let initiator = Initiator::new(
            HandshakeConfig {
                identity: self.identity.as_ref(),
                peer_vk: vk,
                peer_node_id: peer,
                version: MESH_WIRE_VERSION,
            },
            &mut OsCryptoRng,
        )?;
        link.write_frame(&initiator.hello().encode()).await?;
        let ack_frame = link.read_frame().await?;
        let ack = HandshakeMessage::decode(&ack_frame)?;
        let (session, confirm) = initiator.handle_ack(&ack)?;
        link.write_frame(&confirm.encode()).await?;
        self.register_connection(peer, link, session).await
    }

    /// Ký + phát một event CỦA CHÍNH NODE. `origin_seq` do engine cấp
    /// (monotonic) rồi ký lại — trả về `(số link đã xếp hàng, event ĐÃ KÝ)`
    /// vì event_id thay đổi sau khi cấp seq (caller không được tin id cũ).
    /// Vote tự thân KHÔNG tự nâng weight (ReputationLedger không có hồ sơ
    /// self — fail-closed).
    pub async fn gossip_signed(&self, mut event: NsgEvent) -> Result<(usize, NsgEvent), MeshError> {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let mut core = self.core.lock().await;
        event.origin_id = self.self_id;
        event.epoch = core.epoch;
        event.origin_seq = core.next_origin_seq;
        core.next_origin_seq = core.next_origin_seq.saturating_add(1);
        event.sign(self.identity.as_ref());

        // Event của chính mình cũng phải qua log (dedupe/replay/bound như mọi
        // nguồn) — nguồn sự thật duy nhất cho quorum.
        let epoch = core.epoch;
        core.inbox
            .log_mut()
            .accept(event.clone(), self.identity.verifying_key(), now_wall, epoch)?;
        Self::record_arrival(&mut core, event.event_id, LOCAL_PATH, now_mono);

        let payload = event.to_wire();
        let mut queued = 0usize;
        for handles in core.connections.values() {
            for handle in handles {
                if handle.payload_tx.send(payload.clone()).is_ok() {
                    queued = queued.saturating_add(1);
                }
            }
        }
        Ok((queued, event))
    }

    /// Đánh giá quorum cho một subject từ log cục bộ. Weight từ
    /// ReputationLedger (peer chưa có hồ sơ = 0 — fail-closed); path từ sổ
    /// arrival (mất dữ liệu đường → 0 = gộp về cùng đường — thiên về chặt).
    /// Quorum đạt → GHI ShadowLedger (shadow mode — KHÔNG thực thi, NSG-3).
    pub async fn evaluate_subject(&self, subject: NodeId) -> QuorumOutcome {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let mut core = self.core.lock().await;
        let mut ballots: Vec<Ballot> = Vec::new();
        for ev in core.inbox.log().iter() {
            if ev.subject != Some(subject) || !ev.is_decision_fresh(now_wall) {
                continue;
            }
            let weight = core.reputation.weight_of(&ev.origin_id);
            let path = core.arrival.get(&ev.event_id).map(|r| r.path).unwrap_or(0);
            if let Some(ballot) = Ballot::from_event(ev, weight, path) {
                ballots.push(ballot);
            }
        }
        // Revocation feed (transparency list) nối vào ở D2 — hiện không ai revoked.
        let outcome = evaluate_quorum(&ballots, subject, core.epoch, |_| false, &self.config.quorum);
        if let QuorumVerdict::Reached { .. } = outcome.verdict {
            match core
                .shadow
                .record(subject, &outcome, self.config.isolation_ttl_ms, now_mono)
            {
                Ok(()) => {
                    core.stats.quorum_reached = core.stats.quorum_reached.saturating_add(1);
                }
                Err(_) => {
                    // Sổ đầy — đếm rõ ràng, không âm thầm (INV-010).
                    core.stats.shadow_dropped = core.stats.shadow_dropped.saturating_add(1);
                }
            }
        }
        outcome
    }

    /// Tick vận hành: GC graph (auto-lift isolation hết TTL, stale node/edge)
    /// + xả sổ arrival hết hạn. Trả GcReport để caller audit.
    pub async fn tick(&self) -> GcReport {
        let now_mono = self.clock.now_mono_ms();
        let mut core = self.core.lock().await;
        // Node TỰ THÂN luôn "sống" khi engine đang chạy — refresh presence
        // trước GC để GC không dọn nhầm self-node.
        let _ = core.graph.heartbeat(&self.self_id, now_mono);
        // I-1: hết deadline tự cách ly → dọn cờ (GC sẽ lift self-node về
        // Unknown đúng luật INV-014 — reversibility outranks persistence).
        if let Some(until) = core.self_isolated_until {
            if now_mono >= until {
                core.self_isolated_until = None;
                tracing::info!("hết TTL tự cách ly — engine mở lại inbound");
            }
        }
        let report = core.graph.tick_gc(now_mono);

        // Xả sổ arrival hết hạn (core còn cần ở đây).
        while let Some(oldest) = core.arrival_order.front().copied() {
            let expired = core
                .arrival
                .get(&oldest)
                .map(|r| now_mono.saturating_sub(r.received_mono_ms) >= self.config.arrival_ttl_ms)
                .unwrap_or(true);
            if expired {
                core.arrival_order.pop_front();
                core.arrival.remove(&oldest);
            } else {
                break;
            }
        }

        // I-2 §6.3 grace de-escalation: tick sạch → đếm lùi; về 0 và đang
        // Suspect → Attested. Node chưa ở Suspect giữ nguyên số tick
        // (probation chỉ tiêu khi node thực sự trong giai đoạn thử).
        let subjects: Vec<NodeId> = core.probation.keys().copied().collect();
        for subject in subjects {
            let Some(node) = core.graph.node(&subject) else {
                core.probation.remove(&subject);
                continue;
            };
            if node.state != NodeState::Suspect {
                continue;
            }
            let left = core.probation.get_mut(&subject).map(|t| {
                *t = t.saturating_sub(1);
                *t
            });
            if left == Some(0) {
                core.probation.remove(&subject);
                if core.graph.transition(&subject, NodeState::Attested).is_ok() {
                    tracing::info!("probation sạch — subject về Attested");
                }
            }
        }
        drop(core);

        // I-2 §9 watchdog: quét WFP rule hết hạn — idempotent; lỗi chỉ warn
        // (sweep lại tick sau; deadline tuyệt đối không đổi theo reboot).
        {
            let mut desk = self.desk.lock().await;
            match desk.sweep(self.clock.now_wall_ms()) {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "đã dọn WFP rule hết hạn");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = ?e, "WFP sweep lỗi — sẽ thử lại tick sau"),
            }
        }
        report
    }

    /// Bật mDNS discovery (M-2): quảng bá beacon cục bộ kèm port TCP
    /// listener + bắt đầu browse dịch vụ mesh.
    ///
    /// Yêu cầu listener đã bind (start()) để biết port. Gọi lần hai → lỗi rõ ràng.
    pub async fn enable_mdns(&self) -> Result<(), MeshError> {
        {
            let slot = self.discovery.lock().await;
            if slot.is_some() {
                return Err(MeshError::InvalidEndpoint("mDNS discovery đã bật".into()));
            }
        }
        let port = self.ensure_listener_bound().await?.port();
        let beacon = MeshBeacon {
            node_id: self.self_id,
            vk: self.identity.verifying_key().to_bytes(),
            wire_version: BEACON_VERSION,
        };
        let discovery = MdnsDiscovery::new()?;
        discovery.advertise(&beacon, port)?;
        *self.discovery.lock().await = Some(discovery);
        tracing::info!("mesh mDNS discovery đã bật (advertise + browse)");
        Ok(())
    }

    /// Một chu kỳ discovery (M-2): poll mDNS → beacon → `absorb_discovered`.
    pub async fn browse_and_connect(&self) -> Result<usize, MeshError> {
        let mut discovered = {
            let mut slot = self.discovery.lock().await;
            let Some(discovery) = slot.as_mut() else {
                return Err(MeshError::InvalidEndpoint("mDNS discovery chưa bật".into()));
            };
            discovery.browse()
        };
        self.absorb_discovered(&mut discovered).await
    }

    /// Tiếp nhận một loạt (beacon, endpoint) từ MỌI nguồn discovery — hiện
    /// là mDNS, M-4 (BLE) / M-3 (WiFi-Direct) sẽ cấp cùng dạng. Nhận beacon
    /// mới: pin neo → observe Discovered → tự connect nếu chưa có link.
    ///
    /// Ranh giới trung thực (INV-012): beacon KHÔNG nâng trust — pin neo từ
    /// beacon là first-contact (TOFU) vì NodeId ≡ vk theo thiết kế; beacon
    /// lệch node_id ≠ vk bị từ chối + đếm. Trust thật chỉ đến từ bắt tay chữ
    /// ký + reputation/quorum; enrollment thủ công vẫn là đường mạnh hơn.
    pub async fn absorb_discovered(
        &self,
        discovered: &mut Vec<(MeshBeacon, SocketAddr)>,
    ) -> Result<usize, MeshError> {
        discovered.retain(|(beacon, _)| beacon.node_id != self.self_id);
        discovered.sort_by_key(|(beacon, _)| beacon.node_id);

        let mut connected = 0usize;
        for (beacon, addr) in discovered.iter() {
            // Beacon lệch node_id ≠ vk = beacon giả — từ chối + đếm, không im lặng.
            if beacon.node_id != beacon.vk
                || beacon.wire_version != BEACON_VERSION
                || ed25519_dalek::VerifyingKey::from_bytes(&beacon.vk).is_err()
            {
                let mut core = self.core.lock().await;
                core.stats.beacons_rejected = core.stats.beacons_rejected.saturating_add(1);
                continue;
            }
            // from_bytes đã Ok ở gate trên — dựng vk cho map pinning.
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&beacon.vk)
                .expect("gate trên đã xác thực bytes");
            {
                let mut core = self.core.lock().await;
                let verdict = core.admission.evaluate_candidate(
                    &beacon.node_id,
                    &vk,
                    core.epoch,
                    core.pinned.len(),
                );
                if verdict != super::admission::AdmissionVerdict::Admitted {
                    core.stats.beacons_rejected = core.stats.beacons_rejected.saturating_add(1);
                    continue;
                }
                if core.pinned.insert(beacon.node_id, vk).is_none() {
                    // Node mới qua discovery — CHỈ Discovered (presence ≠ trust).
                    let _ = core.graph.observe(beacon.node_id, self.clock.now_mono_ms());
                }
            }
            // Peer chưa có link nào → tự connect (đúng M-PLAN M-2: discovery
            // tìm thấy rồi TCP connect; attest do bắt tay chữ ký đảm nhiệm).
            let has_link = !self
                .core
                .lock()
                .await
                .manager
                .records_of(&beacon.node_id)
                .is_empty();
            if !has_link && self.connect_peer(beacon.node_id, *addr).await.is_ok() {
                connected = connected.saturating_add(1);
            }
        }
        Ok(connected)
    }

    /// I-2 — Đề nghị cách ly đang CHỜ operator duyệt (Isolation Inbox):
    /// shadow entry `Reached` + `Pending` + mới hơn quyết định gần nhất của
    /// subject. KHÔNG tự thực thi — auto-pilot là I-3, vẫn bị freeze gate.
    pub async fn pending_isolation_proposals(&self) -> Vec<IsolationProposal> {
        let core = self.core.lock().await;
        let mut proposals = Vec::new();
        for entry in core.shadow.entries() {
            if !entry.reached || entry.outcome != super::shadow::ShadowOutcome::Pending {
                continue;
            }
            // Đề nghị cũ hơn quyết định gần nhất của subject = đã xử lý.
            if let Some(last) = core.decisions.latest_decision_mono(&entry.subject) {
                if entry.decided_mono_ms <= last {
                    continue;
                }
            }
            let ttl = match entry.proposed_action {
                super::shadow::ProposedAction::Isolate { ttl_ms } => ttl_ms,
                super::shadow::ProposedAction::Observe => continue,
            };
            proposals.push(IsolationProposal {
                subject: entry.subject,
                total_weight: entry.total_weight,
                accepted_event_ids: entry.accepted_event_ids.clone(),
                proposed_mono_ms: entry.decided_mono_ms,
                ttl_ms: ttl,
            });
            if proposals.len() >= 32 {
                break; // bound hiển thị — sổ shadow vẫn giữ đầy đủ
            }
        }
        proposals
    }

    /// I-2 — Operator DUYỆT cách ly (human-in-the-loop): thực thi WFP thật
    /// (nếu có) + graph Isolated + cắt link + arm probation. Yêu cầu có đề
    /// nghị quorum đang chờ (không ai được isolate tay không căn cứ).
    pub async fn approve_isolation(&self, subject: NodeId, reason: &str) -> Result<EnforcementMode, MeshError> {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let ttl = self.config.isolation_ttl_ms;

        // 1. Phải có đề nghị quorum đang chờ — không có = từ chối rõ ràng.
        let refs = {
            let core = self.core.lock().await;
            let has_pending = core.shadow.entries().any(|e| {
                e.reached
                    && e.subject == subject
                    && e.outcome == super::shadow::ShadowOutcome::Pending
                    && core
                        .decisions
                        .latest_decision_mono(&subject)
                        .is_none_or(|last| e.decided_mono_ms > last)
            });
            if !has_pending {
                return Err(MeshError::EventRejected(
                    "không có đề nghị cách ly đang chờ cho subject này".into(),
                ));
            }
            core.shadow
                .entries()
                .filter(|e| e.reached && e.subject == subject)
                .last()
                .map(|e| e.accepted_event_ids.clone())
                .unwrap_or_default()
        };

        // 2. Thực thi: WFP per-IP khi peer có link đang sống; loopback/không
        //    link/không quyền → LogicOnly trung thực (không giả vờ chặn).
        let ip = {
            let core = self.core.lock().await;
            core.manager
                .records_of(&subject)
                .first()
                .map(|r| r.addr.ip())
        };
        let until_unix = now_wall.saturating_add(ttl);
        let enforcement = {
            let mut desk = self.desk.lock().await;
            match desk.block(ip, &subject, until_unix) {
                Ok(mode) => mode,
                Err(e) => {
                    tracing::warn!(error = ?e, "WFP block thất bại — hạ xuống logic-only");
                    EnforcementMode::LogicOnly
                }
            }
        };

        // 3. Graph: Attested → Suspect → Isolated(TTL); cắt link; arm probation.
        {
            let mut core = self.core.lock().await;
            if let Some(node) = core.graph.node(&subject) {
                if node.state == NodeState::Attested {
                    core.graph.transition(&subject, NodeState::Suspect)?;
                }
            }
            core.graph.isolate_with_ttl(&subject, now_mono, ttl)?;
            core.probation.insert(subject, self.config.probation_ticks);
        }
        self.disconnect_peer(&subject).await;

        // 4. Ghi quyết định — audit hai chiều (refs = evidence trace).
        {
            let mut core = self.core.lock().await;
            core.decisions.record(DecisionEntry {
                subject,
                action: DecisionAction::Approve,
                enforcement,
                evidence_refs: refs.clone(),
                decided_mono_ms: now_mono,
                decided_wall_ms: now_wall,
                reason: reason.chars().take(MAX_REASON_LEN).collect(),
            })?;
        }
        tracing::warn!(
            ?enforcement,
            ttl_ms = ttl,
            "OPERATOR DUYỆT cách ly subject (I-2)"
        );
        Ok(enforcement)
    }

    /// I-2 — Admin gỡ cách ly (UAC ở tầng UI): WFP unblock + graph về
    /// **Suspect** (KHÔNG nhảy Attested — lift không phải recovery ký
    /// authority theo INV-014) + arm probation K tick sạch.
    pub async fn lift_isolation(&self, subject: NodeId, reason: &str) -> Result<(), MeshError> {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();

        // WFP unblock trước — traffic mở sau khi graph nhất quán.
        {
            let mut desk = self.desk.lock().await;
            if let Err(e) = desk.unblock(&subject) {
                tracing::warn!(error = ?e, "WFP unblock lỗi khi lift");
            }
        }

        {
            let mut core = self.core.lock().await;
            let Some(node) = core.graph.node(&subject) else {
                return Err(super::MeshError::UnknownNode(hex_short(&subject)));
            };
            if node.state != NodeState::Isolated {
                return Err(super::MeshError::IllegalTransition {
                    from: node.state.as_str(),
                    to: "Suspect (lift chỉ áp cho Isolated)",
                });
            }
            core.graph.transition(&subject, NodeState::Suspect)?;
            core.probation.insert(subject, self.config.probation_ticks);
        }

        let mut core = self.core.lock().await;
        let enforcement = desk_mode(&self.desk).await;
        core.decisions.record(DecisionEntry {
            subject,
            action: DecisionAction::Lift,
            enforcement,
            evidence_refs: vec![],
            decided_mono_ms: now_mono,
            decided_wall_ms: now_wall,
            reason: reason.chars().take(MAX_REASON_LEN).collect(),
        })?;
        drop(core);
        tracing::info!("admin gỡ cách ly — subject về Suspect (probation)");
        Ok(())
    }

    /// I-2 — Operator TỪ CHỐI đề nghị (không thực thi gì): chỉ ghi DecisionLog
    /// để đề nghị không hiện lại trong Inbox. Không đụng graph/WFP.
    pub async fn reject_isolation(&self, subject: NodeId, reason: &str) -> Result<(), MeshError> {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let mut core = self.core.lock().await;
        core.decisions.record(DecisionEntry {
            subject,
            action: DecisionAction::Reject,
            enforcement: EnforcementMode::NotExecuted,
            evidence_refs: vec![],
            decided_mono_ms: now_mono,
            decided_wall_ms: now_wall,
            reason: reason.chars().take(MAX_REASON_LEN).collect(),
        })
    }

    /// Chế độ enforcement hiện hành của desk (UI hiển thị trung thực).
    pub async fn enforcement_mode(&self) -> EnforcementMode {
        self.desk.lock().await.mode()
    }

    /// I-1 — TỰ cách ly khi defense pipeline phát hiện tamper cục bộ
    /// (plan §9 "tự cách ly", M-PLAN §6.1 bậc I-1): node tự hạ `Isolated`
    /// với TTL bắt buộc (INV-014 — không có isolation vĩnh viễn), phát
    /// IsolationAlert CÓ CHỮ KÝ (subject ≡ origin) cho peer, rồi cắt MỌI
    /// link mesh + ngừng advertise. Peer nhận alert chỉ hành động theo
    /// hướng xấu nhất: hạ subject về Isolated (không bao giờ nâng trust).
    pub async fn self_isolate(&self, reason: &str) -> Result<(), MeshError> {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let ttl = self.config.isolation_ttl_ms;

        {
            let mut core = self.core.lock().await;
            if let Some(until) = core.self_isolated_until {
                if now_mono < until {
                    return Ok(()); // đã đang isolated trong hạn — idempotent
                }
            }
            // Self-node trong graph: Attested → Suspect → Isolated + TTL.
            core.graph.transition(&self.self_id, NodeState::Suspect)?;
            core.graph.isolate_with_ttl(&self.self_id, now_mono, ttl)?;
            core.self_isolated_until = Some(now_mono.saturating_add(ttl));
            // Sau TTL, self re-attest cũng phải qua probation (I-2 §6.3).
            core.probation.insert(self.self_id, self.config.probation_ticks);
        }

        // 1. Alert CÓ CHỮ KÝ — gửi TRƯỚC khi cắt link (lần giao cuối cùng).
        //    evidence_root = hash domain-separate của lý do — audit được.
        let mut hasher = Sha512::new();
        hasher.update(b"CYBERV/MESH/SELFISO/v1");
        hasher.update([0x00]);
        hasher.update(reason.as_bytes());
        let digest = hasher.finalize();
        let mut evidence_root = [0u8; 32];
        evidence_root.copy_from_slice(&digest[..32]);
        let alert = NsgEvent {
            event_id: [0; 32],
            origin_id: self.self_id,
            origin_seq: 0, // gossip_signed tự cấp
            epoch: 0,
            causal_parents: vec![],
            evidence_root: Some(evidence_root),
            created_wall_ms: now_wall,
            expiry_wall_ms: now_wall.saturating_add(ttl),
            kind: EventKind::IsolationAlert,
            signal_class: Some(SignalClass::Verified),
            subject: Some(self.self_id),
            obs_channel: None,
            signature: [0; 64],
        };
        let sent = self.gossip_signed(alert).await?;
        tracing::warn!(reason = reason, frames = sent.0, "NODE TỰ CÁCH LY (I-1)");

        // 2. Cắt toàn bộ link mesh + ngừng advertise. Kênh update/rendezvous
        //    (ngoài mesh) không thuộc phạm vi engine này — xem plan §9.
        self.disconnect_all().await;
        self.disable_mdns().await;
        Ok(())
    }

    /// Deadline tự cách ly hiện hành (mono ms) — None nếu không isolated.
    pub async fn self_isolated_until(&self) -> Option<u64> {
        self.core.lock().await.self_isolated_until
    }

    // ================= M-3 Tier B — WiFi Direct (flag tắt mặc định) =========

    /// Pin device_id WFD → NodeId (kênh enrollment — peer phải đã có neo vk).
    /// Không có mapping → `connect_wifi_direct` từ chối (không TOFU qua WFD).
    pub async fn pin_wfd_device(&self, device_id: &str, peer: NodeId) -> Result<(), MeshError> {
        if device_id.is_empty() || device_id.len() > 512 {
            return Err(MeshError::InvalidEndpoint("device_id WFD không hợp lệ".into()));
        }
        let mut core = self.core.lock().await;
        if !core.pinned.contains_key(&peer) {
            return Err(MeshError::UnknownPeer(hex_short(&peer)));
        }
        if core.wfd_pins.len() >= 256 && !core.wfd_pins.contains_key(device_id) {
            return Err(MeshError::LimitExceeded { kind: "wfd-pin", dropped: 256 });
        }
        core.wfd_pins.insert(device_id.to_string(), peer);
        Ok(())
    }

    /// Bật WFD advertise + browse (M-3). Flag tắt → lỗi rõ; shim không hỗ
    /// trợ (stub/radio tắt) → lỗi trung thực, không giả vờ.
    pub async fn enable_wifi_direct(&self) -> Result<(), MeshError> {
        if !self.config.wifi_direct_enabled {
            return Err(MeshError::InvalidEndpoint(
                "wifi_direct_enabled = false trong cấu hình (Tier B tắt mặc định)".into(),
            ));
        }
        {
            let slot = self.wfd.lock().await;
            if slot.is_some() {
                return Err(MeshError::InvalidEndpoint("WFD đã bật".into()));
            }
        }
        let mut transport = WfdTransport::default();
        transport.advertise()?;
        *self.wfd.lock().await = Some(transport);
        tracing::info!("mesh WiFi Direct đã bật (advertise) — Tier B experimental");
        Ok(())
    }

    pub async fn disable_wifi_direct(&self) -> Result<(), MeshError> {
        let mut slot = self.wfd.lock().await;
        match slot.take() {
            Some(mut transport) => {
                let _ = transport.advertise_stop();
                Ok(())
            }
            None => Err(MeshError::InvalidEndpoint("WFD chưa bật".into())),
        }
    }

    /// Poll ConnectionRequested mới (phía accept). KHÔNG tự accept — Tier B
    /// experimental: accept là hành động chủ đích qua `connect_wifi_direct`
    /// (cùng WinRT API, device_id lấy từ request này).
    pub async fn poll_wfd_connections(&self) -> Result<Vec<String>, MeshError> {
        let (requests, dropped) = {
            let mut slot = self.wfd.lock().await;
            let Some(transport) = slot.as_mut() else {
                return Err(MeshError::InvalidEndpoint("WFD chưa bật".into()));
            };
            transport.poll_connections()?
        };
        if dropped > 0 {
            tracing::warn!(dropped, "WFD request queue drop — tăng tần suất poll");
        }
        let mut core = self.core.lock().await;
        core.stats.wfd_requests_seen =
            core.stats.wfd_requests_seen.saturating_add(requests.len() as u64);
        Ok(requests)
    }

    /// Kết nối mesh qua WFD: shim thiết lập phiên WinRT → endpoint TCP thuần
    /// → link với path_class(WiFiDirect) → bắt tay mesh chuẩn (pinning bắt
    /// buộc — peer phải có neo vk + mapping device_id khớp).
    pub async fn connect_wifi_direct(&self, device_id: &str, peer: NodeId) -> Result<(), MeshError> {
        let (vk, pinned_matches) = {
            let core = self.core.lock().await;
            (
                core.pinned.get(&peer).copied(),
                core.wfd_pins.get(device_id).copied(),
            )
        };
        // Mismatch device_id ↔ peer kiểm TRƯỚC vk — lỗi mapping là lỗi cấu
        // hình, không phải lỗi "peer lạ".
        if pinned_matches != Some(peer) {
            return Err(MeshError::InvalidEndpoint(
                "device_id WFD không khớp pinning enrollment của peer này".into(),
            ));
        }
        let Some(vk) = vk else {
            return Err(MeshError::UnknownPeer(hex_short(&peer)));
        };
        let utf16: Vec<u16> = device_id.encode_utf16().collect();
        let endpoint =
            wfd::establish_endpoint(&utf16, self.config.connect_timeout_ms.min(u32::MAX as u64) as u32)?;
        let stream = TcpStream::connect(endpoint.addr)
            .await
            .map_err(|e| MeshError::TransportIo(format!("TCP trên WFD {}: {e}", endpoint.addr)))?;
        stream.set_nodelay(true).ok();
        let link = Box::new(TcpLink::new_with_transport(stream, endpoint.addr, TransportId::WiFiDirect));
        self.establish_outbound(peer, vk, link).await
    }

    // ================= M-4 Tier C — BLE beacon (discovery only) ==============

    /// Quảng bá beacon BLE nén 26 byte (presence — không mang trust).
    pub async fn enable_ble_advertise(&self, beacon: &BleBeacon26) -> Result<(), MeshError> {
        if !self.config.ble_discovery_enabled {
            return Err(MeshError::InvalidEndpoint(
                "ble_discovery_enabled = false trong cấu hình (Tier C tắt mặc định)".into(),
            ));
        }
        ble::advertise(beacon)
    }

    pub async fn disable_ble_advertise(&self) -> Result<(), MeshError> {
        ble::advertise_stop()
    }

    /// Bật BLE watcher (presence của node khác).
    pub async fn enable_ble_watch(&self) -> Result<(), MeshError> {
        if !self.config.ble_discovery_enabled {
            return Err(MeshError::InvalidEndpoint(
                "ble_discovery_enabled = false trong cấu hình (Tier C tắt mặc định)".into(),
            ));
        }
        {
            let slot = self.ble.lock().await;
            if slot.is_some() {
                return Err(MeshError::InvalidEndpoint("BLE watch đã bật".into()));
            }
        }
        let mut discovery = BleDiscovery::default();
        discovery.start_watch()?;
        *self.ble.lock().await = Some(discovery);
        Ok(())
    }

    pub async fn disable_ble_watch(&self) -> Result<(), MeshError> {
        let mut slot = self.ble.lock().await;
        match slot.take() {
            Some(mut discovery) => discovery.stop_watch(),
            None => Err(MeshError::InvalidEndpoint("BLE watch chưa bật".into())),
        }
    }

    /// Poll BLE presence từ shim → absorb. Trả số sample hợp lệ.
    /// Payload không decode được (đếm riêng) bị bỏ — không bao giờ raise trust.
    pub async fn poll_ble_presence(&self) -> Result<usize, MeshError> {
        let raw = {
            let mut slot = self.ble.lock().await;
            let Some(discovery) = slot.as_mut() else {
                return Err(MeshError::InvalidEndpoint("BLE watch chưa bật".into()));
            };
            discovery.poll()?
        };
        let mut malformed = 0u64;
        let mut parsed: Vec<(BleBeacon26, [u8; 6])> = Vec::with_capacity(raw.len());
        for (addr6, payload) in raw {
            match BleBeacon26::decode(&payload) {
                Ok(beacon) => parsed.push((beacon, addr6)),
                Err(_) => malformed += 1,
            }
        }
        if malformed > 0 {
            let mut core = self.core.lock().await;
            core.stats.ble_beacons_malformed =
                core.stats.ble_beacons_malformed.saturating_add(malformed);
        }
        Ok(self.absorb_ble_presence(&mut parsed).await)
    }

    /// Tiếp nhận BLE presence — **ZERO TRUST** (M-PLAN §5, plan §10 Tier C):
    /// chỉ ghi sổ presence (`ble_seen`); KHÔNG observe graph, KHÔNG pin,
    /// KHÔNG tạo node, KHÔNG feed quorum. Bất biến được test chốt: presence
    /// BLE không đổi NodeState của bất kỳ node nào.
    pub async fn absorb_ble_presence(&self, samples: &mut [(BleBeacon26, [u8; 6])]) -> usize {
        let now_mono = self.clock.now_mono_ms();
        let mut core = self.core.lock().await;
        let mut absorbed = 0usize;
        for (beacon, _addr6) in samples.iter() {
            // Trần sổ presence — evict cũ nhất, đếm (INV-015).
            while core.ble_seen.len() >= 256 && !core.ble_seen.contains_key(&beacon.node_prefix) {
                match core.ble_seen_order.pop_front() {
                    Some(old) => {
                        core.ble_seen.remove(&old);
                    }
                    None => break,
                }
                core.stats.ble_presence_dropped = core.stats.ble_presence_dropped.saturating_add(1);
            }
            if !core.ble_seen.contains_key(&beacon.node_prefix) {
                core.ble_seen_order.push_back(beacon.node_prefix);
            }
            core.ble_seen.insert(beacon.node_prefix, now_mono);
            absorbed += 1;
        }
        core.stats.ble_samples_seen = core.stats.ble_samples_seen.saturating_add(absorbed as u64);
        absorbed
    }

    /// BLE đã thấy node_prefix này gần đây? (chỉ presence — không phải trust)
    pub async fn ble_seen_recently(&self, node_prefix: &[u8; 8], now_mono_ms: u64, within_ms: u64) -> bool {
        let core = self.core.lock().await;
        core.ble_seen
            .get(node_prefix)
            .is_some_and(|t| now_mono_ms.saturating_sub(*t) <= within_ms)
    }

    /// Ngắt mDNS discovery — link TCP đã có KHÔNG bị đụng (offline-first).
    pub async fn disable_mdns(&self) -> bool {
        let mut slot = self.discovery.lock().await;
        match slot.take() {
            Some(discovery) => {
                discovery.shutdown();
                true
            }
            None => false,
        }
    }

    async fn ensure_listener_bound(&self) -> Result<SocketAddr, MeshError> {
        let mut t = self.transport.lock().await;
        if t.local_addr().is_none() {
            *t = TcpLanTransport::bind(
                self.config.listen_addr,
                Duration::from_millis(self.config.connect_timeout_ms),
            )
            .await?;
        }
        t.local_addr()
            .ok_or_else(|| MeshError::InvalidEndpoint("listener chưa bind".into()))
    }

    /// Chủ động ngắt mọi link tới một peer (vận hành + sẽ dùng cho isolation).
    /// Connection task tự kết thúc (channel đứt) và đóng socket; release/count
    /// được task tự ghi qua `on_link_down` — hàm này chỉ bỏ handle.
    pub async fn disconnect_peer(&self, peer: &NodeId) -> usize {
        let mut core = self.core.lock().await;
        let removed = core.connections.remove(peer).unwrap_or_default();
        let count = removed.len();
        // Drop sender ở đây: task thấy Disconnected → tự on_link_down
        // (release registry + đếm links_closed) — không nhân đôi ở hai nơi.
        drop(removed);
        count
    }

    /// Ngắt MỌI liên kết (self-isolation cắt mesh — I-1 sẽ dùng).
    pub async fn disconnect_all(&self) -> usize {
        let mut core = self.core.lock().await;
        let peers: Vec<NodeId> = core.connections.keys().copied().collect();
        let mut count = 0usize;
        for peer in peers {
            if let Some(removed) = core.connections.remove(&peer) {
                count += removed.len();
            }
        }
        count
    }

    // -- đo đạc / kiểm chứng (dùng cho dashboard + test) ---------------------

    pub async fn state_of(&self, peer: &NodeId) -> Option<NodeState> {
        self.core.lock().await.graph.node(peer).map(|n| n.state)
    }

    pub async fn edge_state(&self, peer: &NodeId) -> Option<super::graph::EdgeState> {
        self.core
            .lock()
            .await
            .graph
            .edge(&self.self_id, peer)
            .map(|e| e.state)
    }

    pub async fn log_contains(&self, event_id: &[u8; 32]) -> bool {
        self.core.lock().await.inbox.log().get(event_id).is_some()
    }

    pub async fn log_len(&self) -> usize {
        self.core.lock().await.inbox.log().len()
    }

    pub async fn stats(&self) -> MeshNodeStats {
        self.core.lock().await.stats
    }

    pub async fn active_link_count(&self) -> usize {
        self.core.lock().await.manager.total_links()
    }

    pub async fn paths_of(&self, peer: &NodeId) -> Vec<u64> {
        self.core.lock().await.manager.paths_of(peer)
    }

    pub async fn arrival_path_of(&self, event_id: &[u8; 32]) -> Option<u64> {
        self.core.lock().await.arrival.get(event_id).map(|r| r.path)
    }

    pub async fn shadow_len(&self) -> usize {
        self.core.lock().await.shadow.len()
    }

    // -- nội bộ ---------------------------------------------------------------

    async fn accept_loop(self, mut inbound: InboundLinks) {
        while let Some(link) = inbound.next().await {
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handshake_inbound(link).await {
                    // Từ chối bắt tay là từ chối CÓ CHỦ ĐÍCH (unknown peer,
                    // handshake sai) — đã đếm trong stats; log mức debug.
                    tracing::debug!(error = %e, "mesh inbound bị từ chối");
                }
            });
        }
    }

    async fn handshake_inbound(self, mut link: Box<dyn MeshLink>) -> Result<(), MeshError> {
        // Đang TỰ cách ly (I-1) → từ chối mọi inbound handshake, fail-closed.
        {
            let mut core = self.core.lock().await;
            let isolated_now = core
                .self_isolated_until
                .is_some_and(|until| self.clock.now_mono_ms() < until);
            if isolated_now {
                core.stats.inbound_rejected_isolated =
                    core.stats.inbound_rejected_isolated.saturating_add(1);
                return Err(MeshError::LinkClosed("node đang tự cách ly".into()));
            }
        }
        let first = link.read_frame().await?;
        let hello = HandshakeMessage::decode(&first)?;
        let peer = match &hello {
            HandshakeMessage::Hello { node_id, .. } => *node_id,
            _ => {
                return Err(MeshError::HandshakeFailed(
                    "frame đầu inbound không phải Hello".into(),
                ))
            }
        };
        let vk = {
            let mut core = self.core.lock().await;
            let Some(vk) = core.pinned.get(&peer).copied() else {
                core.stats.links_dropped_unknown_peer =
                    core.stats.links_dropped_unknown_peer.saturating_add(1);
                return Err(MeshError::UnknownPeer(hex_short(&peer)));
            };
            // Pre-check cap TRƯỚC khi bắt tay — link thừa bị cắt sớm, không
            // tốn mật mã (admit ở register_connection vẫn là chốt cuối).
            if core.manager.would_exceed_cap(&peer) {
                core.stats.links_dropped_over_cap =
                    core.stats.links_dropped_over_cap.saturating_add(1);
                return Err(MeshError::LimitExceeded {
                    kind: "mesh-link",
                    dropped: core.stats.links_dropped_over_cap,
                });
            }
            vk
        };
        let mut responder = Responder::new(
            HandshakeConfig {
                identity: self.identity.as_ref(),
                peer_vk: vk,
                peer_node_id: peer,
                version: MESH_WIRE_VERSION,
            },
            &mut OsCryptoRng,
        )?;
        let ack = responder.handle_hello(&hello)?;
        link.write_frame(&ack.encode()).await?;
        let confirm_frame = link.read_frame().await?;
        let confirm = HandshakeMessage::decode(&confirm_frame)?;
        let session = responder.handle_confirm(&confirm)?;
        self.register_connection(peer, link, session).await
    }

    async fn register_connection(
        &self,
        peer: NodeId,
        link: Box<dyn MeshLink>,
        session: MeshSession,
    ) -> Result<(), MeshError> {
        let path = link.path_class();
        let transport = link.transport_id();
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let (payload_tx, payload_rx) = mpsc::unbounded_channel();

        let mut core = self.core.lock().await;
        let conn_id = core.next_conn_id;
        core.next_conn_id = core.next_conn_id.saturating_add(1);
        // 1. Cap link/peer + tổng — vượt là từ chối RÕ, link bị drop (đếm).
        if let Err(e) = core.manager.admit(
            peer,
            LinkRecord {
                conn_id,
                path,
                transport,
                addr: link.peer_addr(),
                since_mono_ms: now_mono,
                last_seen_mono_ms: now_mono,
            },
        ) {
            core.stats.links_dropped_over_cap = core.stats.links_dropped_over_cap.saturating_add(1);
            return Err(e);
        }
        // 2. Graph + reputation. Nâng Attested CHỈ từ Discovered — node đang
        //    Suspect/Isolated không được một link mới nâng trust (fail-closed).
        let state = match core.graph.observe(peer, now_mono) {
            Ok(s) => s,
            Err(e) => {
                core.manager.release(&peer, conn_id);
                return Err(e);
            }
        };
        if state == NodeState::Discovered {
            // I-2 grace de-escalation: node trong probation (sau cách ly)
            // chỉ được Suspect — hết K tick sạch mới Attested.
            let to = if core.probation.contains_key(&peer) {
                NodeState::Suspect
            } else {
                NodeState::Attested
            };
            if let Err(e) = core.graph.transition(&peer, to) {
                core.manager.release(&peer, conn_id);
                return Err(e);
            }
        }
        core.reputation.on_attested(peer, now_wall);
        if let Err(e) = core.graph.link(self.self_id, peer, now_mono) {
            core.manager.release(&peer, conn_id);
            return Err(e);
        }
        core.stats.links_established = core.stats.links_established.saturating_add(1);

        // 3. Connection task sở hữu session + link — engine chỉ giữ handle.
        let task = ConnTask {
            node: self.clone(),
            peer,
            conn_id,
            path,
            session,
            link,
            payload_rx,
            faults: 0,
        };
        tokio::spawn(task.run());
        core.connections
            .entry(peer)
            .or_default()
            .push(ConnHandle { conn_id, payload_tx });
        Ok(())
    }

    async fn on_link_down(&self, peer: NodeId, conn_id: u64, reason: &MeshError) {
        let mut core = self.core.lock().await;
        let removed = core.manager.release(&peer, conn_id);
        if let Some(handles) = core.connections.get_mut(&peer) {
            handles.retain(|h| h.conn_id != conn_id);
            if handles.is_empty() {
                core.connections.remove(&peer);
            }
        }
        if removed {
            core.stats.links_closed = core.stats.links_closed.saturating_add(1);
            // Edge/node KHÔNG bị xóa — GC tick sẽ chuyển Stale/Unknown đúng
            // TTL (close condition M-1: disconnect giữa chừng không rớt graph).
            tracing::info!(reason = %reason, "liên kết mesh đóng");
        }
    }

    async fn on_gossip_event(&self, peer: NodeId, conn_id: u64, path: u64, event: NsgEvent) {
        let now_mono = self.clock.now_mono_ms();
        let now_wall = self.clock.now_wall_ms();
        let event_id = event.event_id;
        // Capture trước khi ingest di chuyển event.
        let event_kind = event.kind;
        let event_subject = event.subject;
        let mut core = self.core.lock().await;
        // Peer đã qua handshake ⇒ chắc chắn có neo; dòng này là phòng thủ.
        let Some(vk) = core.pinned.get(&peer).copied() else {
            return;
        };
        let epoch = core.epoch;
        let mut accepted = false;
        match core.inbox.ingest(peer, event, &vk, now_mono, now_wall, epoch) {
            Ok(outcome) => {
                match outcome {
                    AcceptOutcome::Accepted => {
                        accepted = true;
                        core.stats.gossip_in_accepted =
                            core.stats.gossip_in_accepted.saturating_add(1);
                        // Chỉ event ĐƯỢC NHẬN mới chiếm chỗ trong sổ đường.
                        Self::record_arrival(&mut core, event_id, path, now_mono);
                    }
                    AcceptOutcome::Duplicate => {
                        core.stats.gossip_in_duplicate =
                            core.stats.gossip_in_duplicate.saturating_add(1);
                    }
                }
                core.manager.refresh(&peer, conn_id, now_mono);
            }
            Err(_) => {
                // Inbox đã phân loại + đếm chi tiết per-peer (replay/stale/
                // crypto/flood) — engine chỉ tổng hợp cho dashboard.
                core.stats.gossip_in_rejected = core.stats.gossip_in_rejected.saturating_add(1);
            }
        }
        drop(core);
        // I-1: alert tự tố có chữ ký — chỉ hành động ở lần nhận ĐẦU TIÊN
        // (Accepted); Duplicate đã được áp dụng ở lần trước.
        if event_kind == EventKind::IsolationAlert && accepted {
            if let Some(subject) = event_subject {
                self.apply_isolation_alert(peer, subject).await;
            }
        }
    }

    /// Áp IsolationAlert từ peer (I-1): CHỈ nhận alert TỰ TỐ (subject ≡
    /// origin) — alert đòi isolate NGƯỜI KHÁC là dữ liệu quorum, không phải
    /// lệnh. Hành động theo hướng xấu nhất: Attested → Suspect → Isolated
    /// (TTL) và cắt link với subject.
    async fn apply_isolation_alert(&self, origin: NodeId, subject: NodeId) {
        if subject != origin {
            tracing::warn!(
                "IsolationAlert từ peer đòi isolate node khác — bỏ qua (chỉ quorum mới được)"
            );
            return;
        }
        let now_mono = self.clock.now_mono_ms();
        let mut core = self.core.lock().await;
        let Some(node) = core.graph.node(&subject) else { return };
        if !matches!(node.state, NodeState::Attested | NodeState::Suspect) {
            // Discovered/Isolated/Unknown: Discovered không có đường transition
            // hợp lệ (fail-closed — giữ nguyên bảng §3); Isolated = đã cách ly.
            return;
        }
        if node.state == NodeState::Attested
            && core.graph.transition(&subject, NodeState::Suspect).is_err()
        {
            return;
        }
        if core
            .graph
            .isolate_with_ttl(&subject, now_mono, self.config.isolation_ttl_ms)
            .is_ok()
        {
            core.probation.insert(subject, self.config.probation_ticks);
            drop(core);
            self.disconnect_peer(&subject).await;
            tracing::warn!("peer TỰ TỐ isolate — đã hạ Isolated (I-1)");
        }
    }

    async fn note_gossip_out(&self) {
        let mut core = self.core.lock().await;
        core.stats.gossip_out_frames = core.stats.gossip_out_frames.saturating_add(1);
    }

    async fn note_crypto_fault(&self, reason: &MeshError) {
        let mut core = self.core.lock().await;
        core.stats.crypto_faults = core.stats.crypto_faults.saturating_add(1);
        tracing::debug!(error = %reason, "frame mesh inbound lỗi mật mã");
    }

    fn record_arrival(core: &mut NodeCore, event_id: [u8; 32], path: u64, now_mono: u64) {
        if core.arrival.contains_key(&event_id) {
            return; // giữ đường ĐẦU TIÊN — event trùng lặp không đổi đường.
        }
        while core.arrival.len() >= MAX_ARRIVAL_ENTRIES {
            match core.arrival_order.pop_front() {
                Some(oldest) => {
                    core.arrival.remove(&oldest);
                }
                None => break,
            }
        }
        core.arrival.insert(event_id, ArrivalRecord { path, received_mono_ms: now_mono });
        core.arrival_order.push_back(event_id);
    }
}

/// Connection task — sở hữu duy nhất session + link của một đường. Outbound
/// xả queue TRƯỚC mỗi lượt đọc (write không bao giờ chạy song song với read,
/// nên write_all không bị hủy giữa chừng); đọc dùng idle timeout —
/// `MeshLink::read_frame` cancel-safe nên timeout không mất byte.
struct ConnTask {
    node: MeshNode,
    peer: NodeId,
    conn_id: u64,
    path: u64,
    session: MeshSession,
    link: Box<dyn MeshLink>,
    payload_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    faults: u32,
}

impl ConnTask {
    async fn run(mut self) {
        loop {
            // 1. Xả hàng đợi outbound.
            loop {
                match self.payload_rx.try_recv() {
                    Ok(payload) => {
                        let frame = match self.session.seal(FRAME_GOSSIP_EVENT, &payload) {
                            Ok(f) => f,
                            Err(e) => {
                                self.node.on_link_down(self.peer, self.conn_id, &e).await;
                                return;
                            }
                        };
                        if let Err(e) = self.link.write_frame(&frame).await {
                            self.node.on_link_down(self.peer, self.conn_id, &e).await;
                            return;
                        }
                        self.node.note_gossip_out().await;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Engine đã drop handle — node đang tắt: kết thúc sạch.
                        let reason = MeshError::LinkClosed("node đang tắt".into());
                        self.node.on_link_down(self.peer, self.conn_id, &reason).await;
                        return;
                    }
                }
            }
            // 2. Đọc một frame với idle poll — quay lại xả queue khi idle.
            let poll = Duration::from_millis(self.node.config.outbound_poll_ms);
            match timeout(poll, self.link.read_frame()).await {
                Err(_) => continue,
                Ok(Err(e)) => {
                    self.node.on_link_down(self.peer, self.conn_id, &e).await;
                    return;
                }
                Ok(Ok(frame)) => match self.session.open(&frame) {
                    Ok((FRAME_GOSSIP_EVENT, payload)) => match NsgEvent::from_wire(&payload) {
                        Ok(event) => {
                            self.node
                                .on_gossip_event(self.peer, self.conn_id, self.path, event)
                                .await
                        }
                        Err(e) => self.register_fault(e).await,
                    },
                    Ok((other, _)) => {
                        let e = MeshError::Frame(format!("frame type lạ: {other}"));
                        self.register_fault(e).await;
                    }
                    Err(e) => self.register_fault(e).await,
                },
            }
            // 3. Trần lỗi mật mã — kẻ xấu bơm frame giả liên tục bị cắt link.
            if self.faults >= self.node.config.max_crypto_faults_per_link {
                let e = MeshError::Crypto("vượt trần lỗi mật mã trên link".into());
                self.node.on_link_down(self.peer, self.conn_id, &e).await;
                return;
            }
        }
    }

    async fn register_fault(&mut self, reason: MeshError) {
        self.faults = self.faults.saturating_add(1);
        self.node.note_crypto_fault(&reason).await;
    }
}

/// Đọc mode desk trong ngữ cảnh không mutable (helper cho DecisionEntry).
async fn desk_mode(desk: &std::sync::Arc<tokio::sync::Mutex<IsolationDesk>>) -> EnforcementMode {
    desk.lock().await.mode()
}

/// Tóm tắt node id để log — chỉ 8 byte đầu, không lộ định danh đầy đủ.
fn hex_short(id: &NodeId) -> String {
    id.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
