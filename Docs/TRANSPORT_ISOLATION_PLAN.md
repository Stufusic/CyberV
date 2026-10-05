# M-PLAN — Đa giao thức & Cách ly Node (NSG-2b/4/5 cải tiến v2)

> **EN: Focused plan (owner-prioritized over P2-1b/D2) for multi-transport and
> node isolation, improving on NETWORK_SECURITY_GRAPH_PLAN.md v2. Transport
> side: a formal `MeshTransport` trait with path-class diversity feeding the
> quorum independence check, TCP-LAN first, mDNS second, WiFi-Direct via the
> single justified C++ shim, BLE as discovery-only. Isolation side: a
> THREE-STEP ladder — self-isolation (live now), operator-approved isolation
> via UI (NEW — human-in-the-loop, does NOT break the freeze gate), and
> auto-pilot (still gated on freeze gate + D2.3 + wrong-action rate) — plus a
> real WFP enforcement module, isolation evidence packs, grace
> de-escalation, and a mesh-sim isolation simulator.**
>
> Vị trí: cụ thể hóa NSG-2b/NSG-4/NSG-5 trong `NETWORK_SECURITY_GRAPH_PLAN.md`
> v2. Mọi thứ đã có (session AEAD, GossipInbox, ShadowLedger, QuorumEngine,
> MeshGraph, WFP semantics §9, tier A/B/C §10) được TÁI DỤNG — không viết lại.

---

## 0. Tái dụng từ những gì đã commit

| Đã có | Dùng cho |
|---|---|
| `mesh/session.rs` MeshSession (AEAD 2 chiều, replay window) | Phiên trên MỌI transport — session không phụ thuộc transport |
| `mesh/session.rs` mesh handshake 3 bước mutual | Bắt tay giữa peer mesh (KHÔNG dùng pipe 2 bước một chiều) |
| `mesh/discovery.rs` beacon codec | Payload quảng bá mDNS/BLE |
| `mesh/gossip.rs` GossipInbox | Điểm nhập mọi frame từ mọi transport |
| `mesh/shadow.rs` + `mesh/quorum.rs` | Đề nghị isolate + chứng minh quorum |
| `mesh/graph.rs` state machine | Isolated/Suspect/Attested + TTL |
| Plan §9 WFP semantics | Spec thực thi (TTL tuyệt đối, reconcile, break-glass) |

---

## 1. Transport Layer v2 — cải tiến so với v1

### 1.1 `MeshTransport` trait (formal hóa — v1 chỉ mô tả tier)

```rust
pub enum TransportId { TcpLan = 1, WiFiDirect = 2, Ble = 3, Rendezvous = 4 }

pub trait MeshTransport: Send {
    fn id(&self) -> TransportId;
    fn advertise(&mut self, beacon: &MeshBeacon) -> Result<(), MeshError>;   // bắt đầu quảng bá
    fn browse(&mut self) -> Vec<(MeshBeacon, Endpoint)>;                      // quét peer
    fn connect(&mut self, ep: Endpoint) -> Result<Box<dyn MeshLink>, MeshError>;
    fn listen(&mut self) -> Result<Box<dyn MeshLink>, MeshError>;             // accept inbound
}

pub trait MeshLink: Send {
    fn read_frame(&mut self) -> impl Future<Output = Result<Vec<u8>, MeshError>>;
    fn write_frame(&mut self, frame: &[u8]) -> impl Future<Output = Result<(), MeshError>>;
    fn path_class(&self) -> u64;   // thấy §1.2
}
```

- AEAD session + mesh handshake chạy **TRÊN** link — transport không biết gì
  về mật mã (đã đúng thiết kế, giờ formal hóa thành code).
- `TransportManager`: nhiều link cùng peer, cap link/peer (bound INV-015),
  failover Tier A → B, dedupe peer đã attest.

### 1.2 PathClass — cải tiến MỚI cho quorum independence

v1 dùng `arrival_path: u64` tự do. v2 chuẩn hóa: **`path_class = hash(transport_id,
subnet_scope)`** — hai vote đến qua cùng transport + cùng segment mạng bị coi
là CÙNG đường (điều kiện 5 đánh giá thật thay vì "đường khác nhau trên giấy").
Test chéo: 2 vote cùng path_class đếm 1; khác path_class + 4 điều kiện khác →
độc lập.

### 1.3 Phân cấp giữ nguyên (§10)

Tier A = TCP-LAN (production) · Tier B = WiFi Direct (flag tắt mặc định) ·
Tier C = BLE beacon (discovery only, zero trust).

---

## 2. M-1 — Transport trait + TCP-LAN (làm đầu tiên)

- `mesh/transport/{mod,tcp}.rs`: tokio TCP listener + connector; frame =
  wire format của session (length-prefixed AEAD) — truyền thẳng qua link.
- Tích hợp: link inbound/outbound → handshake mesh 3 bước → GossipInbox.
- **Close:** 2 process thật trên 1 máy (loopback) và 2 máy LAN thật trao đổi
  gossip qua TCP; disconnect giữa chừng → edge stale, không rớt graph.

## 3. M-2 — mDNS discovery (NSG-2b)

- Crate `mdns-sd` (pure-Rust) — qua cargo-deny/machete + rationale §Phụ lục B
  (một dependency duy nhất của M-series).
- Advertise beacon qua mDNS TXT/SRV; browse → node ở `Discovered`; TCP connect
  sau khi chọn peer. Mất mDNS không rớt link hiện có (offline-first).
- **Close:** 2 máy LAN tự tìm thấy nhau và attest thành công không cấu hình tay.

## 4. M-3 — WiFi Direct Tier B qua C++ shim (theo HYBRID §1.1a)

- Shim C++20 duy nhất được phép: WinRT `WiFiDirectAdvertisementPublisher` /
  `WiFiDirectDevice` — chỉ transliterate API, logic Rust; build qua build.rs;
  biên giới extern-C + test biên giới.
- Config flag tắt mặc định; không tính trust weight cho tới fault-injection
  (ngắt carrier giữa handshake) đạt.
- **Close:** 2 máy bắt tay qua WiFi-Direct + fault test ngắt carrier recover đúng.

## 5. M-4 — BLE beacon Tier C

- BLE advertisement chứa beacon codec (nén ≤ 26 byte dữ liệu hữu ích) —
  **không bao giờ mang frame trust**; presence BLE không nâng NodeState (test
  chứng minh: beacon BLE received → NodeState vẫn Discovered).
- Thư viện quyết định tại lúc làm (btleplug vs Win32 BLE) — qua deny/machete.

---

## 6. Isolation Engine v2 — cải tiến cốt lõi

### 6.1 Thang 3 bước I-1/I-2/I-3 (cải tiến ĐÁNG KỂ so v1)

v1 để toàn bộ NSG-4 sau freeze gate. v2 **tách bậc người-dùng-duyệt**:

| Bậc | Hành vi | Điều kiện mở |
|---|---|---|
| **I-1 Self-isolation** | Node tự hạ Isolated khi tự phát hiện tamper; peer-alert | Đã có thiết kế NSG-3 — bật ngay khi có transport |
| **I-2 Operator-approved** (MỚI) | Quorum đạt → shadow entry → **UI hiện đề nghị cách ly + SuspectRank đầy đủ provenance → người dùng bấm duyệt** → thực thi WFP thật | KHÔNG phá freeze gate: quyết định cuối là con người (đúng bậc "thủ công trước" của roadmap §3.3 L4); mọi action ghi MMR |
| **I-3 Auto-pilot** | Quorum → isolate không cần duyệt | Freeze gate Trụ 1 + D2.3 + wrong-action rate đạt ngưỡng benign set (giữ nguyên gate v2) |

### 6.2 WFP Enforcement module thật — `mesh/wfp.rs`

- windows-sys feature `Win32_NetworkManagement_WindowsFilteringPlatform`:
  `FwpmEngineOpen` → `FwpmFilterAdd` (block per-IP/port peer) → TTL →
  `FwpmFilterDelete` — đúng semantics §9: rule marker `CyberV-NSG-<subject8>`,
  deadline TTL tuyệt đối, **startup reconcile** dọn rule mồ côi, cleanup
  idempotent, không chạm loopback/IPC.
- **Fallback trung thực:** không mở được engine (thiếu quyền) → isolation
  logic-only (graph + ngừng gossip + báo `is_verified: false` cho UI), không
  giả vờ đã chặn mạng.

### 6.3 Cải tiến bổ sung

- **Isolation evidence pack:** mọi isolate gắn evidence_root + decision trace
  vào MMR; gỡ/isolation hết hạn gắn recovery-ref — audit hai chiều.
- **Grace de-escalation:** hết TTL + re-attest thành công → `Suspect` (không
  nhảy thẳng `Attested`), theo dõi K tick sạch mới lên `Attested` — giảm
  ping-pong isolate/un-isolate.
- **mesh-sim isolation simulator:** mở rộng `sim.rs` — mô phỏng isolate/
  recover/reconcile 256 node + partition (đo trước khi đụng WFP thật).

### 6.4 Đường UI (I-2 console)

- Dashboard thêm trang **Isolation Inbox**: shadow entries Pending + SuspectRank
  (§7.2 format) + 2 nút `Duyệt cách ly` / `Gỡ nghi` (UAC + ghi lý do + MMR).
- UI gửi lệnh qua phiên AEAD hiện có (lệnh mới `IsolationDecision` — schema
  bounded, thêm vào `IpcCommand`).

---

## 7. Lộ trình M/I với close conditions

| Phase | Scope | Close condition |
|---|---|---|
| **M-1** | Transport trait + TCP-LAN + path_class | 2 process trao đổi gossip qua TCP; 2 vote cùng path_class đếm 1 |
| **M-2** | mDNS + wire GossipInbox | 2 máy LAN tự discovery + attest, không cấu hình tay |
| **I-1** | Self-isolation bật | Test: tamper signal → self-isolate → peer alert qua gossip |
| **I-2** | WFP module + UI Isolation Inbox + evidence pack | Test admin: rule WFP thêm/xóa thật, reboot reconcile; benign set KHÔNG sinh đề nghị |
| **M-3** | WiFi Direct shim | 2 máy bắt tay WFD + fault ngắt carrier recover |
| **M-4** | BLE beacon | BLE presence không đổi NodeState (test) |
| **I-3** | Auto-pilot | freeze gate + D2.3 + wrong-action rate ~0 trên benign set |

Thứ tự gợi ý: M-1 → M-2 → I-1 → I-2 (nhóm nhỏ ra được "cách ly có người
duyệt" sớm nhất mà an toàn) → M-3 → M-4 → I-3.

## 8. Dependency + rủi ro

| Hạng mục | Ghi chú |
|---|---|
| `mdns-sd` (M-2) | Qua cargo-deny/machete + rationale Phụ lục B (một crate duy nhất mới) |
| WFP (I-2) | Cần admin để thêm rule — UI isolate chạy elevated (UAC); logic-only fallback khi không có quyền |
| C++ shim (M-3) | Duy nhất được phép theo HYBRID §1.1a; build.rs; không Boost |
| Đa transport đồng thời | Cap link/peer + flood-limit per-peer đã có trong GossipInbox — mở rộng key thành (peer, transport) |

## 9. Ranh giới trung thực

- Đa giao thức và I-2 KHÔNG tăng assurance: vẫn không AV, không firewall biên;
  cách ly chỉ chặn traffic giữa node CyberV với peer bị tố, không phải firewall
  toàn hệ thống.
- Auto-pilot (I-3) vẫn bị chặn bởi freeze gate — plan này KHÔNG mở nó sớm.

---

## 10. Trạng thái triển khai (cập nhật 2026-10-05)

> **EN: Implementation status after the first M-PLAN execution pass — what is
> wired, test provenance per phase, and what remains (M-3/M-4/I-3).**

| Phase | Trạng thái | Code | Test chứng minh |
|---|---|---|---|
| **M-1** Transport trait + TCP-LAN + path_class | ✅ Đã wire | `mesh/transport/{mod,tcp}.rs`, `mesh/node.rs` | `mesh_transport_tests.rs`: 2 node trao đổi gossip qua TCP loopback thật; 2 vote cùng path_class đếm 1 (tầng quorum + tầng engine); disconnect → edge Stale, node không rớt graph; frame hỏng AEAD đếm fault, link sống dưới trần; peer chưa pin bị từ chối; cap link/peer từ chối rõ ràng |
| **M-2** mDNS discovery | ✅ Đã wire | `mesh/transport/mdns.rs` (mdns-sd 0.21 — rationale Phụ lục B plan NSG) | `mesh_mdns_tests.rs`: 2 node TỰ tìm thấy + attest không cấu hình tay; beacon lệch node_id ≠ vk bị từ chối + đếm |
| **I-1** Self-isolation | ✅ Đã wire | `EventKind::IsolationAlert`, `MeshNode::self_isolate` | `mesh_isolation_tests.rs`: tamper → tự isolate → alert ký → peer hạ Isolated + cắt link; alert mượn tên đòi isolate người khác bị bỏ qua; hết TTL mở lại inbound (INV-014) |
| **I-2** WFP + Isolation Desk + UI Inbox | ✅ Đã wire (chờ verify admin thật) | `mesh/wfp.rs`, `mesh/isolation.rs`, IPC `IsolationInbox`/`IsolationDecision`, UI `isolation_page.py` | `mesh_isolation_desk_tests.rs`: quorum 2 đường thật (loopback + LAN) → đề nghị → operator duyệt → thực thi (loopback → LogicOnly trung thực) → probation Suspect → 3 tick sạch → Attested; unit test WFP marker/deadline + AccessDenied mapping; test admin block/unblock/sweep để `#[ignore]` — chạy tay khi elevated |
| **mesh-sim** isolation simulator | ✅ Đã wire | `mesh/sim.rs::run_isolation_sim` | 256 node + partition/merge + quorum/decide/isolate/TTL-lift; bất biến: isolations == lifts (không isolation vĩnh viễn, INV-014) |
| **M-3** WiFi Direct shim | ⏳ Chưa làm | — | Close: 2 máy bắt tay WFD + fault ngắt carrier recover |
| **M-4** BLE beacon | ⏳ Chưa làm | — | Close: BLE presence không đổi NodeState |
| **I-3** Auto-pilot | ⛔ CHỦ Ý KHÔNG MỞ | — | Freeze gate Trụ 1 + D2.3 + wrong-action rate benign set — giữ nguyên gate v2 |

Ghi chú trung thực bổ sung khi triển khai:

- **path_class dùng scope/24 IPv4 (loopback gộp một scope)** — hệ quả chủ ý:
  mesh phẳng MỘT subnet + MỘT transport không tự đủ quorum (2 vote cùng
  segment đếm 1). Quorum cần đa dạng đường (khác transport hoặc khác segment)
  — test I-2 dùng loopback + LAN IP thật để tạo hai đường.
- **Pin neo từ beacon là first-contact (TOFU)**: NodeId ≡ vk theo thiết kế
  nên beacon giả tạo được node mới nhưng KHÔNG thể mạo danh node có sẵn;
  node mới bị cap cold-start (weight thấp) — quorum vẫn chặn. Enrollment
  thủ công vẫn là đường mạnh hơn.
- **WFP loopback guard**: rule không bao giờ thêm cho loopback (plan §9) —
  approve isolation trên peer loopback trả `LOGIC_ONLY` trung thực thay vì
  giả vờ chặn.
- **ShadowLedger giữ bất biến `executed == false` vĩnh viễn** — quyết định
  thực thi của operator nằm ở `DecisionLog` (bounded 256, evidence refs =
  event_id phiếu), không đụng sổ shadow.
