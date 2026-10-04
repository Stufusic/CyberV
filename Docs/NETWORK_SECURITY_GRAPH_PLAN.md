# CyberV — Kế hoạch NSG v2 (Network Security Graph — Mạng đồ thị an ninh)

> **CẬP NHẬT 2026-10-04 (b):** **NSG-0…NSG-1.6 đã HIỆN THỰC** (pure logic) —
> module `agent/src/mesh/` (graph/events/reputation/quorum/consistency) +
> 81 test (49 unit + 32 integration) xanh, clippy `-D warnings` sạch.
> Phụ lục A ghi wire format đã chốt theo code. Các phase NSG-2+ vẫn ❌ planned
> (đợi P1-1 AEAD + freeze gate).
>
> **EN: Development plan v2 for the CyberV mesh feature ("Network Security
> Graph"), revised after an owner review (2026-10-04). v2 adds: a quantified
> Trust/Reputation model, a diversity-aware Quorum Independence model
> (replacing count-based ≥2 quorum), an NSG Event Model with epochs and a
> partition/merge consistency protocol (its own milestone), a local-attacker
> model, a Recovery Safety Model ("signed ≠ safe"), WFP isolation operational
> semantics, transport tiering A/B/C, a performance benchmark framework, and
> threats T10–T12. Status: NSG-0…1.6 (pure logic) IMPLEMENTED with tests;
> NSG-2+ remain gated on P1-1 AEAD and the Pillar-1 freeze gate.**
>
> Ý tưởng gốc (chủ dự án): các máy tính cùng cài CyberV liên kết với nhau qua
> nhiều giao thức (LAN, WiFi, Bluetooth, …) thành **mạng lưới bảo vệ lẫn
> nhau**. Khi một node bị phát hiện tấn công → **cách ly node đó**, đồng loạt
> **tương quan truy nguồn**, và hệ thống có khả năng **tự vá** khi ứng dụng
> bị hỏng.
>
> v2 thay thế hoàn toàn v1 (cùng file, xem §0 changelog).

---

## 0. Changelog v1 → v2 (từ phản biện chủ dự án)

| # | Thay đổi | Lý do |
|---|---|---|
| 1 | Quorum "≥2 node" → **Quorum Independence Model** có trọng số, đánh giá độc lập theo cặp (§5) | 2 node khác nhau ≠ 2 nguồn độc lập; Attested ≠ honest |
| 2 | Thêm **Trust & Reputation Model** 5 chiều + cold-start cap (§4) | Node mới enroll không được ngang quyền node có lịch sử; Sybil phải thành cơ chế định lượng |
| 3 | Thêm **NSG Event Model** (event_id/epoch/causal_parent…) + **Epoch/Partition-Merge protocol** (§6) | Gossip thiếu consistency model sẽ vỡ khi mesh lớn; split-brain cần milestone riêng |
| 4 | Thêm **Local Attacker Model** (T12) | Malware admin trên chính node là threat cấp cao của endpoint security |
| 5 | Thêm **Recovery Safety Model** — "signed ≠ safe" (§7.3) | Update hợp lệ về mật mã vẫn có thể độc hại nếu authority bị chiếm |
| 6 | Thêm T10 Resource exhaustion, T11 State explosion (§8) + INV-015 | Threat model thiếu lớp tài nguyên |
| 7 | Đổi tên "truy tìm thủ phạm" → **Incident Correlation & Suspect Ranking**, chốt output format (§7.2) | Tránh overclaim attribution |
| 8 | Đặc tả vận hành **WFP isolation** (§9) | "Reversible trên giấy" ≠ reversible an toàn khi vận hành |
| 9 | Transport phân **Tier A/B/C** (§10) | Multi-transport không được kéo chậm core |
| 10 | Thêm **Benchmark framework** (§11) + NSG-3.5, NSG-7, NSG-8 | Test đúng/sai chưa đủ — cần số liệu |
| 11 | Roadmap mở rộng **NSG-0…NSG-8**, thêm NSG-1.5/1.6/3.5 (§13) | Hai lớp Trust/Independence và Epoch/Consistency là bắt buộc trước code mạng |
| 12 | INV-013 viết lại (diversity-aware), INV-014 mở rộng WFP, thêm INV-015 (§14) | Bất biến phải phản ánh mô hình mới |

---

## 1. Định vị trong kiến trúc hiện có

NSG là tầng phủ **phân tán** trên nền tảng đã có. Tái dụng (không viết lại):

| Thành phần hiện có | Vai trò trong NSG | Trạng thái thật |
|---|---|---|
| `identity` (Ed25519 + DPAPI vault) | Danh tính node; khóa node = khóa device đã enroll | ✅ |
| `protocol` (length-prefixed + domain separator) | Mẫu wire format cho mọi frame mesh | ✅ |
| `defense::passive::isolation` (frame MAC, session cap) | Mẫu xác thực phiên + anti-replay | ✅ |
| P1-1 AEAD (X25519 + ChaCha20-Poly1305) | Mã hóa phiên mesh — **một primitive, hai nơi dùng** | ❌ planned |
| `evidence` (Merkle tree, evidence graph) | Evidence pack đính kèm incident report | ✅ merkle; ⚠️ topology |
| `defense::passive::update` + `update/authority.rs` + `cyberv-keygen` | Kênh **tự vá** duy nhất được phép (INV-005) | ✅ gate; ❌ feed (M1) |
| `transparency` (MMR + revocation) | Thu hồi node bị chiếm; anti rogue-admin; **recovery audit** | ✅ |
| `privacy::SelectiveDisclosureEngine` | Chia sẻ evidence chọn lọc giữa node | ⚠️ signed-claim |
| `defense` Response Ladder v2 (L0→L4, shadow mode) | Bậc hành động; cách ly node = L4 | 📐 thiết kế, chưa code |
| `daemon_runner` tick loop | Vòng heartbeat/gossip mesh chạy trong tick hiện tại | ✅ |
| Supabase (`functions/*`, migrations) | Rendezvous/introducer + kho incident; **tùy chọn** | ✅ |
| `dashboard` (Vite fleet view) | Trực quan hóa đồ thị + incident + observability | ✅ khung |

**Ranh giới không đổi**: không AV, không SIEM, không firewall biên.
"Truy tìm thủ phạm" = **Incident Correlation & Suspect Ranking** (§7.2) —
tương quan chỉ báo có bằng chứng, không phải quy kết.

**Nguyên tắc ưu tiên không đổi:** Correctness > Evidence > Reliability >
Detection > Prevention > Automation > Coverage. NSG-0…NSG-1.6 là pure
logic/tài liệu (làm được ngay); NSG-4+ **bị chặn** bởi freeze gate Trụ 1 +
D2.3 response ladder.

---

## 2. Năm quyết định thiết kế cốt lõi

### 2.1 Corroboration — và v2 là **independence-aware**, không phải đếm node

- **Tự cách ly (self-isolation):** node phát hiện chính mình bất thường → tự hạ
  xuống Isolated **ngay**, không cần quorum (fail-closed đúng đắn).
- **Cách ly node khác (peer-quarantine):** v2 thay "≥2 node" bằng quorum có
  trọng số + kiểm tra độc lập theo cặp — **tổng trọng số tin cậy của các vote
  độc lập theo cặp ≥ ngưỡng, ≥1 vote mang tín hiệu `verified`, cùng epoch**
  (đặc tả đầy đủ §4-§5). Hai vote cùng trích một evidence root không đếm kép.
- Report đơn lẻ **không bao giờ** thành hành động — chỉ L0 + cập nhật reputation.
- Shadow mode mặc định trước mọi mức tự động (rollout 5 bước roadmap v2).

### 2.2 Cloud không phải trust anchor

Supabase chỉ làm introducer + kho incident. Trust là peer-to-peer signed —
phá máy chủ không chiếm được mesh, chỉ mất khả năng giới thiệu node mới.
LAN-local phải vận hành trọn vẹn UC-1/UC-2.

### 2.3 Honest-state mở rộng cho mesh (INV-007)

`Discovered ≠ Attested`: transport chỉ là đường physical, không nâng trust.
Probe nào không chạy được → `is_verified: false` và **observation weight của
node đó thấp tương ứng** (§4) — honest-state không chỉ là nhãn, nó vào thẳng
công thức quorum.

### 2.4 Safety over liveness (mới — áp cho mọi xung đột)

Khi hai nguồn thông tin mâu thuẫn không phân giải được (conflicting reports,
partition merge, epoch transition), mesh **chuyển sang trạng thái hạn chế hơn
tạm thời** (Suspect / QuorumUnavailable), không bao giờ tự chọn nhánh "tin
cậy hơn" cho nhanh. Hành động chỉ tiếp tục khi corroboration đạt lại.

### 2.5 Signed ≠ safe (mới — áp cho update/healing)

Chữ ký Ed25519 hợp lệ chứng minh **nguồn gốc**, không chứng minh **an toàn**.
Authority key bị chiếm → update độc hại vẫn verify pass. Biện pháp ở §7.3
(Recovery Safety Model): custody 2-of-3, staged rollout, rate limit, audit
MMR, emergency revoke — và ghi nhận **residual risk** trung thực trong
THREAT_MODEL.

---

## 3. Mô hình dữ liệu + layout module

Module mới: `agent/src/mesh/` (tầng ngang như `evidence`):

```text
mesh/
  graph.rs        — NodeId, MeshNode, NodeState, MeshEdge; MeshGraph (bounded)
  events.rs       — NSG Event Model (§6): event_id, origin_seq, epoch, causal_parent
  reputation.rs   — TrustScore 5 chiều (§4), cold-start cap, decay/restore
  quorum.rs       — Independence check theo cặp + weighted quorum (§5)
  consistency.rs  — Epoch, partition detect, merge reconcile (§6.2)
  gossip.rs       — GossipFrame, anti-replay, flood-limit, dedupe
  session.rs      — handshake + AEAD (tái dụng P1-1 primitive khi có)
  discovery/      — lan_mdns.rs, wifi_direct.rs, bt_beacon.rs
  quarantine.rs   — ShadowLedger, IsolationAction + TTL, WFP semantics (§9)
  healing.rs      — self-integrity, repair orchestrator, peer watchdog (§7.3)
  config.rs       — MeshConfig (enabled=false, shadow=true mặc định)
bin/mesh-sim      — harness mô phỏng 10–256 node cho benchmark/adversarial (§11)
```

Trạng thái node (fail-closed, một chiều trừ recovery có chữ ký):

```text
Unknown ──handshake ký thật──▶ Attested ──telemetry xấu + quorum──▶ Suspect
Suspect ──quorum đủ──────────▶ Isolated (TTL) ──recovery ký authority──▶ Attested
Attested ──offline quá TTL edge──▶ Unknown
Mọi trạng thái ──mất quorum khả dụng / xung đột──▶ QuorumUnavailable (giới hạn hành động)
```

`NodeId` = `device_id` canonical hiện có. `MeshGraph` bound cứng 256 node /
2048 edge — vượt → từ chối node mới, đếm loss, không âm thầm (tinh thần
INV-010; cơ chế trong INV-015).

---

## 4. Trust & Reputation Model (mới — P0.2)

Mỗi node có **TrustScore** gồm 5 chiều độc lập, mỗi chiều 0.0–1.0. Quorum
không đếm vote — nó **cộng trọng số** `W_i = f(I,O,E,B,H)` của từng vote
(§5).

| Chiều | Ý nghĩa | Tăng khi | Giảm khi | Nguồn dữ liệu |
|---|---|---|---|---|
| **I — Identity Trust** | Chất lượng danh tính | Attestation sạch, enroll tuổi ≥ ngưỡng, key rotation đúng chu kỳ | Challenge fail, key mới xoay đột ngột, gần revocation | handshake + `verify-state` |
| **O — Observation Trust** | Chất lượng telemetry node phát | Probe thật (`is_verified: true`), signal_class được ghi | Probe stub/fail-closed, thiếu provenance | INV-007 honest-state của chính node |
| **E — Evidence Trust** | Độ tin cậy bằng chứng node nộp | evidence_ref verify khớp Merkle root khi kiểm chéo | Ref sai/hash không khớp, evidence trùng lặp | `evidence::merkle` kiểm khi gossip |
| **B — Behavior Trust** | Lịch sử báo cáo | Report dẫn tới xác nhận đúng (corroborated) | Report dẫn tới wrong-action (đo qua shadow ledger) | `quarantine.rs` ledger |
| **H — Historical Reliability** | Ổn định vận hành | Heartbeat đều, vote nhất quán qua nhiều epoch | Bật/tắt thất thường, vote lật kèo theo đám đông | gossip history |

**Quy tắc kết hợp (fail-closed):** `W = min-cap(I, O, E, B, H) × Σ w_k·k_k` —
tức **chiều nào Unknown/không đo được thì trần trọng số bị ghim thấp**, không
có chiều nào "được miễn" vì chiều khác cao. Giá trị trọng số hệ số nằm trong
**mesh policy có chữ ký authority** (tái dụng kênh INV-011 — không hardcode).

**Cold-start cap (chống Sybil bằng kinh tế học, không chỉ mitigation mô tả):**
node mới enroll bị ghim `W ≤ W_new` (tham số policy, vd 0.25) cho tới khi đạt
`K` ngày tuổi **và** `M` observation có provenance **và** chưa từng wrong-action.
Một bầy Sybil enroll hàng loạt do đó **không đủ tổng trọng số** để tự tạo
quorum giả — chi phí mỗi Sybil là thời gian + hành vi sạch kéo dài.

**Decay/restore:** wrong-action giảm B theo bậc; phục hồi phải qua chu kỳ
benign sạch quan sát được (không reset thủ công trừ khi authority ký).

---

## 5. Quorum Independence Model (mới — P0.1, lỗ hổng lớn nhất của v1)

**Phát biểu vấn đề:** hai vote từ hai node khác nhau vẫn có thể là **một nguồn
thật sự** (cùng bị compromise, cùng đọc một IOC poisoned, cùng một MITM relay).
Quorum v2 kiểm tra độc lập **theo cặp** trước khi cộng trọng số.

Hai vote (i, j) chỉ được coi **độc lập** khi **toàn bộ** các điều kiện sau giữ:

| # | Điều kiện | Kiểm tra thế nào |
|---|---|---|
| 1 | **Distinct identity** | `origin_id` khác nhau (điều kiện hiển nhiên, KHÔNG đủ) |
| 2 | **Distinct observation channel** | Tín hiệu gốc đến từ nguồn probe khác loại (vd ETW-based vs filesystem-ACL-based) — hai vote cùng một probe type trên hai máy chỉ tính một kênh |
| 3 | **Distinct evidence root** | `evidence_root` của hai vote khác nhau; cùng trích một root → đếm **một lần** (dedupe theo evidence, không theo node) |
| 4 | **Causal separation** | Đường `causal_parent` DAG của i không chứa j (và ngược lại) — một vote dẫn xuất từ report của node kia không tự cộng thêm |
| 5 | **Network path separation** | Vote nhận qua session/transport path khác nhau (chống một MITM relay cả hai); cùng một peer relay hai vote → vote thứ hai chỉ tính khi có chữ ký gốc độc lập xác minh được |

**Công thức quyết định (thay "quorum ≥ 2"):**

```text
quorum_score = Σ W_i  với {i} là tập vote pairwise-independent, cùng epoch, chưa hết hạn
điều kiện ALL:
  (a) quorum_score ≥ Q_threshold            (ngưỡng trong signed policy)
  (b) |{i}| ≥ 2
  (c) ∃ i: signal_class(i) == verified      (probe-based, không phải heuristic)
  (d) mọi cặp đều pass 5 điều kiện độc lập trên
  (e) không có vote nào từ peer đã revoke (transparency list) hoặc hết hạn
```

**Chống collusion:** report dẫn tới wrong-action → B giảm (vote yếu đi), quan
sát qua shadow ledger; lịch sử vote nằm trên MMR append-only (truy vết được);
authority revoke được node chiếm; epoch-stamp chặn vote cũ lượm lại (§6).
**Trung thực:** collusion hoàn hảo giữa hai node đã attest đủ lâu là **giảm
rủi ro chứ không triệt tiêu** — residual risk vào THREAT_MODEL, và đó là lý
do auto-mode luôn có đường human review + audit (roadmap v2 §3.3).

---

## 6. Event & Consistency Model (mới — P0.3) + Epoch/Partition-Merge

### 6.1 NSG Event Model — mọi sự kiện mesh là một bản ghi bất biến

```text
struct NsgEvent {
    event_id:        [u8; 32],  // hash nội dung (dedupe tự nhiên)
    origin_id:       NodeId,    // ai tạo
    origin_seq:      u64,       // monotonic per-origin — thứ tự toàn phần theo nguồn
    epoch:           u64,       // epoch mesh tại thời điểm tạo
    causal_parent:   Vec<event_id>, // DAG — sự kiện này dẫn xuất từ đâu
    evidence_root:   [u8; 32],  // merkle root của evidence pack (nếu có)
    created_mono + created_wall, // nguồn monotonic + grace window ký (roadmap §4)
    expiry:          deadline,  // sau mốc này chỉ còn giá trị điều tra
    kind:            Report|Vote|Heartbeat|EpochMarker|Recovery,
    signature:       Ed25519(origin identity key),
}
```

**Quy tắc xử lý (đặc tả đủ để code, không để "xuống phase sau"):**

| Tình huống | Quy tắc |
|---|---|
| **Ordering** | Thứ tự toàn phần **per-origin** theo `origin_seq`; giữa các origin chỉ partial order qua `causal_parent`. Không yêu cầu total order toàn mạng (eventual consistency) |
| **Duplicate event** | Dedupe theo `event_id` — idempotent nhận lại |
| **Duplicate evidence** | Nhiều vote cùng `evidence_root` → đếm evidence **một lần** trong quorum (điều kiện 3, §5) |
| **Conflicting reports** (A nói X xấu, C nói X lành) | Giữ cả hai; quorum engine xem là hai claim set riêng; phân giải theo (1) completeness evidence, (2) verified > heuristic, (3) không phân giải được → **QuorumUnavailable + human review**, không tự chọn (§2.4) |
| **Stale event** | `expiry` quá → drop **đếm được**; `epoch` cũ hơn epoch hiện tại → stale vote, không đếm |
| **Revoked peer vote** | Check revocation (transparency) trước khi cộng trọng số — vote của node bị revoke = 0 |
| **Partition merge** | §6.2 |
| **Epoch transition** | Event mang epoch cũ hơn epoch hiện hành bị bỏ qua cho quyết định (vẫn giữ điều tra); EpochMarker được ký bởi tập node chuyển tiếp (§6.2) |

### 6.2 Epoch & Partition/Merge Protocol (milestone riêng NSG-1.6)

```text
SteadyState ──mất kết nối đa số neighbor quá K heartbeat──▶ DegradedEpoch(e+1)
DegradedEpoch ──hội tụ lại, reconcile xong──▶ SteadyEpoch(e+2)
```

- **Partition detection:** connectivity graph rơi dưới ngưỡng (mất đa số
  neighbor đã attest) → node **tăng epoch cục bộ** và phát `EpochMarker` ký
  kèm membership view hash. Không hành động peer-quarantine mới ngoài quorum
  **trong chính view đó** (tránh "mạng lẻ tự phong cấp").
- **Trong DegradedEpoch:** self-isolation vẫn hoạt động đầy đủ (không phụ thuộc
  mạng); peer-quarantine chỉ được đề nghị ở trạng thái **provisional** — TTL
  tối đa bị ghim ngắn hơn, đánh dấu rõ, đợi merge xác nhận.
- **Merge protocol:** hai view gặp nhau → trao epoch + membership hash +
  phần cuối của MMR:
  1. Epoch cao hơn thắng làm **epoch hiện hành** (epoch là số, không tranh cãi).
  2. Đối chiếu quarantine decisions của hai bên: (a) cùng isolate X → giữ,
     tính lại TTL từ merge; (b) một bên isolate X, bên kia attest X → X về
     **Suspect** (không auto-trust, không auto-isolate), chạy lại corroboration
     với dữ liệu hợp nhất (§2.4 safety over liveness); (c) thiếu thông tin →
     QuorumUnavailable.
  3. Vote/event stale-epoch bị loại; log hai phía giữ nguyên trên MMR (truy
     vết hậu kỳ, không xóa sử).
- **QuorumUnavailable** là trạng thái **hiển thị** ở GetStatus — mesh không
  hành động nhưng **local defense tiếp tục bình thường** (độc lập lỗi giữa các
  năng lực — roadmap §1.1).

---

## 7. Ba luồng nghiệp vụ

### 7.1 UC-1 — Liên kết máy (discovery → trust edge)

1. **Quảng bá:** mDNS `_cyberv._tcp` (LAN) / rendezvous Supabase (ngoài LAN).
   Beacon chỉ chứa `device_id` + public key.
2. **Bắt tay 3 bước** (mẫu P1-1): `Hello` → `HelloAck(sig identity + PK_ephemeral)`
   → `Finish(AEAD)`; frame có sequence + nonce window (mẫu `isolation::protocol`).
3. **Mutual attestation:** chứng minh danh tính bằng khóa đã enroll; không attest
   được → `Discovered`, không nhận evidence, không vote.
4. Ghi edge + tick heartbeat trong `daemon_runner`. TrustScore của node bắt đầu
   tích lũy từ đây (cold-start cap §4).

### 7.2 UC-2 — Node bị tấn công → cách ly + Incident Correlation

> Đổi tên chính thức: **không dùng "hunting attacker"** trong module/UI —
> dùng **Incident Correlation & Suspect Ranking**. Output không bao giờ là
> "Process X = 92% attacker".

1. Node B detect bất thường cục bộ (defense pipeline) → **tự cách ly** nếu
   chính B bị tamper; phát `NsgEvent{kind: Report}` — chỉ indicator
   (path/signer/lineage/hash hành vi) + `evidence_root`, không dump telemetry.
2. Các node nhận report → **IOC sweep** trên telemetry cục bộ → match → phát
   `Vote` (có provenance + signal class riêng của chính nó).
3. `quorum.rs` tính quorum theo §5 (pairwise independence + weighted + epoch).
   Đủ → đề nghị `Isolate(nodeId, TTL)` — shadow ghi quyết định; pilot thực thi
   WFP semantics §9.
4. **Suspect Ranking output — format bắt buộc:**

```text
SuspectRank {
  subject:                  process path / signer / lineage (đã cam kết SHA-512),
  confidence:               0..100 (tính từ trọng số vote, không phải "% attacker"),
  evidence_count:           số evidence pack liên quan,
  independent_sources:      số nguồn độc lập thực sự sau §5 (≤ evidence_count),
  signal_classes:           [verified|heuristic] của từng nguồn,
  false_positive_indicators:[dấu hiệu cảnh báo report có thể nhầm],
  trace:                    event_id chain (audit MMR)
}
```

Ranking là **chỉ báo điều tra có provenance** — L2 kill vẫn theo response
ladder hiện có, không tự kill từ ranking.

### 7.3 UC-3 — Tự vá + Recovery Safety Model (mới — P0.5)

Phát hiện/vá như v1 (bảng corrupt → kênh update ký, two-phase commit, vault →
re-enroll). v2 bổ sung **Recovery Safety Model** — vì **signed ≠ safe** (§2.5):

| Rủi ro recovery | Biện pháp bắt buộc |
|---|---|
| Downgrade / rollback attack | Version policy monotonic hiện có + (khi P2-1 xong) neo TPM counter thật; trước đó báo trung thực version-check là software-level |
| **Malicious-but-valid update** (authority bị chiếm) | Authority key custody 2-of-3 offline (✅ có); signing runbook 2 người; **staged rollout**: update mới áp canary trước, fleet sau; emergency revoke qua transparency checkpoint; residual risk ghi THREAT_MODEL |
| Partial download / disk corrupt | Two-phase staging + hash binding bytes thật (✅ có, INV-005); retry có rate limit |
| **Boot-loop repair** | Repair rate-limited (N lần/ngày); K lần fail liên tiếp → ở lại **last-known-good**, phát peer alert + dashboard, **không** auto-wipe |
| Last-known-good | Giữ version staged trước (known-good rollback ✅ trong thiết kế rules §3.1 roadmap — áp dụng cho cả binary); activation fail → tự revert + alert |
| Recovery audit | Mọi quyết định repair/isolate/recovery ghi **MMR append-only** — recovery không được phép "ngoài sổ sách" |

Ranh giới trung thực giữ nguyên: "tự vá" = tự phục hồi **từ update có chữ
ký** — không AI tự sinh code; không có authority key ⇒ repair bị từ chối.

---

## 8. Threat model mesh — T1…T12 (điều kiện đóng NSG-0)

| # | Rủi ro | Biện pháp thiết kế | Nhóm test |
|---|---|---|---|
| T1 | **Sybil** — node giả tràn mạng | Enroll + attestation; cold-start cap (§4); diversity rules (§5); bound graph | Adversarial |
| T2 | **Replay/MITM frame** | AEAD + sequence monotonic + nonce window; MITM không có khóa → handshake fail | Adversarial |
| T3 | **Node bị chiếm phát lệnh cách ly giả** | Independence-weighted quorum (§5); evidence_ref bắt buộc; reputation decay; authority revoke | Adversarial + Attack |
| T4 | **False-quarantine DoS** | Quorum §5 + shadow mode + TTL + recovery ký; wrong-action rate đo trước auto | Benign + Adversarial |
| T5 | **Poison gossip** (spam/flood) | Flood-limit per-peer, frame bound, drop đếm được; dedupe event_id | Adversarial |
| T6 | **Privacy leak giữa node** | Selective disclosure — chỉ indicator + merkle ref; không serial/telemetry thô; **retention policy §8.1** | Adversarial |
| T7 | **Partition / split-brain** | Epoch protocol §6.2 — đặc tả đầy đủ, milestone riêng NSG-1.6 | Failure/Recovery |
| T8 | **Rendezvous bị chiếm/nói dối** | Server chỉ giới thiệu — trust không bao giờ đến từ server; client verify chữ ký peer độc lập | Adversarial |
| T9 | **Transport yếu làm cửa sau** | Tier A/B/C (§10) — Tier C không mang frame trust | Attack |
| **T10** | **Resource/CPU/memory exhaustion**: graph flooding, evidence flooding, merkle proof khổng lồ, queue exhaustion, handshake exhaustion, disk exhaustion | **INV-015**: mọi queue/graph/evidence store bound cứng + drop đếm được; handshake rate-limit per-source; cap kích thước merkle proof; disk quota cho spool | Adversarial |
| **T11** | **State explosion**: node/ incident/ edge/ stale state tăng vô hạn | Bounded graph (256/2048); incident TTL + archive tự động; edge GC theo heartbeat; epoch compaction (event cũ gộp root) | Adversarial |
| **T12** | **Local privilege abuse** — malware trên chính node thao túng CyberV local IPC/state | File state/config mesh ACL hóa (tái dụng hardening `filesystem_acl`); config mesh ký authority (kênh INV-011); IPC giữ allowlist PID + AEAD (P1-1); **residual trung thực:** malware admin về nguyên tắc chạm được software vault → mitigation thật = vault shield + PPL (M1) + TPM non-exportable (P2-1); node nghi bị chiếm phải tự isolate được (UC-2) | Attack (local) |

### 8.1 Data retention & privacy policy (P1.10)

- Evidence pack giữa node: **chỉ indicator + merkle ref**, expiry mặc định
  90 ngày local; hết hạn → xóa bản thân, chỉ còn root trên MMR.
- Không lưu/hầu hết telemetry thô qua mesh; server Supabase chỉ giữ report
  metadata + ranking, không payload raw.
- Mọi thứ mesh gửi qua cloud phải đi qua `SelectiveDisclosureEngine`.
- Local user có đường export/purge evidence của node mình (audit vẫn còn trên
  MMR — purge không xóa hash chain).

---

## 9. WFP Isolation — Operational Semantics (mới — P1.7)

Isolation "reversible trên giấy" chỉ thành reversible an toàn khi đặc tả vận
hành đủ:

| Khía cạnh | Quy tắc |
|---|---|
| **Scope** | Chặn traffic đến/đi **IP/port của node bị isolate** (per-peer, không CIDR cào bằng nếu tránh được); lưu cả endpoint set snapshot tại thời điểm isolate |
| **Chiều** | Chặn cả inbound + outbound tới peer đó |
| **Loopback** | KHÔNG BAO GIỜ chạm loopback; IPC agent-UI không bị ảnh hưởng |
| **Tự cách ly** | Khi node tự isolate chính mình: chỉ outbound bị chặn trừ kênh update + rendezvous read-only (phải còn đường vá và báo cáo) |
| **Persistence + reboot** | Rules đánh dấu tiền tố `CyberV-NSG-`; **deadline TTL lưu bằng thời điểm tuyệt đối**; khi boot, reconcile: quét marker rules, xóa rule hết hạn, tính lại TTL từ deadline đã lưu (reboot không reset vòng đời isolation) |
| **TTL race** | Cleanup idempotent; watchdog quét lại mỗi tick; crash trước khi cleanup → startup reconcile dọn — **hết TTL mà không có recovery ký → auto-lift về Unknown rồi mới tái attestation** (reversibility outranks persistence, đúng INV-014) |
| **Admin override** | Local admin lift được isolation qua UI + UAC; hành động ghi MMR |
| **Break-glass** | Exemption ký authority (mẫu Trụ 4 — corporate proxy exemption), audit MMR |
| **Race khi isolate ↔ đồng thời recovery** | Serialize qua lock trong `quarantine.rs`; mọi transition qua state machine §3, không mutation trực tiếp rule |

---

## 10. Transport Tiering A/B/C (P1.9 — formal hóa)

| Tier | Transport | Vai trò | Trạng thái dùng | Quy tắc |
|---|---|---|---|---|
| **A — Production target** | LAN/IP: mDNS discovery + TCP + AEAD session | Toàn bộ frame mesh: gossip, vote, evidence | Sản xuất | Mọi test correctness/quorum/benchmark chạy trên Tier A |
| **B — Experimental** | WiFi Direct (`WiFiDirectAdvertisementPublisher`/Watcher, WinRT) | Discovery + session phụ | Config flag riêng, tắt mặc định | Không tính vào trust weight cho tới khi có fault-injection riêng đạt; chỉ NSG-5+ |
| **C — Auxiliary** | BLE advertisement | **Beacon discovery thôi** | Không bao giờ mang mesh frame | Zero trust contribution; presence BLE không nâng NodeState |

`MeshTransport` trait: Tier B/C cắm vào không đụng core — multi-transport
không được kéo chậm core NSG (nếu B/C trễ → cắt, không chặn NSG-4…8).

---

## 11. Performance Benchmark Framework (mới — P1.8, NSG-3.5)

Correctness/security test chưa đủ — mesh là distributed system, cần số liệu.
Harness: `agent/tests/mesh_bench.rs` (nhỏ, thật) + `mesh-sim` bin (10–256 node
mô phỏng — trung thực: >10 node chỉ mô phỏng được, không phải lab thật; số
mô phỏng ghi rõ nguồn khi công bố).

| Metric | Mục tiêu khởi điểm (calibrate khi đo) |
|---|---|
| Discovery latency (LAN) | ≤ 5 s tới khi thấy đủ peer |
| Handshake latency | ≤ 1 s p95 |
| Gossip propagation | ≤ 2 s tới 90% fleet (50 node LAN) |
| Memory/node (steady) | ≤ 2 MB |
| CPU tick nền | ≤ 1% một core |
| Evidence processing | ≥ 100 events/s |
| Quorum decision latency | ≤ 3 s từ vote cuối cùng |
| Bandwidth overhead | ≤ 50 KB/s idle; ≤ 500 KB/s lúc incident |
| Scalability runs | 2 / 10 / 50 / 100 / 256 node — đúng bound graph §3 |

Bảng số liệu lưu vào mục benchmark của chính tài liệu này mỗi release — số
không đạt → không mở phase tiếp theo (tinh thần close condition).

---

## 12. Phân phase NSG-0 → NSG-8 + điều kiện đóng

```text
NSG-0   Threat Model T1–T12 + Wire Protocol spec          [tài liệu — làm ngay]
NSG-1   Graph + NSG Event Model + Quorum engine (pure)    [làm ngay]
NSG-1.5 Trust/Reputation + Quorum Independence (pure)     [làm ngay — BẮT BUỘC]
NSG-1.6 Epoch + Partition/Merge Consistency (pure + sim)  [làm ngay — BẮT BUỘC]
        ──── gate: P1-1 AEAD primitive có thật ────       (tái dụng, không viết 2 lần)
NSG-2   LAN Discovery + Attestation + AEAD session        (UC-1 only, zero action)
NSG-3   Gossip + IOC Correlation + Shadow Ledger          (read-only action)
NSG-3.5 Performance + Fault Injection                    (§11; số liệu gate cho NSG-4)
        ──── gate: freeze gate Trụ 1 + D2.3 response ladder ────
NSG-4   Peer Quarantine + WFP + TTL Recovery              (shadow → pilot)
NSG-5   WiFi Direct + BLE Discovery + Rendezvous          (Tier B/C)
NSG-6   Healing + Signed Repair + Recovery Safety Model
NSG-7   Adversarial Large-Scale Mesh Testing              (mesh-sim 100–256 node)
NSG-8   Production Hardening + Observability              (GetStatus mesh, metrics, dashboard)
```

| Phase | Điều kiện đóng |
|---|---|
| NSG-0 | T1–T12 vào `THREAT_MODEL.md`; wire format + event model chốt trong tài liệu này |
| NSG-1 | State machine + event dedupe/conflict + quorum engine pure; Attack/Benign/Adversarial matrix xanh; workspace test xanh |
| NSG-1.5 | TrustScore 5 chiều + cold-start cap; **test chứng minh**: bầy Sybil node-mới không đủ quorum; hai vote cùng evidence root đếm một; report nhầm → B decay |
| NSG-1.6 | Partition → DegradedEpoch → merge reconcile đúng 3 nhánh §6.2; stale-epoch vote bị loại; split-brain benign không isolate nhầm |
| NSG-2 | Hai process thật LAN handshake; node không attest → `Discovered` không hơn; MITM/replay sim fail |
| NSG-3 | Flood/replay/poison bị từ chối + đếm; shadow ledger không thực thi action; suspect ranking xuất format §7.2 |
| NSG-3.5 | Bảng benchmark §11 đủ, không mục nào đỏ; fault injection (kill process giữa handshake/gossip) recover đúng |
| NSG-4 | Wrong-action rate ~0 trên benign set; WFP semantics §9 rehearse (reboot giữa TTL, race recovery); mọi isolate có recovery test |
| NSG-5 | Tier B/C đúng vai trò: BLE không mang frame (test chứng minh); Tier B flag-tắt mặc định |
| NSG-6 | Repair từ chối manifest không ký; boot-loop protection test; recovery audit trên MMR |
| NSG-7 | mesh-sim adversarial (sybil farm, collusion 2 node, partition storm) — tỷ lệ sai ≤ ngưỡng policy |
| NSG-8 | GetStatus phản chiếu mesh state thật (kể cả QuorumUnavailable); dashboard graph + observability; docs cập nhật |

---

## 13. Bất biến mới đề xuất (vào `INVARIANTS.md` ở NSG-1, kèm test)

> Draft ràng buộc sớm — như quy cách "Planned" của INVARIANTS.md (INV-009/010/011).

- **INV-012 (planned) — Mesh Channel Fail-Closed:** mọi frame mesh có chữ ký
  Ed25519 identity + AEAD + anti-replay (sequence/nonce window). Peer không
  attest được → tối đa `Discovered`: không nhận evidence, không vote, không
  hành động vì nó. Frame sai xác thực drop **và đếm được**.
  *Vi phạm nếu:* accept frame không sign/AEAD vì "LAN tin được"; nâng trust từ
  presence thay vì handshake chữ ký.
- **INV-013 (planned, v2 viết lại) — Diversity-Aware Action Authority:** mọi
  peer-quarantine cần quorum **pairwise-independent có trọng số, cùng epoch**
  (5 điều kiện §5), tổng W ≥ ngưỡng, ≥ 1 tín hiệu `verified`; report đơn lẻ
  chỉ là L0; node cold-start bị ghim trọng số; shadow mode mặc định cho tới
  khi wrong-action rate đạt ngưỡng benign set.
  *Vi phạm nếu:* quorum đếm node thay vì đếm nguồn độc lập; hai vote cùng
  evidence root đếm kép; vote stale-epoch được tính; bỏ cold-start cap;
  bật auto không qua shadow.
- **INV-014 (planned, mở rộng) — Reversible Isolation + Operational Safety:**
  mọi isolation có TTL tuyệt đối (reboot không reset vòng đời), cleanup
  idempotent + startup reconcile, đường recovery ký authority, break-glass
  ký authority; không chạm loopback/IPC; auto-lift sau TTL nếu không có
  recovery (sau đó bắt buộc tái attestation để lên `Attested`).
  *Vi phạm nếu:* TTL vô hạn; rule mồ côi sau reboot; recovery không verify
  chữ ký; isolation chặn chính kênh update của node tự cách ly.
- **INV-015 (planned, mới) — Bounded Mesh State:** mọi cấu trúc mesh
  (graph, queue gossip, evidence store, handshake backlog) có bound cứng trong
  config ký; vượt → từ chối entry mới + đếm loss hiển thị (không âm thầm);
  epoch compaction định kỳ giữ state hữu hạn.
  *Vi phạm nếu:* queue unbounded "để chắc"; drop không đếm; bound chỉ nằm
  trong comment.

---

## 14. Ma trận kiểm thử 4 nhóm cho mesh (merge gate từng phase)

| Nhóm | Kịch bản NSG | Kỳ vọng |
|---|---|---|
| **Attack** | MITM handshake; replay phiên; sybil farm (mesh-sim); canary tấn công node B → B tự isolate; **local admin malware thao túng state file (T12)** | handshake fail; replay drop+đếm; sybil không đủ weighted quorum; self-isolate; state file tamper bị phát hiện |
| **Benign** | ngủ/thức, đổi WiFi, tắt BT, node offline tạm, update chính đáng, **partition rồi hội tụ không có tấn công** | không vote/quorum; edge stale → Unknown; merge không isolate nhầm |
| **Adversarial** | report giả loạt node (T4); flood (T5/T10); gossip thiếu provenance; evidence ref sai Merkle; **collusion 2 node (T3)**; stale-epoch vote | report đơn không thành action; flood bị bound + đếm (INV-015); frame từ chối; collusion bị independence rules chặn |
| **Failure/Recovery** | chia cắt → hội tụ (§6.2); isolate nhầm → recovery ký; repair fail giữa chừng; **reboot giữa TTL isolation**; crash-loop | epoch reconcile đúng; recovery đúng TTL; staging rollback sạch; rule mồ côi được dọn |

Fault injection (NSG-3.5): kill process giữa handshake/gossip/merge, đầy disk
spool, clock skew — recover đúng hoặc báo degraded, không im lặng.

---

## 15. Xếp hạng ưu tiên và điều plan này KHÔNG thay đổi

1. **Freeze gate không di động:** NSG-4/5/6 mở sau freeze gate Trụ 1 + D2.3.
   NSG-0…NSG-1.6 pure logic/tài liệu — làm song song, không tăng attack surface.
2. **Không nhảy hàng P1-1/P2-1:** NSG-2 cần primitive P1-1 — thứ tự tự nhiên.
3. **Bluetooth giữ Tier C** — không hứa data qua BT.
4. **Dependency mới** (mdns-sd, cytoscape…) qua cargo-deny/machete + rationale.
5. **Config mặc định:** `mesh.enabled=false`, `shadow=true`, mọi ngưỡng quorum
   nằm trong signed policy — vắng mặt tính năng không làm detection xấu đi.
6. **Residual risks trung thực** vào THREAT_MODEL: collusion hoàn hảo,
   authority key compromise, local-admin compromise — giảm rủi ro, không triệt tiêu.

## 16. Trạng thái thực hiện

| Phase | Trạng thái | Bằng chứng |
|---|---|---|
| NSG-0 | ✅ Đã hiện thực | THREAT_MODEL.md biên giới T5 (M1–M12); wire format chốt — Phụ lục A |
| NSG-1 | ✅ Đã hiện thực | `mesh/{mod,graph,events,quorum}.rs`; `mesh_graph_tests.rs` (8), `mesh_quorum_tests.rs` (13) + unit |
| NSG-1.5 | ✅ Đã hiện thực | `mesh/reputation.rs` (TrustScore 5 chiều, cold-start cap 150, decay/restore + cooldown); test chứng minh sybil farm 6 node = 900 < 1800, farm + 1 node lành = 1400/1600 < 1800, report sai ×2 → weight 0 |
| NSG-1.6 | ✅ Đã hiện thực | `mesh/consistency.rs` (DegradedEpoch, marker ký, merge 3 nhánh, shared-parent independence); `mesh_consistency_tests.rs` (8) |
| NSG-2 | ⚠️ Tầng session ✅ / mDNS wiring ❌ | `mesh/session.rs` (bắt tay 3 bước X25519 + AEAD ChaCha20-Poly1305 hai chiều + replay window 128 commit-sau-tag); `mesh/discovery.rs` (beacon codec); `mesh_session_tests.rs` (11 — MITM thay PK, downgrade 2 chiều, khóa lạ qua Hello nhưng vỡ ở Confirm, reflection role, replay, frame bounds, **bắt tay trọn vẹn + trao đổi mã hóa qua TCP loopback thật**). Phần còn lại: **NSG-2b** mDNS socket + wire vào daemon (crate discovery phải qua cargo-deny/machete) |
| NSG-3 | ✅ Pure logic / ❌ transport wiring | `mesh/gossip.rs` (GossipInbox flood-limit per-peer, stats phân loại replay/poison/stale + đếm đủ); `mesh/shadow.rs` (ShadowLedger — **không có API thực thi**, `executed` bất biến false); `mesh/correlation.rs` (IOC sweep + SuspectRank format §7.2 — confidence per-mille, independent_sources tái dùng cùng greedy independence với quorum, FP indicators bắt buộc); `mesh_gossip_tests.rs` (8 end-to-end). Phát hiện thêm 1 lỗ hổng: poison clone cùng event_id lọt dedupe → sửa fail-closed (ràng buộc id↔nội dung trước dedupe). Gossip transport thật chờ NSG-2b |
| NSG-4…NSG-8 | ❌ Planned | NSG-4 gate: freeze gate Trụ 1 + D2.3 (shadow → pilot chỉ sau khi wrong-action rate đạt ngưỡng benign set) |

Ghi chú khác biệt nhỏ giữa plan → code (cố ý, ghi trung thực):
- `mesh/config.rs` tách riêng chưa cần — policy co-locate với engine của nó
  (`QuorumPolicy`, `ReputationPolicy`, `ConsistencyPolicy`); khi NSG-2 wire
  `agent_config.json` sẽ thêm lớp `mesh` section và chuyển sang signed policy.
- TrustScore dùng **số học per-mille nguyên** (0..=1000, saturating), không
  float — dễ audit, không trần.
- Behavior/History có **baseline trung lập 500** khi attest (danh tính đã chứng
  minh mật mã → giả định vô tội hạn chế); Observation/Evidence vẫn Unknown tới
  khi có dữ liệu thật (INV-007). Wrong-action (decay 600) đưa node mới về
  weight 0 ngay lập tức.
- Điều kiện 4 (causal separation) mở rộng thêm **shared causal parent**: hai
  vote cùng phái sinh từ một report = một nguồn phái sinh.
- Isolated → Suspect là đường hợp lệ duy nhất để hạ cấp (merge reconcile §6.2b)
  — đã thêm vào bảng chuyển trạng thái kèm test.

Bước tiếp theo: NSG-2 (mDNS discovery + AEAD session tái dụng P1-1) khi P1-1
hoàn thành; NSG-3.5 benchmark khi mesh có transport thật.

---

## Phụ lục A — Wire format đã chốt (theo code NSG-1)

### A.1 Canonical event payload (ký Ed25519 trên chính bytes này)

```text
DOMAIN_MESH_EVENT ("CYBERV/MESH/EVENT/v1")  || 0x00
MESH_EVENT_VERSION (u32 BE)                  || 0x00
kind (u8: Report=1 Vote=2 Heartbeat=3 EpochMarker=4 Recovery=5) || 0x00
signal_class (u8: Verified=1 Heuristic=2 None=0)                || 0x00
origin_id (32B)
origin_seq (u64 BE)
epoch (u64 BE)
created_wall_ms (u64 BE)
expiry_wall_ms (u64 BE)
subject    (0x00 | 0x01 + 32B)
evidence_root (0x00 | 0x01 + 32B)
obs_channel (u8: None=0 Kernel=1 ProcessMitigations=2 FilesystemAcl=3
             NetworkSurface=4 EtwTelemetry=5 Privilege=6 Wdac=7 Other=8)
causal_count (u32 BE) + causal_parents (mỗi cái 32B)
```

- `event_id` = SHA-512/32 của (`DOMAIN_MESH_EVENT_ID` || 0x00 || canonical) —
  chìa khóa dedupe tự nhiên, đồng thời bind id với nội dung (verify chặn tráo id).
- `signature` = Ed25519 identity key của origin trên canonical bytes; verify
  rebuild canonical từ trường và so cả id lẫn sig (test tamper/swap-id).
- Miền băm/ký tách bạch: `CYBERV/MESH/EVENT/v1`, `CYBERV/MESH/EVENT_ID/v1`,
  `CYBERV/MESH/MEMBERSHIP/v1` — cùng quy ước domain separator của
  `protocol::constants` (chống cross-domain signing oracle).

### A.2 NSG Event struct (Rust)

```rust
pub struct NsgEvent {
    pub event_id: [u8; 32],       // hash domain-separate của canonical
    pub origin_id: NodeId,        // device_id canonical (32B)
    pub origin_seq: u64,          // monotonic per-origin — lùi = replay
    pub epoch: u64,
    pub causal_parents: Vec<[u8; 32]>,  // DAG nhân quả
    pub evidence_root: Option<[u8; 32]>, // Vote/Report thiếu root = L0 telemetry
    pub created_wall_ms: u64,
    pub expiry_wall_ms: u64,      // hết hạn → không feeding quyết định
    pub kind: EventKind,
    pub signal_class: Option<SignalClass>,
    pub subject: Option<NodeId>,
    pub obs_channel: Option<ObsChannel>,
    pub signature: [u8; 64],
}
```

### A.3 Công thức quorum (per-mille nguyên)

```text
W(peer) = min( caps, S )
  caps  = 1000
        × (cap_unknown=250 nếu có chiều Unknown, ngược lại 1000)
        × (cold_start_cap=150 nếu còn cold-start, ngược lại 1000)
        × (min các chiều đã biết)
  S     = Σ dim_weights[k] × dim_k / 1000    (weights = [200,200,250,200,150])

Đề nghị isolate đạt khi ALL:
  (a) Σ W_i (các phiếu pairwise-independent, cùng epoch, weight>0, không
      revoked) ≥ 1800
  (b) số phiếu ≥ 2
  (c) ≥ 1 phiếu signal_class == Verified
Độc lập theo cặp: origin khác && channel khác && root khác && không quan hệ
nhân quả trực tiếp && không cùng causal parent && path khác.
```

---

## Phụ lục B — Rationale dependency mới (AGENTS.md cấm danh sách #6)

**Thêm 2026-10-04, phục vụ NSG-2 (tầng session) — tái dụng cho P1-1:**

| Crate | Version | Lý do |
|---|---|---|
| `x25519-dalek` | 2 (features: static_secrets, zeroize) | Đúng crate PHASE1_2 plan P1-1 chỉ định; RustCrypto chính chủ, pure-Rust; ephemeral secret zeroize-on-drop đúng INV-008 |
| `chacha20poly1305` | 0.10 (default-features off, chỉ alloc) | Đúng crate P1-1 chỉ định; AEAD RFC 8439 cho frame phiên mesh + IPC sau này |

Trung thực: `cargo-machete`/`cargo-deny` **chưa cài trên máy dev** — không
chạy được local; job CI dependency-check phải xanh trước merge. Rationale ghi
tại đây theo đúng cấm danh sách #6.

### B.1 Ghi chú thiết kế session (v2, theo code)

- Bắt tay 3 bước: `Hello` → `HelloAck(sig bám CẢ HAI PK ephemeral + CẢ HAI
  node_id + version + role)` → `Confirm(sig chiều ngược)` — MITM thay PK nào
  cũng làm chữ ký lệch; reflection role bị chặn ở discriminant + role byte.
- Khóa phiên: HKDF-SHA512(X25519, salt = transcript hash, info = domain +
  chiều) → **hai khóa độc lập hai chiều**; nonce = sequence per-chiều.
- Replay window 128 với quy tắc **commit-sau-tag**: cửa sổ chỉ cập nhật sau
  khi tag AEAD xác thực — frame giả không thể đẩy frame thật ra khỏi cửa sổ.
- `ack_sig_payload` / `confirm_sig_payload` công khai — là một phần wire
  format, test dựng ack/confirm lệch để kiểm chứng gate phía bên kia.
