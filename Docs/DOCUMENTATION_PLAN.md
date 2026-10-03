# CyberV — Kế hoạch Tài liệu hóa (Documentation Plan)

> Mục tiêu: một bộ tài liệu **đầy đủ, chuẩn mực, phân tầng theo độc giả** cho
> 3 nhóm: (1) Kỹ sư phát triển, (2) AI coding assistant, (3) Người dùng cuối /
> SecOps. Kèm README cho **từng thư mục code cốt lõi**.
>
> Nguyên tắc số 0 áp cho cả tài liệu (giống Zero Deceptive Signals của app):
> **mọi tuyên bố an ninh phải trỏ về test hoặc dòng Threat Model chứng minh nó**.
> Không viết "đã bảo vệ" cho thứ đang mô phỏng.

---

## 1. Hiện trạng (Audit 2026-10-02)

| Tài liệu | Trạng thái | Vấn đề |
|---|---|---|
| `README.md` (root, ~700 dòng, tiếng Việt) | Tốt về kiến trúc/quick start | Thiếu "bản đồ tài liệu"; một số claim an ninh cần đối chiếu lại với trạng thái trung thực hiện tại |
| `USER_GUIDE.md` (411 dòng) | Tồn tại | Chưa phản ánh hành vi trung thực (UI hiển thị UNKNOWN khi daemon chưa wire); thiếu troubleshooting |
| `REQUIREMENTS.md` (132 dòng) | Tồn tại | Tách khỏi thực tế implement; cần đánh dấu trạng thái mỗi yêu cầu |
| `SECURITY.md` | ✅ Đầy đủ | — |
| `Docs/THREAT_MODEL.md`, `PIPELINE_SECURITY_PLAN.md`, `PHASE1_2_...`, `DRIVER_SIGNING_RUNBOOK.md` | ✅ Mới, được track | — |
| `Docs/rv*.md`, `Plan.md`, `Rule.md`, `Pipeline.md` | **Private** (gitignored) | Code tham chiếu `Ref: Docs/rv10.md...` khắp nơi nhưng người clone repo KHÔNG đọc được — gãy ngay từ onboarding |
| **Module README** (agent/, driver/, cyberv_ui/, backend/, database/) | ❌ Không có | Kỹ sư/AI mới phải đọc toàn bộ source để hiểu từng module |
| `AGENTS.md`, bản đồ bất biến cho AI | ❌ Không có | AI assistant không có ngữ cảnh quy ước → hay đề xuất change vi phạm invariant |
| `CHANGELOG.md`, `CONTRIBUTING.md`, `ARCHITECTURE.md`, `API_PROTOCOLS.md` | ❌ Không có | — |

---

## 2. Nguyên tắc soạn thảo (áp cho mọi tài liệu mới)

1. **Một tài liệu — một độc giả**: không trộn tutorial cho end-user với spec kỹ thuật (khung Diátaxis: Tutorial / How-to / Reference / Explanation).
2. **Mọi tuyên bố an ninh phải có "chứng cứ"**: link tới test (`agent/tests/...`), bất biến (INV-xxx), hoặc dòng trong `Docs/THREAT_MODEL.md`. Không chứng cứ = không được viết ở thì khẳng định.
3. **Bảng trạng thái trung thực** trong mỗi module README: ✅ thật / ⚠️ mô phỏng một phần / ❌ chưa hiện thực — đồng bộ với threat model.
4. **Tài liệu sống cùng PR**: PR chạm module BẮT BUỘC cập nhật README module + dòng threat model liên quan (thêm vào PR template).
5. **Không trùng lặp nguồn sự thật**: mỗi fact chỉ viết ở 1 nơi, nơi khác link tới (tránh docs lệch nhau khi code đổi).

---

## 3. Kiến trúc tài liệu mục tiêu

```text
README.md                      ← Cổng vào: quick start + BẢN ĐỒ TÀI LIỆỆU (ai cần gì vào đâu)
AGENTS.md                      ← [AI] Quy ước build/test/code cho AI assistant
CONTRIBUTING.md                ← [Kỹ sư] quy trình PR, review gate, chuẩn commit
CHANGELOG.md                   ← [Tất cả] lịch sử phát hành theo Keep a Changelog

Docs/
├── ARCHITECTURE.md            ← [Kỹ sư+AI] C4 context/container/component, trust boundaries
├── API_PROTOCOLS.md           ← [Kỹ sư+AI] spec dây truyền: IPC frame, IOCTL ABI, HTTP DTO, canonical encoding
├── THREAT_MODEL.md            ← ✅ có
├── PIPELINE_SECURITY_PLAN.md  ← ✅ có
├── PHASE1_2_IMPLEMENTATION_PLAN.md ← ✅ có
├── DRIVER_SIGNING_RUNBOOK.md  ← ✅ có
├── KEY_MANAGEMENT.md          ← [SecOps] custody model, runbook keygen/rotate/lost-share
├── OPERATIONS.md              ← [SecOps] deploy, service mgmt, monitor, incident response
├── INVARIANTS.md              ← [AI+Kỹ sư] INV-001..008 + cách kiểm chứng từng cái
└── CONTEXT_MAP.md             ← [AI] bản đồ module: mục đích, type chính, entry test

<module>/README.md             ← [Kỹ sư+AI] theo template §5 — cho 12 module cốt lõi
USER_GUIDE.md                  ← [Người dùng] làm mới
```

---

## 4. Ba track độc giả

### Track 1 — Kỹ sư phát triển

| Tài liệu | Nội dung bắt buộc |
|---|---|
| **README.md root (cấu trúc lại)** | Giữ quick start; thêm bảng "Tôi cần gì → đọc đâu" (setup / hiểu kiến trúc / sửa module X / vận hành / báo lỗi an ninh); sửa các claim an ninh theo trạng thái trung thực |
| **Docs/ARCHITECTURE.md** | C4 Level 1-3 (reuse diagram root README + trust boundary của THREAT_MODEL); luồng dữ liệu enroll → attest → re-enroll; lý giải quyết định kiến trúc (broker/worker tách, fail-closed...) |
| **Docs/API_PROTOCOLS.md** | Spec toàn bộ "dây truyền": (a) IPC frame JSON + HMAC spec + bounds; (b) IOCTL ABI: 4 CTL_CODE, layout struct packed, ClientAbiVersion; (c) HTTP DTOs + endpoint; (d) canonical encoding (escape rules) + format payload ký từng giao thức (domain separators) — **nguồn sự thật duy nhất** cho ABI 2 phía |
| **CONTRIBUTING.md** | Setup dev, branch/commit convention (khớp git log hiện tại), yêu cầu test, review gate CODEOWNERS, checklist docs-đi-cùng-PR |
| **12 module README** | Xem §5 |

### Track 2 — AI coding assistant (điểm mới, chi phí thấp lợi ích cao)

| Tài liệu | Nội dung bắt buộc |
|---|---|
| **AGENTS.md (root)** | Lệnh build/test/lint chính xác (`cargo test --workspace --release`, `cargo clippy -- -D warnings`, `pytest` từ root); quy ước code (comment tiếng Việt, identifier tiếng Anh, saturating math cho counter, không `unwrap()` trên input ngoài); **danh sách cấm** (đưa mock vào production path, hạ fail-closed, sửa `ioctl.h` không sửa Rust mirror, ghi "verified" cho probe stub...); pointer tới INVARIANTS + CONTEXT_MAP |
| **Docs/CONTEXT_MAP.md** | Mỗi module ~10 dòng: mục đích 1 câu, type/trait chính, điểm vào test, phụ thuộc — tối ưu cho AI retrieve, không kể chuyện |
| **Docs/INVARIANTS.md** | INV-001..008: phát biểu chính xác + **test nào chứng minh** + **change gì là vi phạm** — AI kiểm tra trước khi đề xuất change |

Lý do ưu tiên track này: mỗi session AI làm việc trên repo tiết kiệm được thời gian khám phá lại và giảm rủi ro AI phá invariant (rủi ro thật — invariant nằm rải rác trong 40+ file).

### Track 3 — Người dùng cuối & SecOps

| Tài liệu | Nội dung bắt buộc |
|---|---|
| **USER_GUIDE.md (làm mới)** | Cập nhật hành vi trung thực (UNKNOWN nghĩa là gì, khi nào thành PROTECTED); cài đặt (ZIP hiện tại → Inno installer khi M1); troubleshooting (service không start, pipe lỗi, UI hiện UNKNOWN); FAQ |
| **Docs/OPERATIONS.md** | Cài/dỡ service + driver (script có sẵn), xem log `ProgramData\CyberV\logs`, cấu hình update authority key, quy trình rotate/lost-share, incident: nghi ngờ compromise làm gì |
| **CHANGELOG.md** | Keep a Changelog format, khởi tạo từ các commit đã có |

---

## 5. Template README module (chuẩn bắt buộc, 10 mục)

```markdown
# <Tên module>

> <1 câu: làm gì + tại sao tồn tại> — [Tiếng Anh 1 dòng cho AI retrieval]

**Trạng thái:** ✅ thật / ⚠️ mô phỏng một phần (nêu phần nào) / ❌ kế hoạch
**Biên giới tin cậy:** [T1-T4 theo Docs/THREAT_MODEL.md]

## 1. Vị trí trong kiến trúc      (sơ đồ excerpt + ai gọi nó)
## 2. Cấu trúc file               (file → trách nhiệm, bảng)
## 3. Bất invariant chịu trách nhiệm (INV-xxx + test chứng minh)
## 4. API công khai chính         (type/fn quan trọng + ví dụ 3-5 dòng)
## 5. Luồng dữ liệu               (input → validate → state → output)
## 6. Cấu hình & phụ thuộc        (env var, crate, module khác)
## 7. Kiểm thử                    (chạy lệnh nào, test nào phủ cái gì)
## 8. ⛔ KHÔNG ĐƯỢC làm           (change phá an ninh — cụ thể từng dòng)
## 9. Hạn chế đã biết             (đồng bộ threat model ❌/⚠️)
## 10. Liên kết                   (threat model rows, plan items, rv-doc nếu private)
```

---

## 6. Danh sách 12 module README (nội dung neo sẵn từ audit)

| # | File | Nội dung then chốt phải có |
|---|---|---|
| 1 | `agent/README.md` | Toàn cảnh crate: lib entry points, bin `cyberv-keygen`, service; daemon state machine |
| 2 | `agent/src/defense/README.md` | PassiveDefenseCoordinator, policy ladder fail-closed, bố cục passive/* |
| 3 | `agent/src/defense/passive/ipc/README.md` | Pipe lifecycle, frame spec, HMAC session, allowlist, **khác biệt giữa HMAC hiện tại và AEAD mục tiêu** |
| 4 | `agent/src/defense/passive/isolation/README.md` | Broker/Worker privilege separation, admission 7 bước, replay protection |
| 5 | `agent/src/defense/passive/update/README.md` | Staging hai-phase, version policy, manifest + authority gate fail-closed |
| 6 | `agent/src/identity/README.md` | Vault format (magic header), DPAPI, Secret32, persistence — **đừng làm**: log key, serialize PersistedIdentity |
| 7 | `agent/src/kernel/README.md` | IOCTL ABI (trỏ API_PROTOCOLS), pure parser, cross-validator fail-closed |
| 8 | `agent/src/trust/README.md` | Tầng TPM: **bảng trung thực mock-vs-real** (nv_counter/key/quote), lộ trình TBS/PCP |
| 9 | `agent/src/evidence/README.md` | Merkle RFC 6962, MMR, constraints, temporal — quy ước domain-separated hashing |
| 10 | `driver/CyberVProbe/README.md` | Build (WDK), ObCallbacks semantics, create-time capture, runbook ký |
| 11 | `cyberv_ui/README.md` | MVC/ViewModel layout, display_policy gatekeeper, IPC client, quy tắc fail-closed display |
| 12 | `backend/README.md` + `database/README.md` | Edge Functions (challenge/verify-state/enroll...), RLS + definer functions, migration policy |

---

## 7. Quy ước ngôn ngữ (cần chốt)

| Phương án | Ưu | Nhược | Khuyến nghị |
|---|---|---|---|
| A. Tiếng Việt toàn bộ | Đồng bộ hiện trạng; độc giả chính là nhóm nội địa | AI retrieval kém hơn; cộng đồng quốc tế khó tiếp cận | — |
| B. Tiếng Anh toàn bộ | Chuẩn quốc tế, AI-friendly | Đập đi toàn bộ doc tiếng Việt hiện có | — |
| **C. Song song nhẹ** | Cân bằng | Cần kỷ luật | **✅ Khuyến nghị:** tiếng Việt là ngôn ngữ chính (khớp code comment hiện tại); **mỗi module README + mỗi file Docs có 1 dòng tóm tắt tiếng Anh** ngay đầu (`> EN: ...`) để AI/international retrieval; AGENTS.md viết song ngữ ngắn |

---

## 8. Quy trình duy trì (docs-as-code)

- **PULL_REQUEST_TEMPLATE.md**: checklist "README module + THREAT_MODEL đã cập nhật?" cho PR chạm code.
- **CODEOWNERS**: bổ sung `Docs/` (các file tracked) vào review gate.
- **Link check** (M2, optional): job CI chạy `lychee`/script kiểm link nội bộ không gãy.
- **Nguồn sự thật**: ABI chỉ viết ở `API_PROTOCOLS.md`; trạng thái module chỉ ở README module; threat status chỉ ở THREAT_MODEL — mọi nơi khác link.
- Giữ `Docs/rv*.md` private như hiện tại; module README khi cần tham chiếu rv-doc sẽ trích nội dung, không link ra tài liệu private.

---

## 9. Lộ trình thực hiện

| Cột mốc | Nội dung | Ước lượng |
|---|---|---|
| **M-D0** | README root (bản đồ docs + sửa claim) + `AGENTS.md` + `Docs/INVARIANTS.md` + `Docs/CONTEXT_MAP.md` | ~0.5 ngày |
| **M-D1** | `Docs/ARCHITECTURE.md` + `Docs/API_PROTOCOLS.md` | ~1 ngày |
| **M-D2** | 12 module README theo template §5 | ~2 ngày |
| **M-D3** | USER_GUIDE làm mới + `OPERATIONS.md` + `KEY_MANAGEMENT.md` + `CHANGELOG.md` + `CONTRIBUTING.md` + PR template | ~1.5 ngày |

**Tổng: ~5 ngày-công.** Thứ tự đề xuất: M-D0 trước (chi phí thấp nhất, lợi ích cao nhất cho mọi session AI/kỹ sư sau đó), rồi M-D2 (module README) chạy song song với phát triển code, M-D1/M-D3 theo.

### Định nghĩa hoàn thành
1. Kỹ sư mới: onboarding chỉ bằng root README + ARCHITECTURE + module README của phần mình phụ trách, không cần đọc rv-doc private.
2. AI assistant: AGENTS.md + CONTEXT_MAP + INVARIANTS đủ để không đề xuất change vi phạm bất biến (kiểm chứng bằng cách để AI tự trả lời "INV nào chi phối file X?"').
3. Người dùng: mọi thao tác hằng ngày + sự cố thường gặp có hướng dẫn trong USER_GUIDE/OPERATIONS.
4. Zero claim không chứng cứ: grep các từ "đã xác minh/bảo vệ" trong docs — mỗi hit phải link test/threat-model.
