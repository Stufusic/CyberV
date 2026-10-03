# CyberV — Lộ trình Phòng thủ Toàn diện (v2, sau phản biện kiến trúc)

> **EN: Defense roadmap v2 — revised after an architectural review. Key changes
> vs v1: independent-failure trust model, verified-vs-heuristic signal taxonomy,
> Pillar-1 freeze gate before any expansion, thin-driver principles, corrobora-
> tion-gated response ladder, benign/negative testing as first-class, quality-
> weighted ATT&CK coverage, phased response rollout (Observe→Shadow→Pilot→Auto),
> and a formal invariant for event-loss safety.**
>
> Nguyên tắc ưu tiên (thay cho mọi "roadmap ambition"):
> **Correctness > Evidence > Reliability > Detection > Prevention > Automation > Coverage.**
>
> Zero Deceptive Signals không còn là nguyên tắc viết tài liệu — nó là **bất
> biến kiểm thử được** (INV-009 planned, §7): mọi control tuyên bố phải có
> repeatable test + evidence ref, nếu không thì không được phép xuất hiện
> ở trạng thái ✅ ở bất kỳ đâu.

---

## 1. Định vị & Mô hình tin cậy (v2)

CyberV: **nền tảng định danh thiết bị neo phần cứng** mở rộng thành **ngăn xếp
phòng thủ phân lớp**. Ranh giới không đổi: không AV, không SIEM thay thế, không
firewall biên, không sandbox cloud.

### 1.1 Sự khác biệt so với v1: chuỗi tin cậy TUYẾN TÍNH → LỚP ĐỘC LẬP LỖI

v1 mô tả `TPM → Ring-0 → telemetry → response → SIEM` như một chuỗi. v2 chuẩn
hóa thành **5 năng lực độc lập, mỗi lớp có mô hình lỗi riêng**:

| Năng lực | Câu hỏi trả lời | Thất bại trông như thế nào | Mô hình lỗi |
|---|---|---|---|
| **Identity** | Máy này là ai? | Giả danh được → toàn bộ fleet decision sai | fail-closed (không xác minh được = không tin) |
| **Integrity** | Máy còn nguyên vẹn? | Bị can thiệp mà không biết → attestation nói dối | fail-closed + tamper-detectable |
| **Detection** | Có đang bị tấn công? | Sai/bỏ sót → mất thời gian phản ứng | probabilistic — KHÔNG fail-closed được, phải đo precision/recall |
| **Prevention** | Chặn được không? | Chặn nhầm → DoS chính mình | fail-safe (default allow + alert, trừ đường ghi tài sản đã protected) |
| **Response** | Phản ứng đúng không? | Action sai → thiệt hại lớn hơn tấn công | policy-gated + reversible-first |

**Tự-chỉnh:** TPM đúng không bảo đảm agent đúng; kernel đúng không bảo đảm
telemetry đúng; detection đúng không bảo đảm response đúng. Mỗi lớp được đánh
giá và kiểm chứng **riêng biệt** — không được cộng gộp thành "an ninh tổng".

### 1.2 Phân loại tín hiệu (áp từ đầu, không phải sau)

| Lớp tín hiệu | Định nghĩa | Nguồn | Quy tắc sử dụng |
|---|---|---|---|
| **Verified** | Có neo mật mã/cơ chế OS không thể giả bởi process user-mode | TPM NV counter thật, Ring-0 observation, chữ ký device key, hash chain | Đủ để hành động đơn nguồn (theo policy) |
| **Heuristic** | Telemetry hành vi — đúng về mặt dữ liệu nhưng ý nghĩa là suy diễn | ETW-Ti, file write patterns, firewall log | CHỈ dùng để phát hiện/cảnh báo; hành động L2+ cần corroboration (§3.3) |

Mọi verdict ghi rõ **signal class** — không được pha trộn "verified" với
"heuristic" khi trình bày (mở rộng trực tiếp INV-002).

### 1.3 Tự vệ của agent — diễn đạt lại chính xác

Thay vì "không thể tắt" (không đúng tuyệt đối — admin đủ cao vẫn có đường),
cam kết chính xác là: **tamper-resistant** (tước quyền handle Ring-0),
**tamper-detectable** (mọi nỗ lực tăng counter + telemetry), **recoverable**
(SCM restart + state recovery + fleet alert). Đây là tập hợp có thể kiểm thử.

## 2. Sáu trụ phòng thủ (v2)

### Trụ 1 — Neo tin cậy = ĐIỂM KHÓA TIẾN ĐỘ (freeze gate)

Thứ tự đóng gói cứng, **không hoán đổi**:

```text
1. TPM thật (P2-1) → 2. Device identity thật (P2-1) → 3. Secure IPC AEAD (P1-1)
→ 4. Signed update vận hành (M1) → 5. Rollback protection trên counter thật (P2-1)
→ 6. Recovery path đã rehearse (P1-2 + EmergencyDowngrade)
```

**Freeze gate:** khi 6 mục đạt "verified" (có test + red-team harness), API và
invariant của Trụ 1 bị **đóng băng** — mọi thay đổi sau đó phải qua review
CODEOWNERS + threat model delta. D2/D3 **không được mở** trước freeze gate
(chống "ảo giác security coverage": detection đứng trên foundation stub chỉ
tạo báo cáo đẹp trên nền tin cậy giả).

### Trụ 2 — Phòng thủ kernel: NGUYÊN TẮC THIN DRIVER

Bài học trung tâm của phản biện: giá trị cao nhất, rủi ro lớn nhất → **driver
cực mỏng, quyết định ở user-mode**:

| Nguyên tắc | Chi tiết |
|---|---|
| Driver chỉ làm 2 việc | (a) enforce primitive (deny write vào protected path), (b) phát signal |
| Không logic detection trong kernel | Pattern/confidence/decision nằm ở user-mode pipeline |
| Mọi callback bounded | Không blocking, không allocation kéo dài, timeout nội bộ, xử lý cancellation |
| Unload-safe + race-safe | Đúng thứ tự teardown (bài học từ ObCallbacks hiện tại), không dùng-after-free khi process kết thúc giữa callback → telemetry |
| Kill-switch | Registry/secure-flag pass-through mode: filter lỗi → tự chuyển pass-through + alert, KHÔNG chặn I/O hệ thống |

**Canary v2 — đa tín hiệu thay vì ngưỡng đơn:**
`N file / T giây` đơn lẻ tạo FP với compiler/backup/updater. Công thức điều kiện
L2 canary = **tổng hợp**: write-rate bất thường **AND** (entropy/extension-change
pattern) **AND** process lineage không tin cậy (unsigned/unapproved) **AND/OR**
canary event. Mỗi tín hiệu độc lập chỉ tạo alert L0/L1.

**ETW-Ti:** giữ đúng nguyên tắc — ETW là **heuristic telemetry**, không phải
bằng chứng; luôn gắn nhãn signal class heuristic.

**Self-protection:** bổ sung image-load callback chặn DLL unsigned vào agent;
PPL khi signed driver sẵn sàng (M1).

### Trụ 3 — Phát hiện & Phản ứng

**3.1 Rules Engine — ràng buộc cứng (không thành scripting engine trá hình):**
- Rules là **dữ liệu khai báo có giới hạn biểu thức** (match trên event fields,
  threshold, time-window) — KHÔNG phải code/turing-complete.
- Phân phối: chỉ qua kênh update ký → tái dụng trọn bộ INV-005 (signature,
  monotonic version, anti-rollback) + **schema validation** + **resource limits**
  (số rule, độ phức tạp match) + **atomic activation** + **known-good rollback**
  (giữ version trước; activation mới fail → tự revert + alert).

**3.2 Event Pipeline + PROVENANCE BẮT BUỘC:**
Mỗi event mang ít nhất:
`{source, signal_class, trust_level, timestamp_mono+wall, sequence, process_identity (pid, path, signer, lineage), evidence_ref}`
— forensic phải trả lời được "verdict này dựa trên cái gì". Không provenance
đủ → event chỉ là L0 telemetry, không đủ feeding verdict L2+.

**Pipeline resilience → bất biến chính thức (INV-010 planned):**
- Priority classes: L2+ security event **không bao giờ bị mất âm thầm**
  (spool-to-disk + loss accounting); L0 telemetry có thể drop khi quá tải
  (đếm được, báo được).
- Watchdog + degraded mode: pipeline chết → detection chết **phải hiển thị** ở
  GetStatus (không im lặng — đúng tinh thần fail-closed).
- Thống nhất: backpressure/bound đã có ở EventBus → nâng thành formal invariant
  với test.

**3.3 Response Ladder v2 — corroboration trước hành động:**

```text
signal → confidence → CORROBORATION → policy → response
```

| Bậc | Điều kiện kích hoạt | Rollout gate |
|---|---|---|
| L0 log | Mọi tín hiệu | luôn bật |
| L1 block handle/file (temporary) | 1 verified signal HOẶC ≥2 heuristic tương quan | pilot |
| L2 kill process | **≥2 nguồn độc lập**, ≥1 verified HOẶC 3 heuristic khớp cùng technique; chưa từng FP trên benign set | Observe→Shadow→Pilot→Limited Auto→Full Auto |
| L3 quarantine + evidence pack | L2 confirmed + policy authority bật | pilot fleet |
| L4 network isolate | authority policy + confirm L3 | thủ công trước |

Quy tắc: **không bao giờ `1 signal → kill`**; mọi action reversible-first;
mọi action ghi MMR append-only (anti rogue-admin); **shadow mode**: L2/L3 chạy
"log-only" ghi quyết định ĐÃ SẼ làm nhưng không thực thi — dùng để đo
wrong-action rate trước khi bật thật.

### Trụ 4 — Mạng: thêm VÒNG ĐỜI PINNING (chống tự khóa mình)

TLS pinning là security-critical và dễ tự bắn chân trong môi trường doanh nghiệp
(proxy MITM hợp pháp, cert rotation). Thiết kế bắt buộc:

- Pin theo **SPKI set có backup pin** (≥2 key, key dự phòng offline).
- Pin set phân phối như **config có chữ ký authority** (cùng kênh rules) — rotate
  không cần release binary mới.
- Outage behavior: pin fail → block + alert + thử pin set dự phòng; KHÔNG
  fail-open âm thầm, KHÔNG brick vĩnh viễn — có **exemption mode** ký authority
  cho tenant có corporate proxy (audit được qua MMR).
- Clock/revocation: mọi kiểm tra thời hạn dùng nguồn monotonic + grace window
  có chữ ký (time manipulation là risk đã ghi §8).

### Trụ 5 — Ransomware & **Exfiltration behavioral indicators** (đổi tên cho đúng)

- ETW + firewall log tạo **chỉ báo hành vi exfiltration** — không đủ kết luận
  exfiltration hoàn chỉnh; mọi verdict ở lớp này ghi signal class heuristic.
- **Evidence pack integrity** (chống chính attacker sửa/xóa): hash-chain liên
  kết các gói evidence, monotonic sequence, chữ ký device key, **local spool**
  write-ahead + **secure upload queue** có retry — mất kết nối không mất evidence,
  kẻ xóa cục bộ không xóa được chuỗi hash đã spool.

### Trụ 6 — Vận hành & Kiểm chứng: TEST THEO 4 NHÓM (nền tảng chống FP)

| Nhóm | Nội dung | Gate |
|---|---|---|
| **Attack** | red-team matrix (Atomic Red Team style) — attack → detect | phải detect |
| **Benign** | compiler, backup, installer, Windows Update, browser, IDE, game, Docker/VM, enterprise software — **MUST NOT trigger** | phải im lặng |
| **Adversarial** | chống chính CyberV: fake manifest, rule poisoning, event spam, clock manipulation, evidence tamper | phải từ chối |
| **Failure/Recovery** | pipeline crash, driver fail-safe, kill-switch, restore từ quarantine | phải recover đúng |

**Regression tự động 4 nhóm chạy sau MỖI thay đổi driver/rules** — đây là điều
kiện merge, không phải hoạt động thời điểm.

## 3. Kiến trúc bổ sung — chú ý single choke point

Kiến trúc pipe không đổi nhưng thêm các yêu cầu độ bền (đã nâng thành planned
invariants §7): priority classes, loss accounting, watchdog/degraded mode,
priority spool. Trụ nào cũng phải có hành vi độc lập khi pipeline chết:
driver vẫn enforce primitive (prevention không phụ thuộc detection).

## 4. Ma trận MITRE ATT&CK — coverage theo CHẤT LƯỢNG, không theo số lượng

**Bỏ KPI "60% coverage" làm chỉ tiêu chính.** Coverage chỉ là công cụ quản lý
scope (secondary). Một technique chỉ được đánh ✅ khi đạt đủ 7 cột:

```text
Technique → Detect? → Prevent? → Respond? → Evidence? → Tested? → FP-tested? → Confidence
```

Bảng ATT&CK chi tiết v1 giữ nguyên cấu trúc 10 tactics nhưng **cột trạng thái
đổi theo 7 cột trên** — bảo trì trong file này, review mỗi cột mốc. 10
technique detect tốt có giá trị hơn 40 detect yếu: chọn techniques theo (a) tần
suất thực chiến, (b) khớp thế mạnh kiến trúc (Defense Evasion/Impact — nơi
CyberV có verified signal).

## 5. Lộ trình D1→D4 v2 — tách D2, thêm VERIFICATION gate

```text
FOUNDATION   P1-2 → P1-3 → P2-1 → M1 signing
                 ↓ (Pillar-1 freeze gate: 6 mục verified + invariant đóng băng)
VERIFICATION Threat Model mở rộng (risk mới §8) → INVARIANTS INV-009/010/011
             → Failure/Recovery tests cho chính foundation
                 ↓
D1           Event schema + provenance → pipeline + INV-010 test
             → rules v1 (10-15 rule CỰC KỲ tin cậy, không mở rộng số lượng)
             → red-team + benign harness v1  (~3 tuần)
                 ↓
D2.1 Kernel/minifilter   (thin-driver, kill-switch; regression: 4 nhóm test)
                 ↓
D2.2 ETW + detection     (multi-source correlation)
                 ↓
D2.3 Response ladder     (L0→L2 có policy + rollback + shadow mode)
                 ↓
D2.4 WDAC pilot          (allowlist, audit-mode-first như cũ)
                 ↓
D3.1 SIEM/Fleet  →  D3.2 Network (L4)  →  D3.3 Forensics/evidence pack
                 ↓
D4       Continuous adversarial verification (không phải "đạt xanh rồi dừng")
```

**Điều kiện đóng từng phase (phase-close conditions):**

| Phase | Điều kiện đóng |
|---|---|
| P1/P2 | TPM/identity/IPC/update chạy thật + red-team foundation xanh |
| M1 | Driver/artifact chain verified end-to-end |
| D1 | Pipeline ổn định + rules replayable + 4 nhóm test chạy CI |
| D2.1 | Minifilter không crash trên toàn bộ test matrix + kill-switch demo được |
| D2.2 | ETW multi-source correlation + precision/recall đo được trên benign/attack set |
| D2.3 | L0→L2 có policy + rollback + shadow-mode wrong-action rate dưới ngưỡng |
| D2.4 | WDAC pilot không break benign workloads |
| D3.1-3 | Event/verdict end-to-end; L4 policy-controlled; evidence integrity kiểm chứng |
| D4 | Continuous verification pipeline chạy định kỳ + mọi regression bị bắt |

**Rollout L2/L3 cứng:** Observe → Shadow → Pilot → Limited Auto → Full Auto —
mỗi bước phải qua ít nhất một chu kỳ benign regression đầy đủ.

## 6. KPI v2 — thêm chất lượng, hạ coverage xuống secondary

| KPI | Mục tiêu | Nhóm |
|---|---|---|
| **Precision / Recall** (trên benign + attack set) | precision ≥ 99% trước L2 auto; recall đo được theo matrix | Detection quality |
| **Wrong-action rate** (% response sai) | ~0 trên shadow mode; đo trước mọi mức auto | Response correctness |
| **Evidence chain completeness** | 100% verdict L2+ có evidence-ref đầy đủ | Evidence integrity |
| **% auto-response chứng minh đúng qua replay test** | 100% trước khi bật Full Auto | Response correctness |
| MTTR + rollback success rate (chính CyberV) | rehearse mỗi release | Recovery |
| MTTD (self-tamper/canary/fake-update) | < 30s / < 60s / < 5s | Detection speed |
| ATT&CK coverage (quality-weighted) | secondary — chỉ để quản lý scope | Scope |
| Kernel overhead | < 3% IOPS | Performance |

## 7. Bất biến mới (chuyển vào `Docs/INVARIANTS.md` mục "Planned")

- **INV-009 (planned) — Testable Honest Signaling:** mọi control/verdict xuất
  bản phải có (a) signal class (verified/heuristic), (b) evidence-ref, (c)
  repeatable test id. CI gate: không có control ✅ không test. = Zero Deceptive
  Signals thành bất biến máy đọc được.
- **INV-010 (planned) — No-Silent-Loss:** event L2+ không bao giờ bị drop âm
  thầm (spool + loss accounting + degraded mode hiển thị); drop L0 phải đếm được.
- **INV-011 (planned) — Signed Rule Distribution:** rules chỉ qua kênh ký
  (INV-005 reuse) + schema validation + resource limits + atomic activation +
  known-good rollback.

## 8. Rủi ro bổ sung (từ phản biện — phải vào THREAT_MODEL trước gate D2)

| Rủi ro | Biện pháp |
|---|---|
| **Supply-chain build compromise** | Reproducible build hướng tới, SBOM so khớp, signing xảy ra trên artifact đã verify hash |
| **Signing key/build artifact compromise** | 2-of-3 offline custody (có), + rotation runbook, + cert profile tách bạch dev/prod |
| **Time manipulation** (clock ảnh hưởng TTL/rollback/trajectory) | Monotonic nguồn + grace window ký; đã có FreshnessState::Unknown — áp dụng nhất quán toàn pipeline |
| **Resource exhaustion** (spam event nghẽn pipeline) | INV-010 + priority classes + loss accounting + bound per-source |
| **Kernel/user race** (callback → process chết → telemetry) | Teardown đúng thứ tự; snapshot PEPROCESS reference trước; test race chuyên biệt |
| **Recovery failure / tự khóa chính mình** | Kill-switch pass-through; break-glass recovery (đã có WDAC); rehearse "CyberV chặn chính CyberV" trong Failure/Recovery test |

## 9. Thay đổi so với v1 (changelog phản hồi review)

- Chuỗi tin cậy tuyến tính → 5 năng lực độc lập lỗi + mô hình fail-open/fail-safe từng lớp (§1.1)
- Thêm taxonomy verified/heuristic (§1.2); tự vệ diễn đạt lại "tamper-resistant + detectable + recoverable" (§1.3)
- Trụ 1 thành freeze gate chặn D2/D3 (§2)
- Minifilter: thin-driver principles + kill-switch; canary đa tín hiệu (§2)
- Rules engine: ràng buộc chống scripting-engine; event provenance bắt buộc; pipeline → INV-010 (§3)
- Response: corroboration matrix + shadow mode + rollout 5 bước (§3.3)
- Pinning lifecycle chống tự khóa (§4)
- "Exfiltration detection" → "behavioral indicators"; evidence pack hash-chain + spool (§5)
- Testing 4 nhóm (Attack/Benign/Adversarial/Failure-Recovery) thành gate merge (§6)
- ATT&CK coverage → secondary, 7 cột chất lượng (§4)
- D2 tách D2.1-D2.4; D3 tách D3.1-D3.3; D4 = continuous verification (§5)
- KPI: + precision/recall, wrong-action rate, evidence completeness, replay-proven auto-response (§6)
- Rủi ro: +6 mục mới (§8)
