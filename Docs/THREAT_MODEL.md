# CyberV — Threat Model (STRIDE)

> Phạm vi: 4 biên giới tin cậy chính của hệ thống. Mỗi bảng liệt kê mối đe dọa
> STRIDE, kiểm soát hiện tại, và trạng thái. Rà soát lại tài liệu này **mỗi
> major release** và khi có thay đổi kiến trúc ở các biên giới dưới đây.
> Tham chiếu kỹ thuật: `README.md` (invariants INV-001..008),
> `Docs/PHASE1_2_IMPLEMENTATION_PLAN.md`, `Docs/PIPELINE_SECURITY_PLAN.md`.

## Trust Boundaries

```text
[T1] UI (cyberv_ui, quyền user)  ◄── Named Pipe ──►  [T2] Agent/Broker (service, SYSTEM)
                                                        │
                     Internet ◄── HTTPS ──►  [T3] Update/Transport channel
                                                        │
[T4] Ring-0 (CyberVProbe.sys) ◄── IOCTL ──► Agent (SDDL: SYSTEM+Admins)
```

---

## T1 — Named Pipe IPC (UI ↔ Agent)

| # | STRIDE | Mối đe dọa | Kiểm soát | Trạng thái |
|---|--------|------------|-----------|------------|
| 1.1 | Spoofing | Process khác giả danh UI kết nối pipe | Handshake version + nonce echo (client xác server); PID client lấy từ kernel + allowlist fail-closed (`with_allowed_client_pids`) | ⚠️ Cơ chế có sẵn, allowlist chưa được wire mặc định (B2-4) |
| 1.2 | Spoofing | Pipe squatting: pre-create pipe DACL yếu | `first_pipe_instance(true)` | ✅ Đã vá (C9) |
| 1.3 | Tampering | Sửa frame trên dây (giữa UI và agent) | HMAC-SHA512 session key phủ toàn bộ frame, constant-time compare | ✅ Đã vá (C10) |
| 1.4 | Repudiation | Client chối bỏ đã gửi lệnh | Chưa có audit log per-frame gắn PID | ❌ Backlog (B2-8, thấp) |
| 1.5 | Info disclosure | Đọc trạng thái/attestation không phép | Frame ≤ 64KB; GetStatus fail-closed UNKNOWN; MAC chặn đọc đục lỗ | ✅ |
| 1.6 | DoS | Treo kết nối cạn kiệt instance; flood pipe | Read-timeout 30s + loop không chết + max_instances 8 | ✅ Đã vá (M5) |
| 1.7 | Elevation | Lệnh `SignChallenge` biến broker thành signing oracle | MAC bắt buộc trước khi thực thi lệnh + session cap 64 | ✅ Đã vá (C4) |
| 1.8 | Elevation | DACL giả trên pipe cho phép client thấp đặc quyền | DACL thật qua SECURITY_ATTRIBUTES chưa có — đang HMAC-only | ❌ P1-1 (AEAD + DACL) |

## T2 — Update / Transport channel (Agent ↔ Server)

| # | STRIDE | Mối đe dọa | Kiểm soát | Trạng thái |
|---|--------|------------|-----------|------------|
| 2.1 | Spoofing | Server giả/MITM cấp gói cập nhật độc hại | Manifest Ed25519 pinned key + re-hash package bytes (`verify_package_binding`) | ✅ Đã vá (C2) — hạ tầng phát hành M1 |
| 2.2 | Tampering | Đổi byte gói sau khi qua manifest | Hai-phase commit: chỉ CompleteCommit khi counter + hash cùng khớp | ✅ Đã vá (M1 staging) |
| 2.3 | Repudiation | Gói cũ bị phát hành lại (rollback update) | `VersionPolicyValidator` từ chối downgrade/replay | ✅ |
| 2.4 | Info disclosure | JWT/apikey/chữ ký đi plaintext | Transport bắt buộc HTTPS (loopback miễn trừ test) | ✅ Đã vá (H2) |
| 2.5 | DoS | Feed update trả payload khổng lồ OOM agent | Chưa có giới hạn kích thước response | ❌ Backlog (L11) |
| 2.6 | Spoofing | Thiết bị giả attestation lên server | Challenge-response Ed25519 + server tự thực thi TTL challenge | ✅ |
| 2.7 | Elevation | Không xác thực được vẫn "đã bảo vệ" | Engine chỉ quay lại Active khi `authenticated=true` | ✅ Đã vá (H1) |

## T3 — DPAPI Vault (khóa định danh thiết bị)

| # | STRIDE | Mối đe dọa | Kiểm soát | Trạng thái |
|---|--------|------------|-----------|------------|
| 3.1 | Spoofing | Vault transplant giữa máy khác nhau | DPAPI gắn user/machine + vault shield cam kết file | ✅ |
| 3.2 | Tampering | Sửa vault file trực tiếp | `VaultShield::verify_integrity` fail-closed khi chưa lock baseline | ✅ Đã vá (H6) |
| 3.3 | Info disclosure | Đọc khóa từ RAM (dump, cạnh tranh bộ nhớ) | `Secret32` zeroize-on-drop; ed25519-dalek zeroize feature bật; **chưa có** `VirtualLock` | ⚠️ Backlog (B2-5) |
| 3.4 | Info disclosure | Crash dump chứa khóa | Chưa có policy tắt dump cho service | ❌ B1-4 (M0+1) |
| 3.5 | DoS | Xóa/thay vault gây mất identity | Kiểm tra ACL thư mục (probe thật) thuộc P1-3 | ❌ P1-3 |
| 3.6 | Tampering | Torn write khi mất điện | Đã rename atomic nhưng **thiếu** `FlushFileBuffers` + tmp name unique | ❌ Backlog (L4) |

## T4 — Ring-0 Interface (Agent ↔ CyberVProbe.sys)

| # | STRIDE | Mối đe dọa | Kiểm soát | Trạng thái |
|---|--------|------------|-----------|------------|
| 4.1 | Spoofing | Process khác đăng ký PID của tiến trình khác | IOCTL chỉ cho đăng ký PID của chính caller; SDDL device SYSTEM+Admins | ✅ Đã vá (M1 driver) |
| 4.2 | Tampering | Ghi đè registration vô hiệu hóa shield | `STATUS_DEVICE_BUSY` khi active khác PID; driver tự tra cứu create-time | ✅ Đã vá (C1/M2) |
| 4.3 | Spoofing | PID reuse lừa driver bảo vệ process lạ | Kernel-capture `PsGetProcessCreateTimeQuadPart` (FILETIME) | ✅ Đã vá (C1) |
| 4.4 | Tampering | Terminate/inject qua process handle | ObCallbacks strip mask mở rộng (VM_OPERATION, CREATE_THREAD...) | ✅ Đã vá (M3) |
| 4.5 | Tampering | Tấn công qua thread handle (TerminateThread...) | PsThreadType callback strip THREAD_* | ✅ Đã vá (H5) |
| 4.6 | DoS | Spam IOCTL mở cạn tài nguyên kernel | Sequential queue + buffer check nghiêm ngặt; không cấp phát pool | ✅ |
| 4.7 | Info disclosure | Đọc evidence qua IOCTL không phép | SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | ✅ |
| 4.8 | Spoofing | Driver giả mạo tráo dữ liệu kernel | Chưa có attestation driver ↔ agent (driver signing là bước đầu) | ❌ Phase 2 (P2-2 + attestation signing) |
| 4.9 | Repudiation | Telemetry bị agent "chế" | Agent không tự sinh telemetry khi driver vắng mặt (fail-closed UNKNOWN) | ✅ Đã vá (C11) |

## T5 — Mesh NSG (Node ↔ Node qua LAN/WiFi-Direct/BLE) — 📐 planned

> Biên giới mới theo `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2. Mã đe dọa M1–M12
> tương ứng T1–T12 trong plan. **Toàn bộ kiểm soát mới là thiết kế chưa code**
> (NSG-0…NSG-8) — không mục nào được trình bày như "đã bảo vệ" cho tới khi có
> test chứng minh (Zero Deceptive Signals / INV-009 planned).

| # | STRIDE | Mối đe dọa | Kiểm soát thiết kế | Trạng thái |
|---|--------|------------|-----------|------------|
| M1 | Spoofing | Sybil: node giả enroll hàng loạt tạo quorum giả | Enroll + attestation (khóa device); TrustScore cold-start cap ghim trọng số node mới; quorum independence 5 điều kiện; bound graph 256 node | ❌ NSG-1.5 |
| M2 | Tampering | Replay/MITM frame giữa node | AEAD session + sequence monotonic + nonce window; handshake chữ ký identity; MITM không khóa → fail | ❌ NSG-2 (P1-1 primitive) |
| M3 | Elevation | Node bị chiếm phát lệnh cách ly giả cho cả mạng | Quorum independence có trọng số (pairwise 5 điều kiện + weighted); evidence_root bắt buộc; reputation decay; revoke qua transparency | ❌ NSG-1/1.5 |
| M4 | DoS | False-quarantine: report đơn lẻ cắt node lành | Report đơn = L0 telemetry; shadow mode mặc định; TTL bắt buộc; recovery ký authority; wrong-action rate đo trên benign set trước auto | ❌ NSG-4 |
| M5 | DoS | Poison/flood gossip | Flood-limit per-peer, frame bound, dedupe event_id, drop đếm được (INV-015) | ❌ NSG-3 |
| M6 | Info disclosure | Rò rỉ telemetry/serial giữa node | Selective disclosure — chỉ indicator + merkle ref; retention 90 ngày; server chỉ giữ metadata | ❌ NSG-3 |
| M7 | DoS | Partition/split-brain hai phân mạng cách ly nhầm nhau | Epoch + DegradedEpoch + merge protocol 3 nhánh; stale-epoch vote bị loại; safety over liveness (xung đột → Suspect) | ❌ NSG-1.6 |
| M8 | Spoofing | Rendezvous (Supabase) bị chiếm/nói dối | Server chỉ giới thiệu — trust không bao giờ đến từ server; client verify chữ ký peer độc lập | ❌ NSG-5 |
| M9 | Spoofing | Transport yếu (BT/WiFi-Direct) làm cửa sau | Tier A/B/C: BLE chỉ beacon discovery, không mang mesh frame; WiFi-Direct flag-tắt mặc định | ❌ NSG-5 |
| M10 | DoS | Resource/CPU/memory exhaustion (graph flooding, merkle proof khổng lồ, handshake storm) | INV-015: mọi queue/graph/evidence store bound cứng + drop đếm được; rate-limit per-source; cap proof size; disk quota | ❌ NSG-1 |
| M11 | DoS | State explosion (node/incident/edge tăng vô hạn) | Bound graph; incident TTL + archive; edge GC; epoch compaction | ❌ NSG-1/1.6 |
| M12 | Elevation | Malware local-admin thao túng mesh state/IPC của chính node | State/config mesh ACL hóa; config ký authority; IPC allowlist PID + AEAD; **residual trung thực:** admin chạm được software vault → vault shield + PPL (M1) + TPM (P2-1); node nghi bị chiếm tự isolate | ❌ NSG-4 |

---

## Rủi ro được chấp nhận (Accepted Risks)

| Rủi ro | Lý do chấp nhận | Điều kiện xem lại |
|---|---|---|
| HMAC thay AEAD trên IPC (không mã hóa payload) | Payload chỉ là trạng thái/lệnh, không có bí mật; UI và agent cùng máy | P1-1 AEAD sẽ thay |
| `keyring`-style OS storage chưa dùng | DPAPI trực tiếp đã đáp ứng | Khi đa user profile |
| Metadata độ tươi `None` = full score (H5) | Cần thay đổi đồng bộ phase20 tests; hiện ghi nhận trong kế hoạch P1-3 | P1-3 |

## Phương pháp đánh giá (mặt nạ trạng thái)

- ✅ — kiểm soát đã hiện thực + có test; ⚠️ — hiện thực một phần; ❌ — chưa làm, có backlog item tương ứng.
- Mọi mục ❌/⚠️ **không được phép** xuất hiện trong tài liệu marketing như "đã bảo vệ" (Zero Deceptive Signals).
