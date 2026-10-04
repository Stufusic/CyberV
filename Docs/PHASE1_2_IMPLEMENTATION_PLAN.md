# CyberV — Kế hoạch Thực hiện Phase 1 & Phase 2

> **CẬP NHẬT 2026-10-02 (lần 2):** Phase 3 & Phase 4 đã THỰC HIỆN — xem mục `6` ở cuối tài liệu.
> Trạng thái: **Phase 1 (cột mốc khẩn cấp) — đã thực hiện trong session này** cho các lỗi critical;
> các mục còn lại đã được ước lượng công việc. Phase 2 lên kế hoạch chi tiết cho các chu kỳ sau.
>
> Bối cảnh: Audit toàn diện (2026-10-02) xác nhận khoảng cách giữa bất biến an ninh tài liệu
> hóa và mã nguồn thực tế. Tài liệu này phân rã công việc còn lại thành các gói có thể giao
> hàng và kiểm chứng độc lập.

---

## 1. Cột mốc đã hoàn tất (Critical Fixes — session 2026-10-02)

| # | Lỗi | File | Biện pháp |
|---|-----|------|-----------|
| C1a | `process_start_time` sai đơn vị (giây Unix vs FILETIME 100ns/1601) → shield không bao giờ strip quyền | `agent/src/defense/kernel/registration.rs` | Gửi FILETIME thật từ `GetProcessTimes`; driver tự tra cứu `PsGetProcessCreateTimeQuadPart` và chỉ *xác minh* giá trị client |
| C1b | (Kernel) tin start-time do client khai | `driver/CyberVProbe/ob_callbacks.c` | Kernel-side capture + từ chối client khai lệch (`STATUS_REVISION_MISMATCH`) |
| C2 | Agent không bao giờ gọi `register_protected_pid` | `agent/src/service.rs` | Wire `attempt_kernel_shield_registration()` vào SERVICE_RUNNING, log trung thực cả thành công/lỗi |
| C3 | INF thiếu `[NT.Wdf]`/`KmdfService` → driver không load được | `driver/CyberVProbe/CyberVProbe.inf` | Thêm section Wdf, pin `KmdfLibraryVersion 1.15` |
| C4 | Hạ shield: `PROCESS_VM_OPERATION/CREATE_THREAD` không strip; thread-handle bypass hoàn toàn | `ob_callbacks.c` | Mở rộng mask; thêm `PsThreadType` callback (strip `THREAD_TERMINATE/SUSPEND_RESUME/SET_CONTEXT/...`) |
| C5 | Ghi đè registration ngầm vô hiệu hóa bảo vệ | `ob_callbacks.c` | Chặn `STATUS_DEVICE_BUSY` khi đang active khác PID; reject PID không tồn tại |
| C6 | ABI version không được kiểm tra cả 2 phía | `ioctl.h` + `kernel/protocol.rs` + `client.rs` + `driver.c` | Thêm `ClientAbiVersion` (u64) vào struct registration; driver trả `STATUS_REVISION_MISMATCH` nếu lệch |
| C7 | Cổng cập nhật không xác minh chữ ký nào | `defense/passive/update/manifest.rs` | `verify_signature(&VerifyingKey)` dùng Ed25519 thật trên canonical length-prefixed bytes + `verify_package_binding` re-hash bytes gói; staging bỏ điều kiện `hash \|\| version`, else-branch → `RollbackCleanly` |
| C8 | Recovery attestation có fallback tính được chữ ký từ public inputs | `defense/recovery/re_attestation.rs` | Xóa fallback; bắt buộc 32-byte key; canonical message thêm `previous_pcr`, nonce, `created_at` (length-prefixed); freshness check 15 phút |
| C9 | Named pipe không DACL, không xác thực client, có thể bị squatting | `ipc/server.rs` | `first_pipe_instance(true)`; client PID từ kernel (`GetNamedPipeClientProcessId`) + allowlist fail-closed; read-timeout 30s; loop không chết khi cạn instance; phản hồi gắn `server_seen_client_pid` |
| C10 | Frame broker không MAC → signing oracle | `isolation/{protocol,worker,broker}.rs` | HMAC-SHA512 (16-byte, constant-time compare) phủ mọi trường; MAC check **trước** sequence; session key CSPRNG; cap 64 phiên |
| C11 | `GetStatus` trả hằng số PROTECTED + hash bịa | `ipc/server.rs` | Trả `UNKNOWN` + `is_verified=false` fail-closed; bỏ hash giả; AttestationChallenge trả UNAVAILABLE |
| C12 | TPM NV counter là RAM mock nhưng báo `HardwareBacked` | `trust/tpm/nv_counter.rs` | Báo `SoftwareFallback` trung thực cho tới khi tích hợp TBS thật (Phase 2) |
| C13 | `TpmIdentityKey` phần mềm tự xưng hardware non-exportable | `trust/tpm/key.rs`, `binding.rs`, `provider.rs` | Tách `new_tpm_managed` (thật) vs `new_simulated_software` (cờ trung thực); `assurance_level()` theo cờ thật; mock quote không còn ký bằng khóa bất kỳ |
| C14 | Serial thô truyền lên mạng | `hardware/normalizer.rs` | `serial_commitment` = SHA-512 domain-separated; canonical_id dùng 128-bit đầu; test chặn serial thô |
| C15 | Checkpoint rogue-key + un-revoke thiếu bind | `transparency/{checkpoint,proof}.rs` | `verify_with_pinned_authority` + `expected_log_id`; guard bind `device_id` + `mmr_root` |
| C16 | Backend RPC sai tham số → auth flow gãy | `verify-state/index.ts` | Đúng `p_device_id` |
| C17 | RPC SECURITY DEFINER không kiểm ownership | `database/migrations/20260905000003_lock_definer_functions.sql` (mới) | REVOKE từ anon/authenticated + ownership gate trong thân hàm |
| C18 | Engine fail-open: `Ok(_)` → Active bỏ qua `authenticated` | `daemon/engine.rs` | Chỉ chuyển Active khi `authenticated && AUTHENTICATED` |
| C19 | `decode_hex` panic UTF-8; invariant bypass whitespace; service heartbeat bịa; HTTPS không bắt buộc; UI recovery tự xưng PROTECTED; `bool("false")`; UI default fail-open; handshake không verify nonce | nhiều file | Đã vá tương ứng + test |

---

## 2. PHASE 1 — Hoàn thiện tường lửa xác thực (còn lại)

### P1-1. Kênh IPC mã hóa đầy đủ (X25519 + ChaCha20-Poly1305) — 5 ngày
Hiện trạng: frame đã có HMAC-SHA512 với session key, nhưng session key hiện được sinh phía
broker và "trao" cho worker trong bộ nhớ (mô phỏng handshake). Chưa có DACL thật trên pipe.

> **CẬP NHẬT 2026-10-04 (b) — P1-1a ĐÃ HIỆN THỰC phía agent:**
> - ✅ Primitive tái dụng từ NSG-2 (`mesh/session.rs` + `mesh/pipe_session.rs`):
>   bắt tay 2 bước X25519 — client gửi PipeHello(pk_ephemeral), agent trả
>   PipeHelloAck **ký Ed25519 identity bám version + CẢ HAI PK** (client pin
>   khóa agent — chống MITM/squatting); HKDF-SHA512 → 2 khóa 2 chiều; AEAD
>   ChaCha20-Poly1305 thay HMAC cho mọi envelope; replay window 128
>   commit-sau-tag.
> - ✅ `ipc/server.rs`: vòng lặp phiên per-connection (trước đây 1 message/
>   connection); frame sai/replay → đóng kết nối; không có khóa identity →
>   fail-closed (chỉ ERR plaintext rồi đóng — không bao giờ phục vụ envelope
>   qua kênh không xác thực server); bound chặn trước cấp phát.
> - ✅ `ipc/pipe_acl.rs`: DACL THẬT qua `SetKernelObjectSecurity` với
>   SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AC)` áp ngay sau tạo instance
>   (trước đây chỉ là descriptor ghi nhớ, chưa áp).
> - ✅ `service.rs` wire khóa identity từ DPAPI vault (`load_or_create_identity`).
> - ✅ 5 test tích hợp pipe thật: roundtrip GetStatus/HeartbeatPing với
>   server_seen_client_pid từ kernel, fail-closed không-key, replay đóng
>   kết nối, frame quá hạn mức đóng, downgrade version bị từ chối; + 5 unit
>   test handshake (MITM thay PK, pin sai khóa, downgrade, decode).
> - ⏳ **P1-1b (còn lại): phía Python UI** — client handshake + AEAD frames
>   (crate `cryptography` có sẵn ChaCha20Poly1305) + pin khóa agent + verify
>   `server_seen_client_pid`. Cho tới khi P1-1b xong, UI cũ không nói chuyện
>   được với server mới — hành vi hiển thị UI là UNKNOWN fail-closed (an toàn).
> - ⏳ Ghi nhận trung thực: grant DACL cho user console ở chế độ service cần
>   WTS API (hiện SDDL theo plan; dev mode agent chạy dưới user thường).

- [ ] Thêm crate `x25519-dalek`, `chacha20poly1305`, `hkdf` (đã có).
- [ ] Handshake 3 bước trên pipe: `ClientHello(PK_ephemeral)` → `ServerHello(PK_ephemeral, sig Ed25519 của agent)` → derived session key `HKDF(x25519, transcript)`.
- [ ] Agent ký `ServerHello` bằng identity key — client pin public key này (chống MITM/squatting).
- [ ] Thay HMAC-only frame bằng AEAD: `chacha20poly1305` (payload + AAD = header).
- [ ] DACL thật khi tạo pipe: `ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AC)")` qua raw `CreateNamedPipeW` + `tokio::io::unix`-style adapter, hoặc giữ tokio pipe và set DACL qua `SetKernelObjectSecurity` ngay sau `create()`.
- [ ] UI: pin agent public key + verify `server_seen_client_pid`.
- [ ] Test: MITM simulation, replay toàn bộ phiên, downgrade attempt.

### P1-2. Wire AgentDaemon thật vào Windows Service — 3 ngày
- [ ] `service.rs`: khởi tạo `HttpDeviceTransport` (từ config `%ProgramData%\CyberV\agent.toml`) + `WindowsWmiCollector`; chạy `AgentDaemon::tick()` theo `attestation_interval_secs`.
- [ ] Heartbeat log báo **trạng thái thật** của daemon (`AgentState`).
- [ ] `GetStatus` IPC đọc trạng thái thật từ daemon (shared `Arc<RwLock<AgentState>>`).
- [ ] Mock types (`MockDeviceTransport`, `MockHardwareCollector`, `MockTpmProvider`) vào `#[cfg(any(test, feature = "mock"))]` — compiler chặn đưa mock vào production path.
- [ ] Test: service lifecycle + daemon tick trên máy có/không driver.

### P1-3. Telemetry thật thay stub — 5 ngày
Mỗi probe phải gọi Win32 API thật, và khi không gọi được phải trả `is_verified=false` + score 0 (fail-closed):
- [ ] `privilege.rs`: `OpenProcessToken` + `GetTokenInformation(TokenPrivileges)` + `AdjustTokenPrivileges` → kiểm tra `SeDebugPrivilege` đã remove.
- [ ] `process_mitigations.rs`: `GetProcessMitigationPolicy` (ACG, CFG, DynamicCode, ImageLoad, StrictHandle) + `SetProcessMitigationPolicy`.
- [ ] `filesystem_acl.rs`: `GetNamedSecurityInfoW` trên vault + logs dir; xác minh DACL chỉ SYSTEM+Admins.
- [ ] `wdac/ci_verifier.rs`: `NtQuerySystemInformation(SystemCodeIntegrityInformation)` + `SystemCodeIntegrityPolicyInformation` (CI/HVCI/test-signing/debug).
- [ ] `network_surface.rs`: kiểm firewall profile + socket inventory thật.
- [ ] `capability.rs`/`security/capabilities/*`: gắn vào các probe trên, không còn hardcode "present/active/fused".
- [ ] Kiểm chứng: mutation test tạo lại các stub cũ phải làm test fail.

### P1-4. UI/UX không chặn + không lừa — 3 ngày
- [ ] `agent_service.py`: chuyển poll IPC + hardware collect sang `QThread` worker (signals đã có); PowerShell TPM probe cache theo TTL 60s thay vì spawn mỗi 2s.
- [ ] `ipc/client.py`: overlapped I/O hoặc `PeekNamedPipe` loop + deadline cho `ReadFile`.
- [ ] `diagnostics_page.py`: 5 check "PASS" hằng số → chạy probe thật từ P1-3, gắn nhãn `NOT EXECUTED (static)` cho phần chưa có probe.
- [ ] `activation.py`: elevation script cài vào `%ProgramFiles%\CyberV\` với ACL admin-only; hash-verify trước khi elevate; dùng absolute path `%SystemRoot%\System32\sc.exe`, `powershell.exe`; chạy async.
- [ ] Xóa dead-code `create_handshake()` standalone (protocol.py) + sửa test tương ứng.

### P1-5. Chốt hạ chất lượng test — 2 ngày
- [ ] Thay test vô đề `assert!(obs.is_none() || obs.is_some())` bằng fuzz thật: tách parser thành `parse_observation(&[u8], bytes_returned)` pure function + `cargo-fuzz`/`arbitrary` target.
- [ ] Thêm `#[cfg(test)]` unit test cho: policy ladder, admission, staging, version policy (hiện 0 test trong module).
- [ ] `pyproject.toml`/`conftest.py` để pytest chạy được từ mọi thư mục.
- [ ] Xóa test tautology `test_golden_rule_unknown_and_degraded_not_protected`.
- [ ] CI thêm `cargo audit`, `cargo deny` (bỏ `keyring` dependency chết hoặc dùng lại).

**Định nghĩa hoàn thành Phase 1:** với máy đã cài driver, `taskkill` vào agent thất bại; frame IPC không MAC/AEAD sai bị chặn; UI không bao giờ hiển thị PROTECTED khi agent không chạy thật; `cargo test` + pytest xanh; CI build driver thành công.

---

## 3. PHASE 2 — Nền tảng phần cứng thật (Root-of-Trust thực chất)

### P2-1. TPM Base Services thật — 8 ngày
- [ ] `WindowsTbsNvCounter`: `Tbsip_Submit_Command` với `TPM2_NV_ReadPublic` / `TPM2_NV_DefineSpace` (một lần provision) / `TPM2_NV_Increment`.
- [ ] Khi probe TPM thất bại → trả `SoftwareFallback` + event; KHÔNG downgrade im lặng.
- [ ] `TpmIdentityKey` thật: `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)` — chỉ giữ key handle reference; sign qua `NCryptSignHash`; private key không bao giờ vào RAM process.
- [ ] `TpmDetector`: đọc `IsEnabled_InitialValue`/`IsActivated_InitialValue` từ `Win32_Tpm` — TPM disabled → `TpmDegraded` (hiện đang bỏ qua cờ này).
- [ ] Quote: `verify()` nhận `expected_attestation_key` pin từ enrollment record.
- [ ] Test: máy có TPM thật (fTPM OK) + máy không TPM phải cho 2 assurance levels khác nhau.

### P2-2. Kernel quan sát phần cứng thật — 8 ngày
- [ ] `CyberVCollectPciTopology`: BDF thật từ tên khóa registry (parse `VEN_xxxx&DEV_xxxx&SUBSYS_...&REV_...` + vị trí `\PCI\` path thay vì index), `DeviceClass` từ config space (`BUS_INTERFACE_STANDARD`/`HalGetBusData`) — hiện hardcode `0x01` cho mọi thiết bị.
- [ ] `SerialNumber`: lấy qua `IOCTL_STORAGE_QUERY_PROPERTY` (StorageDeviceProperty) cho disk controller — mở khóa nhánh "WMI Spoofer Detection" hiện đang dead code.
- [ ] `cross_validator.rs`: track `matched_count`; 0 thiết bị kernel khớp → `Unknown`/`is_hardware_verified=false` (hiện trả `Consistent` vô điều kiện).
- [ ] Test trên VM + máy thật; so khớp WMI vs kernel trên ≥ 5 máy vật lý khác nhau.

### P2-3. Topology & temporal thật — 5 ngày
- [ ] `evidence/topology/`: SMBIOS Type 16/17 cho memory slots thật, `Win32_PnPEntity` cho PCI hierarchy — bỏ topo bịa với score 10000.
- [ ] `evidence/temporal/collector.rs`: `WindowsStorageCollector` hiện trả `None` vĩnh viễn — wire SMART qua `IOCTL_STORAGE_QUERY_PROPERTY` + `StorageDevicePredictiveFailure` hoặc `Win32_DiskDrive` WMI.
- [ ] Temporal anomaly: dùng nguồn thời gian monotonic (boot-time + TPM-anchored session), báo riêng anomaly "clock moved backwards", aggregate tất cả anomaly thay vì early-return.

### P2-4. Chống rollback & ràng buộc đĩa khởi động — 3 ngày
- [ ] `risk/engine.rs`: đánh dấu storage node boot/primary (`Win32_DiskDrive.Index` + partition info) — đĩa boot thay đổi phải `RequiresUserApproval`, không thể `AutoPromote` như hiện tại (storage mutation 2500 điểm ≤ 3000 threshold).
- [ ] `PendingCommitMarker` thêm HMAC bằng key DPAPI-protect + bind TPM counter generation.
- [ ] NTDLL baseline refresh (syscall/baseline.rs): yêu cầu candidate được ký bằng release key (sau C7) hoặc hash-pin per (OS build, ntdll version).

### P2-5. Canonical & Merkle chuẩn hóa — 4 ngày
- [ ] `CanonicalEncoder`: length-prefix hoặc escape `=`, `\n` — hiện không injective.
- [ ] Merkle tree chuyển đúng RFC 6962 (node split cho odd; không nhân đôi leaf cuối).
- [ ] MMR: enforce leaf/sibling hex-128 trong `verify()`; length-prefix trong peak bagging.
- [ ] Admission policy: canonical signing message chuyển sang length-prefixed (thay `:`-joined) — đồng bộ backend signer.

### P2-6. Driver signing & phân phối — 5 ngày
- [ ] EV certificate / Microsoft hardware dev center attestation signing pipeline; sinh `.cat`.
- [ ] `InfVerif` + `binSkim` vào CI; cài test trên Win10/11 với HVCI bật.
- [ ] SBOM (`cargo auditable`, `syft` cho Python/driver) cho mỗi release.

**Định nghĩa hoàn thành Phase 2:** assurance level phản ánh đúng phần cứng thật (máy không TPM ≠ máy có TPM trên mọi con số báo cáo); snapshot-rollback phát hiện được bằng counter TPM NV thật; WMI spoofer bị bắt bằng dữ liệu kernel; driver build + sign tự động trong CI.

---

## 4. Thứ tự ưu tiên & phụ thuộc

```text
P1-2 (service daemon)  ──┐
P1-3 (real probes)   ────┼──►  GetStatus/heartbeat thật  ──►  UI hiển thị đúng
P1-1 (AEAD channel)  ────┘
P1-4, P1-5 chạy song song (không phụ thuộc backend)

P2-1 (TBS/PCP)      ──► P2-2 (kernel obs) ──► P2-3 (topology/temporal)
P2-4, P2-5 song song;  P2-6 độc lập (chờ EV cert)
```

Ước lượng: **Phase 1 còn lại ≈ 18 ngày-công**, **Phase 2 ≈ 33 ngày-công**.

## 5. Rủi ro & biện pháp

| Rủi ro | Biện pháp |
|---|---|
| Không có WDK trong CI sẽ để C code vô cứu chứng (đã từng xảy ra) | Job `msbuild` WDK là điều kiện merge cho mọi PR chạm `driver/` |
| Thay đổi canonical signing format phá các client đã triển khai | Version bump cả envelope + grace window đọc 2 format |
| TBS API chỉ test được trên máy có TPM | CI matrix: runner không TPM (must fail-closed) + self-hosted runner có fTPM |
| Mock leak vào production quay lại sau refactor | `#[cfg(feature = "mock")]` + clippy lint deny + mutation test check stub cũ |


---

## 6. PHASE 3 & PHASE 4 — ĐÃ THỰC HIỆN (session 2026-10-02, lần 2)

### Phase 3 — CI/CD & chất lượng

| Mục | Kết quả |
|---|---|
| CI build driver WDK | Job `driver-build` (msbuild x64 Release + ABI guard marker) trong `rust.yml` |
| ABI sync test | `agent/tests/kernel_abi_sync_tests.rs`: parse `ioctl.h`, so CTL_CODE (tính tay theo công thức Win32) + `CYBERV_ABI_VERSION` + `ClientAbiVersion` giữa C↔Rust — 4 test |
| Pure parser + fuzz thật | `parse_kernel_observation_bytes()` tách khỏi DeviceIoControl; 8 unit test gồm fuzz 2000 corpus deterministic không panic; test tautology `assert!(x.is_none() \|\| x.is_some())` đã THAY bằng assertion thật |
| cargo-audit + cargo-deny | `deny.toml` (licenses/bans/sources/advisories) + bước CI; bỏ `keyring` dependency chết |
| pytest chạy mọi thư mục | `pyproject.toml` (pythonpath + testpaths) — hết `ModuleNotFoundError` khi chạy từ trong `cyberv_ui/` |
| Unit test in-module | `staging.rs` (6 test, regression M1), `version_policy.rs` (2), `admission.rs` (4: UTF-8 hex panic H4, whitespace invariant M2, cross-field ambiguity M3, tamper), `kernel/client.rs` (8), `protocol.rs` (2 MAC), `manifest.rs` (5), `tree.rs` (3) |

### Phase 4 — Nâng cấp kiến trúc

| Mục | Kết quả |
|---|---|
| Admission canonical signing (M3) | Chuỗi nối `:` → **length-prefixed bytes** (`DOMAIN_POLICY_ADMISSION`); `sign_with()` helper; test chứng minh injective qua field-split |
| Invariant structural check (M2) | `contains("...")` → JSON walk đệ quy bắt cờ nested + whitespace |
| CanonicalEncoder injective (M1) | Escape `\`,`=`,`
`,`` cho `k=v
`; graph encoding escape `\|`,`=`; test injectivity regression |
| Enclave binding (L6) | Combined digest chuyển length-prefixed |
| Merkle RFC 6962 (L7) | Split-node rule: cây n lá chia tại lớn nhất power-of-two < n; **bỏ nhân bản lá lẻ** — hết root-equivalence `[X]` vs `[X,X]` và sibling tự trỏ; 3 test |
| MMR hardening (L8) | `verify()` bắt buộc hex-128 cho mọi leaf/sibling/peak/root; `bag_peaks` prefix độ dài |
| ZK → signed attested claim (H7) | `ZkProof.device_signature_hex`: device identity key ký binding length-prefixed (root/policy/nonce/commitment); verifier check `verify_strict` **trước** khi đốt nonce; test forged-proof-bằng-khóa-lạ bị chặn + nonce không bị đốt |
| Quick-fixes còn lại | M4 clock-rollback → `FreshnessState::Unknown`; M14 saturating counters; M15 clamp composite; H6 VaultShield `NoBaseline` fail-closed; M6 event-bus cap 10000; M7 WDAC XML-escape + `cyberv_signer_tbs` provision-gate (từ chối deploy khi chưa có TBS thật); M9 mock quote hết ký bằng khóa bất kỳ |
| Driver signing | `Docs/DRIVER_SIGNING_RUNBOOK.md`: quy trình attestation signing (EV cert + Partner Center), checklist release, InfVerif, HVCI test |

### Còn lại (đã lập kế hoạch, cần tài nguyên ngoài)

- H5: policy coi metadata None = fresh hoàn hảo — cần thay đổi đồng bộ ~6 test Phase20 (P1-3)
- Service wire AgentDaemon thật + AEAD X25519/ChaCha20 (P1-1, P1-2)
- TBS/PCP thật (P2-1), kernel quan sát PCI/serial thật (P2-2), SMART temporal (P2-3)
- Driver attestation signing — cần EV cert + Hardware Dev Center (xem runbook)
