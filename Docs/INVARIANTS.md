# CyberV — Security Invariants (INV-001..008)

> **EN: Machine-checkable security invariants. Each entry states the invariant,
> the exact test proving it, and what change would violate it. AI assistants and
> engineers MUST check this list before proposing changes to protected code.**
>
> Quy tắc: mọi PR chạm mã được một bất biến bảo vệ phải (a) giữ nguyên test
> chứng minh, (b) cập nhật tài liệu này nếu mở rộng phạm vi bất biến.

---

## INV-001 — Fail-Closed Policy
> **EN: The policy engine must never return `Allow` when evidence is missing,
> the driver is gone, or the composite score is below threshold — it must
> Isolate.**

- **Phát biểu:** `SecurityPolicyEngine` trả `Isolate` vô điều kiện khi (a) shield
  không active + có blocked attempts, (b) driver unload attempts > 0, (c) defense
  score ≤ 3000, (d) composite < step_up_threshold. Thiếu bằng chứng ≠ cho qua.
- **Chứng minh:** `agent/tests/kernel_security_audit_tests.rs::test_remediation_01_fail_closed_policy_on_driver_unloaded`;
  `agent/tests/phase20_fusion_policy_engine.rs::test_02_policy_engine_isolate_on_kernel_tamper`
- **Vi phạm nếu:** thêm nhánh trả `Allow`/`StepUp` khi `metadata: None`, driver
  unreachable, hoặc exception/timeout trong đánh giá; thay default score từ 0
  thành giá trị "lạc quan".

## INV-002 — Verification Separation
> **EN: `Unknown` evidence must never be conflated with `Verified` — missing
> driver forces `is_hardware_verified = false`.**

- **Phát biểu:** Cross-validator trả `Unknown` + `is_hardware_verified: false`
  khi driver vắng mặt hoặc không xác nhận được thiết bị nào; không đường nào
  gán `true` nếu không có sự khớp thật từ Ring-0.
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_02_cross_validator_marks_missing_driver_unverified`;
  `agent/tests/phase14_kernel_cross_validation.rs::test_01_driver_unavailable_graceful_fallback`
- **Việc cần làm (đang mở):** khi `matched_count == 0` dù driver có mặt — hiện
  trả `Consistent` (xem `Docs/PIPELINE_SECURITY_PLAN.md` P2-2). Sửa phải giữ
  INV-002: không có sự khớp thật thì không `verified=true`.
- **Vi phạm nếu:** `unwrap_or(true)`, `unwrap_or(10000)`, gán verified từ dữ
  liệu user-mode đơn thuần.

## INV-003 — Asymmetric Recovery
> **EN: Recovery/re-attestation requires a strict Ed25519 signature from the
> admin authority. Every malformed or wrong-key input is rejected.**

- **Phát biểu:** `RecoveryManager::verify_and_re_attest` bắt buộc khóa admin
  đúng 32-byte Ed25519 + `verify_strict` trên thông điệp canonical
  length-prefixed (gồm previous_pcr, nonce, created_at); challenge quá 15 phút
  bị từ chối. KHÔNG tồn tại đường fallback.
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_03_recovery_requires_valid_asymmetric_signature`;
  `agent/tests/phase22_recovery_lifecycle.rs::test_11b_short_admin_key_rejected_without_fallback`,
  `test_11b_expired_recovery_challenge_rejected`
- **Vi phạm nếu:** thêm "legacy/compat path" bỏ qua verify_strict; thu hẹp
  thông điệp ký; tăng TTL mà không có rationale + test.

## INV-004 — Kernel Shielding & ABI
> **EN: The KMDF driver strips dangerous handle rights (process AND thread) for
> the registered agent PID, with kernel-captured create time as the anti-PID-
> reuse anchor; the C↔Rust ABI must never drift.**

- **Phát biểu:** ObCallbacks strip `PROCESS_TERMINATE/VM_READ/VM_WRITE/
  VM_OPERATION/DUP_HANDLE/SET_INFORMATION/SUSPEND_RESUME/CREATE_THREAD/
  SET_QUOTA` và THREAD_* tương ứng; create-time do KERNEL tra cứu
  (`PsGetProcessCreateTimeQuadPart`), client chỉ advisory; đăng ký kiểm tra
  `ClientAbiVersion` và từ chối ghi đè active registration.
- **Chứng minh:** logic test: `agent/tests/phase16_kernel_tamper_resistance.rs`
  (registration binding, PID-reuse); ABI: `agent/tests/kernel_abi_sync_tests.rs`
  (CTL_CODE + `CYBERV_ABI_VERSION` khớp `ioctl.h`); compile gate: job CI
  `driver-build`. **Hạn chế trung thực:** hành vi runtime của driver chỉ xác
  minh được trên máy thật có driver signed — hiện chưa có harness runtime.
- **Vi phạm nếu:** sửa `ioctl.h`/struct mà không sửa mirror Rust (và ngược lại);
  bỏ check `ClientAbiVersion`; thêm bypass `callerPid == 4`; tin start-time do
  client khai.

## INV-005 — Package Staging Gate
> **EN: An update package that has not passed BOTH the pinned-authority Ed25519
> manifest signature AND the SHA-512 binding of the actual package bytes can
> never leave the Staging gate.**

- **Phát biểu:** `UpdatePackageManifest::verify_signature(pinned_key)` là
  Ed25519 thật trên canonical length-prefixed bytes; `verify_package_binding`
  re-hash byte gói thật; hai-phase commit chỉ `CompleteCommit` khi counter TPM
  **và** hash cùng khớp; chưa cấu hình authority key ⇒ mọi update bị từ chối
  (`authority::verify_update_manifest` fail-closed).
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_05_update_staging_guards_unverified_package`;
  `agent/tests/phase24e_update_and_recovery.rs::test_01/02`; in-module:
  `update/manifest.rs` (5 test), `update/staging.rs` (6 test), `update/authority.rs`;
  E2E: `cyberv-keygen` sign/verify/tamper (tài liệu `Docs/KEY_MANAGEMENT.md`)
- **Vi phạm nếu:** bỏ điều kiện hash trong `evaluate_startup_recovery`; mặc định
  chấp nhận khi key authority chưa cấu hình; ký bằng format nối chuỗi thay vì
  length-prefixed.

## INV-006 — Contradiction & Resilience
> **EN: TPM-counter contradiction means immediate lockdown; the event bus must
> self-heal from mutex poisoning without losing queued events.**

- **Phát biểu:** `software_current < tpm_counter` → `ContradictionDetected` →
  Isolate severity tối đa; `EventBus` khôi phục từ mutex poison qua
  `into_inner()` bảo toàn sự kiện đã xếp hàng; hàng đợi có bound 10000.
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_07_startup_recovery_catches_tpm_rollback`;
  `kernel_security_fault_injection_tests.rs::test_mutant_08_mutex_poison_preserves_events`;
  `kernel_security_audit_tests.rs::test_remediation_04_event_bus_recovers_from_mutex_poison`
- **Việc cần làm (đang mở):** counter TPM thật (P2-1) — hiện RAM-mock báo
  `SoftwareFallback`; logic contradiction đã đúng, neo phần cứng chưa.
- **Vi phạm nếu:** `panic = "abort"` (phá unwinding/catch_unwind — đã ghi quyết
  định trong `Cargo.toml`); bỏ `into_inner()` recovery; đổi hướng so sánh counter.

## INV-007 — Telemetry Integrity (Trung thực báo cáo)
> **EN: Defense modules must report the OS-verified flag honestly — a probe
> that cannot run reports `is_verified: false` with score 0, never a fabricated
> healthy result.**

- **Phát biểu:** Probe không chạy được → `is_verified: false` + score 0;
  `GetStatus` IPC trả `UNKNOWN` thay vì hằng số PROTECTED; WDAC policy chưa
  provision TBS bị từ chối deploy; mock provider ký quote bằng đúng khóa yêu cầu.
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_06_phantom_modules_report_verified_flag`;
  `agent/tests/phase24h_architecture_hardening.rs::test_k01/l01` (unprovisioned
  TBS bị chặn, XML escape)
- **Hạn chế trung thực:** phần lớn probe vẫn là stub báo fail-closed (chờ
  P1-3 hiện thực Win32 API thật) — bất biến này **chặn việc gian lận báo cáo**,
  chưa biến stub thành đo được.
- **Vi phạm nếu:** hardcode `is_verified: true`/score 10000 khi không có phép
  đo; trả hằng số trạng thái từ IPC; mock leak vào production path.

## INV-008 — Guaranteed Memory Zeroize
> **EN: Secret key material is zeroized on drop (zeroize crate), redacted in
> Debug, compared constant-time, and never serialized.**

- **Phát biểu:** `Secret32` = `Zeroizing<[u8;32]>` + `ZeroizeOnDrop` + Debug
  redacted + `PartialEq` constant-time; ed25519-dalek bật feature `zeroize`;
  `PersistedIdentity` không derive Serialize; `cyberv-keygen` zeroize seed sau
  tái tạo.
- **Chứng minh:** `kernel_security_audit_tests.rs::test_remediation_08_zeroization_guaranteed_on_drop`;
  `agent/tests/phase4_security_matrix.rs::test_save_load_identity_vault`,
  `test_corrupt_vault_detected`, `test_hardware_change_does_not_destroy_vault`
- **Vi phạm nếu:** derive `Serialize`/`Display` cho type chứa bí mật; in key
  vào log; giữ bản copy seed ngoài `Secret32`; bỏ feature `zeroize` trong
  Cargo.toml.

---

## Quy tắc sử dụng (cho AI + kỹ sư)

1. Trước khi đề xuất change chạm file trong phạm vi một INV ở trên → đọc mục
   "Vi phạm nếu" của INV đó.
2. Sau khi change → chạy đúng bộ test chứng minh (`cargo test --workspace --release`).
3. Mở rộng phạm vi INV (ví dụ thêm INV-009) → cập nhật file này CÙNG PR, kèm
   test chứng minh mới.
4. Không bao giờ xóa/renaming test được liệt kê ở đây mà không có rationale
   trong mô tả PR + chấp thuận CODEOWNERS.

---

## Planned Invariants (từ phản biện kiến trúc roadmap v2 — hiện thực hóa tại cột mốc D1)

Ba bất biến dưới đây **chưa có test** — được liệt kê để (a) ràng buộc thiết kế
sớm, (b) tránh quên. Chúng PHẢI có test trước khi gate D2 mở (xem
`Docs/DEFENSE_ROADMAP.md` §5). Trạng thái: ❌ planned.

### INV-009 (planned) — Testable Honest Signaling
- **Phát biểu:** mọi control/verdict được xuất bản phải mang (a) signal class
  `verified|heuristic`, (b) evidence-ref, (c) repeatable test id. CI gate từ
  chối control đánh ✅ không có test.
- **Nguồn:** phản biện §1 ("Zero Deceptive Signals phải thành invariant kiểm
  thử được") + §4 (ATT&CK coverage 7 cột).
- **Vi phạm nếu:** verdict không ghi signal class; control ✅ không trỏ test;
  pha trộn verified với heuristic khi trình bày.

### INV-010 (planned) — No-Silent-Loss cho Security Event
- **Phát biểu:** event mức L2+ (quyết định hành động) không bao giờ bị drop âm
  thầm: spool-to-disk + loss accounting + degraded mode hiển thị ở GetStatus;
  drop L0 telemetry được phép nhưng phải đếm và báo được.
- **Nguồn:** phản biện §7 (event pipeline single choke point).
- **Vi phạm nếu:** queue bounded đơn giản drop-all; pipeline chết mà GetStatus
  vẫn báo bình thường; mất event L2 không có accounting.

### INV-011 (planned) — Signed Rule Distribution
- **Phát biểu:** detection rules chỉ được phân phối qua kênh update có chữ ký
  (tái dụng INV-005) + schema validation + resource limits (số rule/độ phức tạp)
  + atomic activation + known-good rollback (activation fail → tự revert).
- **Nguồn:** phản biện §3.1 (rules engine không thành scripting engine trá hình).
- **Vi phạm nếu:** rule load không verify chữ ký; rule engine nhận biểu thức
  turing-complete; activation mới không có đường revert.

### INV-012 (planned) — Mesh Channel Fail-Closed (NSG)
- **Phát biểu:** mọi frame mesh có chữ ký Ed25519 identity + AEAD + anti-replay
  (sequence/nonce window). Peer không attest được → tối đa `Discovered`:
  không nhận evidence, không vote, không được hành động vì nó. Frame sai xác
  thực bị drop **và đếm được**. Vote không đủ provenance (thiếu evidence_root /
  obs_channel / signal_class) không vào quorum — chỉ là telemetry L0.
- **Nguồn:** `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2 §5, §14 (INV-012).
- **Hiện trạng (NSG-1 + NSG-2 session):** `mesh::events::NsgEvent::verify`
  chặn event_id không khớp nội dung + chữ ký sai; `Ballot::from_event` trả
  None khi thiếu provenance; `EventLog::accept` chặn replay/hết hạn/epoch bất
  hợp lệ. **Tầng session AEAD đã hiện thực** (`mesh/session.rs`): bắt tay 3
  bước X25519 + chữ ký identity bám transcript, AEAD ChaCha20-Poly1305 hai
  chiều, replay window 128 commit-sau-tag — test chứng minh MITM thay PK,
  downgrade, khóa lạ, reflection đều bị từ chối. Chưa có I/O production:
  mDNS socket + wiring daemon là NSG-2b; DACL pipe vẫn P1-1.
- **Vi phạm nếu:** accept frame không sign/AEAD vì "LAN tin được"; nâng trust
  từ presence thay vì handshake chữ ký; ballot thiếu provenance vẫn vào quorum.

### INV-013 (planned) — Diversity-Aware Action Authority (NSG)
- **Phát biểu:** mọi peer-quarantine cần quorum **pairwise-independent có trọng
  số, cùng epoch**: 5 điều kiện độc lập theo cặp (identity / observation
  channel / evidence root / causal separation — gồm shared causal parent /
  arrival path), tổng TrustScore ≥ ngưỡng, ≥ 1 tín hiệu `verified`. Report đơn
  lẻ chỉ là L0. Node cold-start bị ghim trọng số (cap 150); weight 0 cho peer
  chưa có hồ sơ; vote từ peer bị revoke = 0; stale-epoch vote = 0; shadow mode
  mặc định cho tới khi wrong-action rate đạt ngưỡng benign set.
- **Nguồn:** `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2 §4-§5, §14 (INV-013).
- **Hiện trạng (NSG-1/1.5/3):** `mesh::quorum::pairwise_independent` +
  `evaluate_quorum` + `mesh::reputation` có test chứng minh: sybil farm không
  tự đạt quorum; farm không "chở" được 1 node lành vượt ngưỡng; cùng evidence
  root / cùng causal cha / cùng arrival path đếm một; report sai → decay tới 0.
  **Shadow mode đã hiện thực** (`mesh/shadow.rs`): ShadowLedger ghi đề nghị
  isolate nhưng **không có API thực thi** — `executed` bất biến false, test
  chặn; wrong-action replay feed decay qua caller. Giới hạn hành động thật
  (pilot/auto) là NSG-4 (gate: freeze gate + D2.3 + wrong-action rate đo trên
  benign set).
- **Vi phạm nếu:** quorum đếm node thay vì đếm nguồn độc lập; hai vote cùng
  evidence root đếm kép; vote stale-epoch/cold-start/revoke được tính; bỏ
  cold-start cap; bật auto không qua shadow.

### INV-014 (planned) — Reversible Isolation + Operational Safety (NSG)
- **Phát biểu:** mọi isolation có TTL deadline tuyệt đối (reboot không reset
  vòng đời); isolation không deadline là trạng thái bất hợp lệ — GC ép về
  `Unknown` ngay; auto-lift sau TTL → bắt buộc tái attestation mới lên
  `Attested`; recovery/quorum-downgrade là các đường thoát duy nhất và đều có
  chữ ký; không chạm loopback/IPC. WFP semantics chi tiết ở plan §9.
- **Nguồn:** `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2 §9, §14 (INV-014).
- **Hiện trạng (NSG-1):** `mesh::graph` — `tick_gc` auto-lift (deadline
  inclusive, bão hòa u64::MAX cũng lift), transition xóa TTL mồ côi, test
  chứng minh isolated node không bị stale-GC đụng sớm. Phần WFP thực thi là
  NSG-4.
- **Vi phạm nếu:** TTL vô hạn; rule mồ côi sau reboot; recovery không verify
  chữ ký; isolation chặn chính kênh update của node tự cách ly.

### INV-015 (planned) — Bounded Mesh State (NSG)
- **Phát biểu:** mọi cấu trúc mesh (graph 256 node / 2048 edge, event log,
  ballot window) có bound cứng; vượt → từ chối entry mới + đếm loss hiển thị
  (không âm thầm, không evict ngầm mất bằng chứng).
- **Nguồn:** `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` v2 §8 T10/T11, §14 (INV-015).
- **Hiện trạng (NSG-1):** `MeshGraph` (dropped_node/edge_count), `EventLog`
  (dropped_count, replay/seq chặn), `evaluate_quorum` (flood_dropped). Epoch
  compaction là NSG-1.6+ — hiện event log giữ tới bound rồi từ chối.
- **Vi phạm nếu:** queue unbounded "để chắc"; drop không đếm; bound chỉ nằm
  trong comment.
