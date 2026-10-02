# CyberV — Kế hoạch Phát triển Pipeline & Tăng cường Bảo mật Ứng dụng

> Phạm vi: (A) Pipeline CI/CD → Release → Phân phối cập nhật tự động;
> (B) Backlog tăng cường bảo mật cho app (agent + driver + UI + backend).
> Bối cảnh: đã hoàn tất audit toàn diện + vá critical + Phase 1/2/3/4
> (xem `Docs/PHASE1_2_IMPLEMENTATION_PLAN.md`). Tài liệu này là bản kế hoạch
> triển khai tiếp theo, neo vào các script/workflow **đã có sẵn** trong repo.

---

## 0. Hiện trạng (Gap Analysis)

### Đã có
| Thành phần | Trạng thái |
|---|---|
| CI test (Rust 526 test + pytest 30) | ✅ `rust.yml` — chạy mỗi PR |
| CI build driver (WDK msbuild + ABI guard) | ✅ job `driver-build` |
| cargo-audit + cargo-deny | ✅ bước CI (deny.toml) |
| Build scripts | ✅ `scripts/build-driver.ps1`, `build-ui.ps1`, `build-dashboard.ps1`, `package.ps1` |
| Driver test-signing | ✅ `scripts/sign-driver.ps1` (self-signed, chỉ máy dev) |
| Update gate phía agent | ✅ manifest Ed25519 + `verify_package_binding` (đã vá C2) |
| Security policy | ✅ `SECURITY.md` (48h acknowledge, coordinated disclosure) |
| Mutation testing | ⚠️ `run_mutation_tests.ps1` — chạy THỦ CÔNG, chưa vào CI |

### Thiếu (mục tiêu của kế hoạch này)
| Gap | Rủi ro hiện tại |
|---|---|
| **Release pipeline**: không có workflow release tự động; `package.ps1` chạy tay | Build release không tái lập, dễ lệch giữa các máy |
| **Ký số binary production**: agent.exe + CyberV-UI.exe KHÔNG được ký | SmartScreen cảnh báo; attacker có thể thay binary; không có provenance |
| **Driver attestation signing**: chỉ có test-signing | Driver không nạp được trên máy thật có HVCI |
| **SBOM + artifact attestation** | Không đáp ứng được câu hỏi "release này chứa gì" khi có CVE mới |
| **Kênh cập nhật tự động** | Manifest gate phía agent sẵn sàng nhưng **không có hạ tầng phát hành** |
| **Tái lập (reproducibility)**: không pin toolchain, không `--locked` trong package | Hai lần build ≠ nhau → không verify được hash |
| **Bảo vệ workflow**: `GITHUB_TOKEN` mặc định full quyền, không environment approval | Compromise CI = compromise release |
| **CODEOWNERS**: thư mục `driver/` không yêu cầu review riêng | PR chạm Ring-0 không cần người phụ trách kernel duyệt |

---

## Phần A — Pipeline phát triển (CI/CD → Release → Update)

### A.1 Kiến trúc pipeline mục tiêu

```text
 PR ──► [S0] Gate CI (đã có + bổ sung)
          ├─ cargo fmt --check, clippy -D warnings
          ├─ cargo test --workspace + pytest
          ├─ driver-build (msbuild + ABI guard)     [CODEOWNERS: driver/]
          ├─ cargo-audit + cargo-deny
          ├─ NEW: cargo-machete (dep chết), llvm-cov (coverage gate ≥ 60%)
          └─ NEW: actionlint + zizmor (lint workflow, chống prompt-injection)
                    │
 main ─► [S1] Nightly/merge build
          ├─ Build matrix (agent + UI + driver)
          ├─ Upload artifact có tên versioned + SHA512SUMS
          └─ NEW: mutation testing tự động (run_mutation_tests.ps1) — nightly
                    │
 tag v* ─► [S2] Release pipeline (workflow `release.yml`)
          ├─ Build --locked với toolchain pin (rust-toolchain.toml)
          ├─ Sign: cyberv-agent.exe, CyberV-UI.exe (Authenticode/EV)
          ├─ Driver: attestation signing qua Partner Center (từ runbook)
          ├─ InfVerif + signtool verify
          ├─ SBOM: cargo auditable (Rust) + syft (PyInstaller exe)
          ├─ Sinh signed release manifest (Ed25519 — đúng format mà agent
          │   đã verify: UpdatePackageManifest { version, package_sha512,
          │   release_key_id, manifest_signature_hex, target_arch })
          ├─ Package: zip + installer (WiX/Inno — quyết định D.2)
          └─ GitHub Release (draft) + approval 2 người mới publish
                    │
          [S3] Kênh cập nhật tự động
          ├─ Upload package + signed manifest lên Supabase Storage
          │   (hoặc GitHub Releases — quyết định D.3)
          ├─ Edge Function mới `update-feed`: trả manifest mới nhất theo
          │   version/arch, kèm staged rollout (flag theo device cohort)
          └─ Agent: poll update-feed → verify gate → staged → commit
                    │
          [S4] Sau phát hành
          ├─ Giám sát: crash rate (opt-in WER), update success rate
          └─ Incident runbook: rollback = publish lại manifest version cũ
              (agent PHẢI accept downgrade có chữ ký authority — lưu ý
               version_policy hiện từ chối downgrade; cần "recovery
               downgrade" ký riêng bởi authority, xem B2-U1)
```

### A.2 Bổ sung gate CI (S0) — làm ngay, chi phí ~0

1. **Pin toolchain**: thêm `rust-toolchain.toml` (channel 1.98.1) — mọi build
   (dev/CI/release) cùng compiler, tiền đề của reproducible build.
2. **Clippy nghiêm ngặt**: bước CI thêm `cargo clippy --workspace --all-targets -- -D warnings`
   (hiện 12 warning cũ — dọn 1 lần rồi chặn vĩnh viễn).
3. **`cargo machete`**: phát hiện dependency khai mà không dùng (kiểu `keyring`
   đã bị phát hiện và bỏ — tự động hóa việc này).
4. **Workflow hardening**: `permissions: contents: read` ở mức job; pin
   actions theo SHA full (không dùng tag); chạy `zizmor`/`actionlint` cho
   chính các file workflow.
5. **CODEOWNERS**: `driver/` + `agent/src/kernel/` + `agent/src/defense/passive/update/`
   yêu cầu review của maintainer kernel; PR chạm 3 thư mục này cần 2 approvals.
6. **Coverage gate (thOptional):** `cargo llvm-cov` publish báo cáo + cảnh báo
   khi coverage giảm > 2% mỗi PR (không chặn cứng giai đoạn đầu).

### A.3 Release pipeline (S2) — skeleton `release.yml`

```yaml
name: Release
on:
  push:
    tags: ["v*"]

permissions:
  contents: read        # token tối thiểu; publish dùng environment

jobs:
  build-release:
    runs-on: windows-latest
    environment: release   # yêu cầu manual approval trên GitHub Environments
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: dtolnay/rust-toolchain@master
        with: { toolchain: "1.98.1" }
      - run: cargo build --release --locked -p cyberv-agent
      - run: msbuild driver\CyberVProbe\CyberVProbe.sln /p:Configuration=Release /p:Platform=x64 /m
      - run: InfVerif /v driver\...\CyberVProbe.inf
      # Ký binary user-mode (quyết định D.1)
      - run: scripts/sign-release.ps1 -Binary target\release\cyberv-agent.exe
      - run: scripts/sign-release.ps1 -Binary dist\CyberV-UI.exe
      # SBOM
      - run: cargo install cargo-auditable && cargo auditable build --release
      - run: syft . -o spdx-json > sbom.spdx.json
      # Manifest cho kênh update — ký bằng Ed25519 release key từ secret
      - run: scripts\generate-update-manifest.ps1 -Version $env:GITHUB_REF_NAME
      - uses: actions/upload-artifact@<pinned-sha>
        with: { name: release-bundle, path: release/ }
  publish:
    needs: build-release
    runs-on: windows-latest
    environment: release-approval   # 2 người duyệt
    steps: [download, tạo GitHub Release draft, đính kèm SHA512SUMS + SBOM]
```

**Nguyên tắc signing:** private key KHÔNG BAO GIỜ nằm trong CI secrets dạng
plaintext. Hai lựa chọn (quyết định D.1):
- **Azure Trusted Signing** (khuyến nghị): CI-friendly, ~$9.99/tháng, key
  nằm trong Azure HSM, support `signtool` trực tiếp; không cần mua EV cert riêng.
- **EV Code Signing cert + HSM/token**: chuẩn truyền thống, cần runner
  self-hosted cắm token hoặc một máy signer trung gian.

### A.4 Kênh cập nhật tự động (S3)

Agent đã có đủ **nửa verify**: `UpdatePackageManifest::verify_signature(pinned
VerifyingKey)` + `verify_package_binding` (đã vá C2). Cần xây nửa phát hành:

1. **Storage**: Supabase Storage bucket `update-packages` (private, Edge
   Function có service role đọc) — tận dụng hạ tầng có sẵn; hoặc GitHub
   Releases nếu muốn đơn giản.
2. **Edge Function `update-feed`** (mới):
   - Input: `device_id`, `current_version`, `target_arch`.
   - Output: manifest mới nhất phù hợp + URL tải (signed URL 15 phút).
   - **Staged rollout**: bảng `update_rollout` (version, cohort_percent);
     cohort = hash(device_id) % 100. 1% → 10% → 50% → 100%, có nút dừng.
   - Rate limit + chỉ cho thiết bị đã enroll (reuse challenge auth).
3. **Agent loop** (gói P1-2 khi wire daemon): tick 24h → GET update-feed →
   verify manifest (đã có) → tải → `verify_package_binding` → stage →
   hai-phase commit (đã có staging.rs với rollback an toàn đã fix M1).
4. **Rollback khẩn cấp** (B2-U1): thêm cơ chế `EmergencyDowngrade` — manifest
   ký BẰNG CHỮ KÝ RIÊNG của authority cho phép version giảm (khác đường update
   thường). Không có nó, bản release lỗi chỉ có thể vá tiến (xấu khi bản mới
   chính nó gây crash loop).

### A.5 Bảo vệ quy trình phát hành

- **Environment approvals**: publish release yêu cầu ≥ 2 maintainer duyệt.
- **Provenance**: GitHub Artifact Attestations (generate-attestation) cho
  mỗi release — người dùng có thể verify artifact sinh từ commit nào.
- **Immutability**: sau publish, tag + release assets không được xóa/thay
  (bật branch protection + rule "do not allow force push").
- **Secret inventory**: `RELEASE_SIGNING_KEY` (Ed25519 update authority)
  chỉ tồn tại ở GitHub Environments secret + bản in offline (shamir/2 người).

---

## Phần B — Backlog tăng cường bảo mật ứng dụng

### B1. Build hardening (ngay, chi phí thấp)

| Mục | Chi tiết |
|---|---|
| **B1-1 Panic policy** | ~~`panic = "abort"`~~ **BỊ LOẠI khi thực hiện M0**: INV-006 (EventBus mutex-poison self-healing) phụ thuộc unwinding qua `catch_unwind`, và `cargo test --release` cho poison test cũng vậy — bật abort sẽ vô hiệu hóa một tính năng an ninh có chủ đích của sản phẩm. Quyết định: giữ unwinding, dựa vào error handling tường minh + SCM restart cho panic thật. |
| **B1-2 Cờ link Windows** | `.cargo/config.toml`: `rustflags = ["-C", "control-flow-guard=yes", "-C", "stack-protector=all"]` cho agent; driver đã có `POOL_NX_OPTIN` (cần gọi `ExInitializeDriverRuntime` khi bắt đầu cấp phát pool). |
| **B1-3 Vệ sinh log** | Bỏ mọi `println!`/`eprintln!` ở production path (chuyển `tracing` + level qua env); grep kiểm `serial`, `signature_hex`, `nonce` không vào log. |
| **B1-4 Crash dumps** | Service đăng ký `SetUnhandledExceptionFilter` → dump có chứa khóa phải tắt hoặc mã hóa; bật `LocalDumps` chỉ cho UI process. |
| **B1-5 Binary hygiene** | `strip = "symbols"` release (giữ PDB upload private để debug), `cargo build --locked`, checksum cố định trước khi ký. |

### B2. Runtime hardening (gắn với P1 còn lại + mục mới)

| Mục | Chi tiết | Tham chiếu |
|---|---|---|
| **B2-1 AEAD channel** | X25519 + ChaCha20-Poly1305 + DACL thật trên pipe (đang HMAC-only) | P1-1 |
| **B2-2 Wire daemon thật** | Service chạy AgentDaemon thật; GetStatus đọc state thật | P1-2 |
| **B2-3 Probe thật** | Thay 7 stub telemetry bằng Win32 API thật, fail-closed | P1-3 |
| **B2-4 Default-deny IPC** | Service cấu hình `with_allowed_client_pids(vec![ui_pid])` — UI handshake trao PID qua kênh đã xác thực | mở rộng C9 |
| **B2-5 Vault lưu trữ** | `FlushFileBuffers` trước rename + tmp name unique (từ audit L4); `VirtualLock` cho trang chứa khóa; kiểm ACL `GetNamedSecurityInfoW` vào probe thật | L4 |
| **B2-6 Update downgrade recovery** | Thêm `EmergencyDowngrade` ký riêng (A.4.4) | mới |
| **B2-7 Anti-tamper mở rộng** | Driver: tự báo heartbeat kỳ 30s; agent vắng heartbeat > 90s → Isolate (hiện chỉ phát hiện khi mở handle) | mới |

### B3. Supply chain (tiếp nối Phase 3)

| Mục | Chi tiết |
|---|---|
| **B3-1 `cargo vet`** | Kiểm duyệt dependency: commit `supply-chain/vet.toml`; CI fail khi thêm dep chưa vet. |
| **B3-2 Pin phiên bản** | `Cargo.lock` commit (đã có) + `pip` dùng hash (`--require-hashes` với requirements.txt tách runtime/dev — hiện đang lẫn). |
| **B3-3 PyInstaller** | CyberV-UI.spec thêm `contents_directory` + verify rằng mock_profiles không ship vào bản production (nhánh `--mock` chỉ dev). |
| **B3-4 Fuzzing nightly** | Job nightly: `cargo-fuzz` (linux runner đủ) cho `parse_kernel_observation_bytes`, `IpcProtocolValidator::parse_and_validate`, `parse_policy_envelope`; treo → issue tự động. |
| **B3-5 Static analysis C** | CodeQL job cho `driver/` (C) + bật `/analyze` trong vcxproj; SDV khi có môi trường WDK đầy đủ. |

### B4. Vận hành & quy trình

| Mục | Chi tiết |
|---|---|
| **B4-1 Threat model** | Viết STRIDE cho 4 boundary: pipe IPC, update channel, DPAPI vault, Ring-0 interface — 1 tài liệu `Docs/THREAT_MODEL.md`, review mỗi major release. |
| **B4-2 Incident runbook** | Quy trình: phát hiện → tách (publish EmergencyDowngrade) → vá → advisory; liên kết SECURITY.md đã có. |
| **B4-3 least-privilege service** | Đánh giá chuyển service từ `LocalSystem` → `LocalService`/virtual account + `SERVICE_SID_TYPE_RESTRICTED`; driver IOCTL đã chặn SYSTEM-only nên agent không cần SYSTEM cho mọi việc — chỉ vault + driver handle. |
| **B4-4 Pen-test checklist** | Chuẩn bị kịch bản test nội bộ trước phát hành: pipe squatting, MITM update, vault transplant, VM clone, thread terminate, malicious update manifest — map thẳng vào adversarial matrix đã có. |

### B5. Kiểm thử độ bền

- Mutation testing vào CI **nightly** (script đã viết tốt — chỉ cần gọi);
  gate: mutation score ≥ 85% cho `defense/`, `update/`, `protocol/`.
- Adversarial matrix phase9 chạy trên **mỗi PR** (hiện đang chạy — giữ).
- Benchmark regression nhẹ: `criterion` cho hot path (fusion scoring) để
  chống DoS hiệu năng vô tình.

---

## Phần C — Lộ trình triển khai

### M0 — Tuần này (0 chi phí, chỉ code/CI)
- [ ] `rust-toolchain.toml` + clippy `-D warnings` (dọn 12 warning cũ)
- [ ] Bổ sung CI: machete, actionlint/zizmor, permissions tối thiểu, CODEOWNERS
- [ ] `release.yml` skeleton (draft, chưa ký) + artifact attestation
- [ ] B1-1/B1-2/B1-3/B1-5 build hardening
- [ ] `Docs/THREAT_MODEL.md` bản đầu

### M1 — Tuần 2-3 (cần quyết định D.1)
- [ ] Azure Trusted Signing (hoặc EV cert) cho agent/UI; tích hợp `sign-release.ps1`
- [ ] Driver attestation signing theo runbook (cần Dev Center account)
- [ ] SBOM + SHA512SUMS + GitHub Release environment approvals
- [ ] `update-feed` Edge Function + bảng rollout + test staged rollout

### M2 — Tuần 4-6 (song song P1 còn lại)
- [ ] B2-1 AEAD channel + B2-4 default-deny IPC
- [ ] B2-2 wire daemon thật + B2-3 probe thật
- [ ] Agent update loop dùng staging hai-phase đã có
- [ ] B2-6 EmergencyDowngrade + rehearsal rollback

### M3 — Tuần 7+
- [ ] B3-4 fuzzing nightly + B3-5 CodeQL C
- [ ] Mutation testing gate ≥ 85% vào CI
- [ ] B4-3 least-privilege service pilot + pen-test checklist nội bộ

### Định nghĩa hoàn thành (DoD) tổng thể
1. Từ tag → bản signed release hoàn toàn tự động, ≥ 2 approval, SBOM kèm theo.
2. Agent trên máy người dùng tự cập nhật qua kênh signed với staged rollout,
   verify fail-closed, rollback rehearsed thành công ≥ 1 lần.
3. Mọi binary shipped (agent, UI, driver) đều verify được provenance.
4. Zero secret plaintext trong CI; signing key nằm trong HSM/Trusted Signing.

---

## Phần D — Các điểm cần quyết định

> **✅ ĐÃ CHỐT (2026-10-02)** — các quyết định dưới đây là chuẩn mực cho M1+:

| # | Câu hỏi | **Quyết định** | Hệ quả triển khai |
|---|---|---|---|
| **D.1** | Phương án ký binary | **EV Code Signing cert + HSM** | - `sign-release.ps1` chạy trên **signing machine** (maintainer cắm HSM token) hoặc **self-hosted runner** có token — KHÔNG BAO GIỜ đưa private key vào GitHub Secrets.<br>- Cùng 1 EV cert dùng cho: ký agent/UI (Authenticode) **và** attestation signing driver qua Partner Center.<br>- release.yml: bước ký đặt sau build, có guard dừng nếu HSM không khả dụng (không publish bản chưa ký). |
| **D.2** | Đóng gói người dùng cuối | **Inno Setup installer** (kèm ZIP portable cho evaluation) | - Installer signed, cài service + driver đúng ACL — khắc phục lỗi UAC-script-trong-path-ghi-được (audit F9).<br>- Inno script `.iss` nằm ở `installer/` (M1). |
| **D.3** | Kênh tải update | **GitHub Releases** | - Package + signed manifest upload vào GitHub Release (draft → publish sau approval).<br>- **Staged rollout vẫn dùng Supabase Edge Function** (dùng lại auth đã có): device hỏi "version tôi phải dùng" → nhận version + tag GitHub Release → tải package từ GitHub → verify manifest Ed25519 cục bộ → staging hai-phase. Model hybrid: **AI quyết định rollout ở Supabase, dữ liệu tin cậy nằm ở chữ ký, hosting không cần tin.** |
| **D.4** | Ai giữ key? | **Key không nằm trên BẤT KỲ server nào** | Xem chi tiết bên dưới ("Key Custody Model"). |

### Key Custody Model (trả lời "ai giữ secret?")

```text
                    ┌─────────────────────────────────────────────┐
                    │  MAINTAINERS (2-of-3, offline)              │
                    │  • Update Authority Key (Ed25519 seed)      │
                    │    - chia 2-of-3, mỗi người giữ 1 share     │
                    │    - tái hợp trên signing machine, khí-gap   │
                    │  • EV cert private key → HSM token vật lý   │
                    └──────────────────┬──────────────────────────┘
                                       │ ký offline, CHỈ xuất artifact đã ký
                                       ▼
┌──────────────┐   manifest đã ký   ┌──────────────────────────────┐
│ GitHub        │ ◄───────────────── │ Signing machine (không online │
│ Releases      │                    │ chung, chỉ đẩy artifact)      │
│ (hosting thu  │                    └──────────────────────────────┘
│ ần, không key)│
└──────┬───────┘
       │ tải package công khai
       ▼
┌──────────────┐   "version nào?"    ┌──────────────────────────────┐
│ Agent trên   │ ◄────────────────── │ Supabase Edge Function        │
│ thiết bị     │  (rollout cohort)   │ (chỉ giữ KEY CÔNG KHAI pin    │
│ (verify chữ  │                     │  sẵn trong code, không secret)│
│  ký CỤC BỘ)  │                     └──────────────────────────────┘
└──────────────┘
```

Nguyên tắc:
1. **GitHub Releases và Supabase KHÔNG giữ bất kỳ private key nào** — cả hai
   chỉ là hosting/coordinator. Tín cậy đến từ chữ ký, không từ server.
2. **Update Authority Key**: sinh trên máy khí-gap, chia 2-of-3; mỗi lần phát
   hành, maintainers ký manifest trên signing machine rồi mới upload. Key
   public được pin trong source agent (`UPDATE_AUTHORITY_PUBLIC_KEY`).
3. **EV cert private key**: nằm trong HSM token vật lý (không thể export),
   dùng trực tiếp qua `signtool` trên máy cắm token.
4. **CI không bao giờ giữ secret dạng private key** — chỉ token với quyền tối
   thiểu (contents: read + release write qua environment approval).
