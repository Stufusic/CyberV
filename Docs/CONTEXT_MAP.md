# CyberV — Context Map (Bản đồ Module)

> **EN: A dense, retrieval-friendly map of every core module: purpose, key
> types, test entry points, and dependencies. Written for AI assistants and
> engineers doing targeted work — facts only, no narrative.**
>
> Ký hiệu trạng thái: ✅ thật · ⚠️ mô phỏng một phần · ❌ kế hoạch.
> Trạng thái chi tiết từng module nằm trong README của module đó
> (xem `Docs/DOCUMENTATION_PLAN.md` §5-6).

---

## Workspace layout

```text
agent/            Rust workspace member: cyberv-agent (lib + bins: cyberv-agent, cyberv-keygen)
driver/CyberVProbe/  KMDF kernel driver (C): CyberVProbe.sys
cyberv_ui/        PySide6 desktop app (người dùng cuối)
backend/          Supabase Edge Functions (TypeScript): auth/challenge/verify-state/enroll...
database/         Supabase Postgres migrations + RLS
dashboard/        Vite web dashboard (fleet view)
scripts/          PowerShell: build/package/sign/install + mutation testing
```

---

## agent/src (Rust — lib `cyberv-agent`)

| Module | Mục đích | Type/trait chính | Test | Phụ thuộc | Trạng thái |
|---|---|---|---|---|---|
| `daemon` | State machine tự hành: enroll → attest → detect mutation → re-enroll; offline grace | `AgentDaemon<T,C>`, `AgentState` | `phase6_transport_daemon.rs` | transport, hardware, fingerprint | ✅ logic; ✅ wired vào service qua `daemon_runner` (P1-2, config-gated) |
| `defense` | Tầng phòng vệ tổng hợp: policy engine + passive coordinator | `SecurityPolicyEngine`, `PassiveDefenseReport` | `phase20_fusion_policy_engine.rs`, `phase24h` | mọi submodule passive | ✅ fail-closed (INV-001) |
| `defense::passive::ipc` | Named pipe server UI↔agent: bắt tay X25519 1-chiều (client pin agent), phiên AEAD ChaCha20-Poly1305, replay window, DACL thật (SetKernelObjectSecurity), allowlist PID kernel | `NamedPipeServer`, `IpcProtocolValidator`, `pipe_session` | `ipc_session_tests.rs` + in-module `protocol.rs` tests | tokio, windows-sys, mesh::session | ✅ P1-1a (agent side); ⚠️ UI Python P1-1b; GetStatus đọc snapshot daemon thật |
| `defense::passive::isolation` | Broker/Worker privilege separation + admission chính sách | `CoreBroker`, `NetworkWorkerDaemon`, `BrokerPolicyAdmissionController`, `compute_frame_mac` | `phase24h` Group F-I + in-module | ed25519, hmac | ✅ MAC bắt buộc trước sequence (INV chặn signing oracle) |
| `defense::passive::update` | Secure update: manifest gate, hai-phase staging, version policy, authority pinning | `UpdatePackageManifest`, `UpdateStagingManager`, `verify_update_manifest` | `phase24e`, in-module 3 file | ed25519, sha2 | ✅ gate fail-closed; ❌ hạ tầng feed ở M1 |
| `defense::passive::syscall` | Baseline ntdll + hook/stub integrity | `StubIntegrityChecker` | `phase24h` | — | ⚠️ baseline refresh chưa được ký (P2-4) |
| `defense::passive::wdac` | WDAC CIPolicy generation + module inventory + CI/HVCI query thật | `WdacPolicyGenerator`, `CodeIntegrityVerifier` (NtQuerySystemInformation) | `phase24h` Group K-M | ntdll | ✅ CI probe thật; TBS provision-gate ✅ |
| `defense::kernel` | Anti-tamper quản lý: registration, telemetry, vault shield | `AntiTamperManager`, `ProtectedProcessRegistration`, `VaultShield` | `phase16`, `kernel_security_*` | kernel::client | ✅ FILETIME thật; ⚠️ driver runtime chưa verify |
| `defense::recovery` | Recovery lifecycle: PCR transition, re-attestation challenge | `RecoveryManager`, `RecoveryChallenge` | `phase22`, `kernel_security_audit_tests` | ed25519 | ✅ fallback đã xóa (INV-003) |
| `evidence` | Đồ thị bằng chứng: merkle, constraints vật lý, temporal, topology | `MerkleEvidenceTree`, `PhysicalConstraintEngine` | `phase10`, `phase12` | fingerprint | ⚠️ topology bịa (P2-3); temporal collector trả None |
| `evidence::merkle` | Merkle RFC 6962 split-node + inclusion proof | `build_balanced_tree`, `MerkleInclusionProof` | in-module `tree.rs` tests | sha2 | ✅ |
| `fingerprint` | Canonical encoding + component hashing + evidence graph | `CanonicalEncoder`, `hash_snapshot`, `build_evidence_graph` | `component_hasher.rs` tests, `phase10` | sha2 | ✅ encoding injective |
| `hardware` | Collector + normalizer (WMI/sysinfo/mock) | `HardwareCollector` trait, `normalize_storage` | `phase10`, in-module normalizer | sysinfo, wmi | ⚠️ `WindowsWmiCollector` có; mock dùng ở đường run mặc định (P1-2) |
| `identity` | Vault DPAPI + keypair + Secret32 | `Secret32`, `DeviceIdentityKey`, `PersistedIdentity` | `phase4_security_matrix.rs` | windows-sys DPAPI | ✅ zeroize (INV-008) |
| `defense::passive::privilege` | Tước SeDebug/SeLoadDriver/SeTcb thật qua token API | `PrivilegeManager::inspect_and_drop_dangerous_privileges` | `phase24b` | advapi32 | ✅ (P1-3) |
| `defense::passive::process_mitigations` | Set+GetProcessMitigationPolicy thật (ACG/CFG/ImageLoad/...) | `ProcessMitigationManager`, `score_from_flags` | `phase24a`, in-module | kernel32 | ✅ (P1-3) |
| `defense::passive::filesystem_acl` | DACL audit thật (GetNamedSecurityInfoW + ACE scan) | `FilesystemAclManager::audit_path` | `phase24b` (gồm tamper test SDDL thật) | advapi32 | ✅ (P1-3) |
| `defense::passive::network_surface` | Listener enumeration + firewall registry thật | `NetworkSurfaceInspector::audit_network_surface` | `phase24c` (gồm listener test thật) | iphlpapi | ✅ (P1-3) |
| `defense::passive::capability` | Ma trận năng lực từ probes thật + CPUID CET | `CapabilityProfiler` | `phase24a` test_01 | — | ✅ (P1-3); CET kernel-policy probe ở P2 |
| `kernel` | IOCTL client + pure parser + cross-validator | `WindowsKernelClient`, `parse_kernel_observation_bytes`, `CrossLayerValidator` | `kernel_abi_sync_tests.rs`, in-module 8 tests | windows-sys | ⚠️ parser ✅; kernel data bịa phía driver (P2-2); cross-validator matched_count=0→Consistent (mở) |
| `mesh` | NSG: đồ thị node bounded + event ký + quorum independence + epoch/merge + session AEAD + gossip/shadow/ranking (NSG-1.x/2/3) | `MeshGraph`, `NsgEvent`, `evaluate_quorum`, `EpochTracker`, `ReputationLedger`, `MeshSession`, `Initiator`/`Responder`, `GossipInbox`, `ShadowLedger`, `rank_suspect` | `mesh_graph_tests.rs`, `mesh_quorum_tests.rs`, `mesh_consistency_tests.rs`, `mesh_session_tests.rs`, `mesh_gossip_tests.rs` + in-module | ed25519, sha2, x25519-dalek, chacha20poly1305, hkdf | ✅ pure logic + session AEAD + gossip/shadow/ranking (test MITM/replay/flood/TCP-loopback); ⚠️ mDNS socket + wiring daemon là NSG-2b; kế hoạch `Docs/NETWORK_SECURITY_GRAPH_PLAN.md` |
| `privacy` | Selective disclosure + ZK signed attested claim | `ZkProver`, `ZkVerifier`, `SelectiveDisclosureEngine` | `phase15` | ed25519 | ⚠️ "ZK" là signed claim có chữ ký device key (H7 fixed), không SNARK |
| `protocol` | Wire format cho chữ ký: challenge/enroll/reenroll/key_rotation | `create_challenge_proof`, `create_enrollment_request` | `phase6`, `phase8` | ed25519 | ✅ domain-separated + length-prefixed |
| `risk` | Chấm điểm hardware mutation → quyết định promote/approve/reject | `RiskMatrixEngine` | `phase5_risk_matrix.rs` | fingerprint | ⚠️ boot-disk swap chưa đánh dấu (P2-4) |
| `security` | Assurance levels, freshness metadata | `AssuranceLevel`, `EvidenceMetadata` | `phase15_5` | — | ✅ |
| `transport` | HTTPS client + mock cho server API | `HttpDeviceTransport`, `DeviceTransport` trait | `phase6` | reqwest | ✅ HTTPS bắt buộc; ⚠️ response size limit chưa có (L11) |
| `transparency` | MMR + signed checkpoint + revocation verifier | `MerkleMountainRange`, `RevocationVerifier` | `phase13` | ed25519 | ✅ pinned-key verify; ⚠️ hex-128 + length-framing đã harden |
| `trust` | Tầng TPM: detector/provider/quote/NV counter | `TpmNvCounter` trait, `WindowsTbsNvCounter`, `TpmIdentityKey` | `phase11`, `phase24h` | — | ⚠️/❌ toàn bộ là mô phỏng báo trung thực — TBS/PCP thật ở P2-1 |
| `bin/cyberv-keygen` | Tool offline: sinh key authority + Shamir 2-of-3 + ký manifest | — | in-module 5 tests + E2E | ed25519, zeroize | ✅ |
| `daemon_runner` | Chạy AgentDaemon thật trong service/CLI, bơm snapshot cho IPC | `daemon_tick_loop`, `run_configured_daemon`, `AgentStatusSnapshot` | in-module tests | kernel probe | ✅ (P1-2) |
| `service_config` | Nạp `agent_config.json` (URL/anon_key/JWT/interval), validate fail-closed | `AgentServiceConfig` | in-module 6 tests | — | ✅ (P1-2) |

---

## driver/CyberVProbe (C — KMDF)

| File | Mục đích | Lưu ý an ninh | Trạng thái |
|---|---|---|---|
| `driver.c` | DriverEntry, IOCTL dispatch, PCI enumeration, SDDL device | Buffer check nghiêm ngặt; `ClientAbiVersion` check; caller==PID của chính nó | ⚠️ chưa compile trong CI — job `driver-build` sẽ xác minh; topology PCI bịa (P2-2) |
| `ob_callbacks.c` | ObRegisterCallbacks process+thread, SetProtectedProcess kernel-side create-time | Strip mask mở rộng; chặn ghi đè registration; PID-reuse anchor là FILETIME kernel-captured | ⚠️ như trên; logic đã sửa theo audit |
| `ioctl.h` | ABI contract C | `#pragma pack(1)`; phải mirror Rust `kernel/client.rs` — test `kernel_abi_sync_tests.rs` chặn drift | ✅ đồng bộ |
| `CyberVProbe.inf` | Cài đặt | `KmdfService` binding đã bổ sung | ⚠️ cần InfVerif + signing (runbook) |

## cyberv_ui (Python — PySide6)

| Package | Mục đích | Test | Trạng thái |
|---|---|---|---|
| `ipc/` | Named pipe client (ctypes), protocol bounds | `test_adversarial_ipc.py` | ✅ handshake verify nonce echo; ⚠️ blocking read không deadline (P1-4) |
| `security/` | `display_policy.resolve_display_state` — gatekeeper bất biến hiển thị | `test_state_mapping.py`, `test_ui_mutations.py` | ✅ fail-closed (UNKNOWN không bao giờ thành PROTECTED) |
| `services/` | `AgentServiceProvider` (poll agent), activation (UAC) | chưa có (P1-4) | ⚠️ defaults fail-closed đã vá; UAC script path cần Inno installer (F9) |
| `viewmodels/` | State per page (dashboard/recovery/diagnostics) | một phần | ⚠️ diagnostics còn 5 check PASS tĩnh (F7 — P1-4) |

## backend + database (Supabase)

| Thành phần | Mục đích | Trạng thái |
|---|---|---|
| `functions/challenge` | Phát nonce có rate limit | ✅ |
| `functions/verify-state` | Verify chữ ký + consume challenge nguyên tử | ✅ RPC param đã sửa + rate limit |
| `functions/enroll`, `key-rotate` | Đăng ký / xoay khóa | ✅ |
| `database/migrations` | Schema + RLS + SECURITY DEFINER functions | ✅ migration 000003 khóa EXECUTE; ⚠️ **chưa apply lên Supabase thật** |
| `rate_limiter.ts` | In-memory sliding window | ⚠️ per-isolate (giới hạn thật nhân theo số isolate) |

## dashboard (Vite web)

Fleet view công khai; không giữ secret (dùng `import.meta.env` Supabase anon). ✅

---

## Điểm vào kiểm thử nhanh (test entry points)

```bash
cargo test --workspace --release          # toàn bộ 534+ test Rust
cargo test --release --test phase24h      # kiến trúc hardening (Groups A-Q)
cargo test --release --lib                # unit test in-module
python -m pytest -q                       # 30 test UI (chạy từ repo root)
cargo clippy --workspace --all-targets -- -D warnings
```
