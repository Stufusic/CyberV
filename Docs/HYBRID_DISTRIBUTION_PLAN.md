# CyberV — Kế hoạch Hybrid C++/Rust + Phân phối Single-EXE (v1)

> **EN: Next-phase plan for the small-team constraint — (1) principled
> C++/Rust language strategy with a strict FFI boundary, (2) single-EXE
> distribution in two tiers (Setup installer with EV-signed driver +
> driverless portable agent for "download and run" on many machines),
> (3) multi-machine operation wired to the NSG mesh plan, (4) re-sequenced
> roadmap R1–R5. Honest engineering note: "optimization" is NOT a reason to
> add C++ — pure-tier benchmarks already show µs-level hot paths; C++ is
> admitted only where the Windows ecosystem demands it (COM/WinRT callbacks,
> native UI shell), behind a pure-extern-C FFI rule.**
>
> Bối cảnh: nhóm nhỏ; người dùng cuối chỉ tải 1 file exe về; chạy trên nhiều
> máy (khớp NSG). Hiện trạng đã có: Rust user-mode (695 test), C/KMDF driver,
> PySide6 UI + PyInstaller spec sẵn, quyết định D.1–D.4 (EV+HSM, Inno,
> GitHub Releases, offline 2-of-3 key).

---

## 1. Chiến lược ngôn ngữ — một ngôn ngữ hệ thống MỖI TẦNG

Nguyên tắc nhóm nhỏ: **mỗi tầng một ngôn ngữ, mỗi biên giới một test suite**.
Thêm ngôn ngữ = thêm 1 biên giới FFI phải bảo trì mãi.

| Tầng | Ngôn ngữ | Lý do / điều kiện |
|---|---|---|
| Kernel driver | **C (KMDF)** — giữ nguyên | Đã audit + đã sửa theo C1–C19; KMDF là C-first; C++ trong kernel (exception table, RAII ẩn) là rủi ro không xứng. C++ chỉ được phép ở driver khi có WDF requirement thật + rationale ghi ở đây |
| Agent core | **Rust** (giữ) | Memory safety, binary tĩnh (static CRT), 1 file exe không phụ thuộc runtime |
| **Shim C++ (mới, có giới hạn)** | **C++20, chỉ 2 chỗ được phép** | (a) WinRT/COM callback API mà Rust painful — vd `WiFiDirectAdvertisementPublisher` (NSG-5 Tier B); (b) native UI shell tương lai NẾU PyInstaller exe quá cồng kềnh. Mỗi ngoại lệ phải rationale tại §1.1 |
| UI | **PySide6 + PyInstaller** (giữ) | Spec `CyberV-UI.spec` đã có; C++/Qt chỉ khi thấy §1.1(b) thỏa |

### 1.1 Quy tắc biên giới FFI (bắt buộc khi có shim C++)

- ABI **extern "C" thuần** — không pass C++ object/exception qua biên giới;
  lỗi trả mã `enum` + message buffer bounded.
- Sở hữu bộ nhớ **một chiều** (ai cấp phát người đó giải phóng); không
  `shared_ptr` qua biên.
- Shim build bằng **`cc`/`cmake` crate trong `build.rs` của agent** — KHÔNG
  thêm CMake/MSBuild project riêng (một hệ build).
- Shim không chứa business logic: chỉ transliteration API — logic nằm trong
  Rust (test được).
- Mỗi hàm shim có 1 test biên giới (Rust gọi vào, assert hành vi + lỗi).
- cargo-deny/machete: shim không thêm crate nào.

### 1.2 Chống churn — "tối ưu" không phải lý do

Số đo NSG-3.5 (plan §11.1): quorum ~2µs, AEAD seal+open ~3µs, ingest
~26µs/event. Nút cổ chai thật của hệ thống là **TPM I/O và mạng**, không phải
CPU user-mode. Bất kỳ đề xuất "viết lại C++ cho nhanh" nào phải kèm benchmark
chứng minh bottleneck nằm ở đoạn code đó (không benchmark, không rewrite).

---

## 2. Single-EXE distribution — người dùng tải 1 file

### Tier A — `CyberV-Setup.exe` (cài đặt đầy đủ)

Inno Setup self-contained (khớp quyết định D.2), EMBED toàn bộ:

| Thành phần | Nguồn | Ghi chú |
|---|---|---|
| `cyberv-agent.exe` (service) | Rust `--release`, static CRT | Không phụ thuộc VCRUNTIME |
| `CyberVProbe.sys` | Driver C/KMDF | **Bắt buộc EV attestation-signed (M1/D.1)** — không chữ ký thì Win11 của người dùng không load được driver; test-signing chỉ dùng dev |
| `CyberVUI.exe` | PyInstaller (onefile hoặc onedir nén) | Kèm Python runtime — người dùng không cần cài Python |
| `agent_public_key.hex` bootstrap | service tự publish (P1-1b) | UI pin khóa agent |

Cài đặt: đăng ký service (SYSTEM) + install/load driver + cài UI + cấp DACL.
1 file tải từ GitHub Releases (D.3), hash publish kèm release.

### Tier B — `CyberV-Portable.exe` (không cài đặt, không driver)

Một Rust exe duy nhất, chạy trực tiếp sau tải về: identity (DPAPI vault) +
mesh (NSG UC-1) + secure update + dashboard local. **Ranh giới trung thực:**
driver vắng → kernel shield OFFLINE, hiển thị trung thực theo INV-007; đây
KHÔNG phải chế độ bảo vệ đầy đủ — là chế độ tham gia mạng lưới + giám sát
user-mode. Tier B chính là cánh cửa "tải về là chạy" cho nhiều máy của nhóm.

**Điều kiện mở Tier A:** M1 (EV signing) — do đó R1 kéo M1 lên trước (§4).

---

## 3. Multi-machine — khớp NSG (không viết mới kiến trúc)

- Enrollment: mỗi máy enroll qua Supabase (rendezvous + verify-state đã có);
  mesh LAN-local qua NSG-2b (mDNS), ngoài LAN qua rendezvous.
- Nhóm nhỏ = test fleet tự nhiên: mỗi thành viên chạy 1 node thật (Tier B
  trên máy cá nhân, Tier A trên máy chính), incident/gossip test được trên
  thiết bị thật thay vì chỉ mesh-sim.
- Dashboard fleet view hiển thị graph + SuspectRank (NSG-3).

---

## 4. Lộ trình tái sắp xếp (R1 → R5)

```text
R1  Packaging spine + M1 EV signing runbook
    — CI build 3 artifact: agent exe (static CRT), UI exe (PyInstaller),
      CyberV-Setup.exe (Inno embed driver+service+UI); driver attestation
      signing (D.1); SBOM + hash publish. Close: installer cài sạch trên
      máy Win11 không dev-tool; UI nói chuyện được agent qua phiên AEAD.
R2  P2-1b: TPM identity key (PCP/CNG route) + wire TbsNvCounter vào daemon
    — freeze gate Trụ 1 còn thiếu đúng mục này (+ rollback protection).
R3  NSG-2b: mDNS discovery + wire vào daemon; Tier B portable ra mắt nội bộ
    — nhóm chạy mesh thật (UC-1 trên máy thật, 2+ node).
R4  P2-2: kernel observation thật (C driver) — nơi DUY NHẤT đụng C++/C mới;
    thin-driver principle giữ nguyên.
R5  H5 (metadata decay) + freeze gate review → mở D2 (detection).
```

Mỗi R có close condition = điều kiện đóng tương tự NSG/PHASE1_2 (test 4 nhóm
+ gate hiệu năng nếu chạm đường nóng).

---

## 5. Những gì plan này KHÔNG làm

1. Không rewrite driver sang C++ (churn + rủi ro kernel, không benchmark chứng minh).
2. Không thêm CMake/MSBuild project mới cho C++ — shim đi qua build.rs.
3. Không Electron/WebView UI; không microservices; không "port sang Linux/macOS"
   trước khi Win fleet chạy thật (TBS/DACL/driver là Win-native — port = viết lại).
4. Không thêm dependency C++ bên thứ ba (Boost/QT cho shim) — std + Win API.

## 6. Rủi ro nhóm nhỏ

| Rủi ro | Giảm thiểu |
|---|---|
| 1 người duy nhất hiểu biên giới FFI | Mỗi shim bắt buộc test biên giới + doc rationale tại §1.1; pair-review khi đụng |
| EV cert chi phí/chậm | D.1 đã quyết; nếu chưa sẵn sàng → Tier B ra mắt trước (không driver), Tier A chờ M1 |
| PyInstaller exe to + chậm khởi động | onedir nén trong Inno; nếu vẫn quá nặng → mới kích hoạt §1.1(b) C++/Qt shell |
| Driver signing portal phê duyệt lâu | Nộp sớm ở R1, song song với R2/R3 |

## 7. Mở đầu

- R1 bắt đầu bằng pipeline build artifact + runbook signing (tách khỏi code path).
- Bất kỳ quyết định thêm/bỏ ngôn ngữ nào sau plan này phải update §1 kèm rationale
  + chấp thuận owner (quy tắc plan-level, giống AGENTS.md cấm danh sách).
