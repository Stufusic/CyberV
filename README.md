# CyberV: Hardware-Anchored Device Binding & Endpoint Trust Platform

> **Nền tảng xác thực định danh thiết bị và phòng vệ điểm cuối gắn chặt phần cứng (Hardware-Anchored Device Identity & Endpoint Trust) dành cho hệ điều hành Windows.**

CyberV là một giải pháp bảo mật kiến trúc chuyên sâu được thiết kế để liên kết danh tính thiết bị trực tiếp với các linh kiện vật lý và chip bảo mật phần cứng TPM 2.0. Hệ thống kết hợp phân rã đặc quyền đa tiến trình (Broker-Worker Sandbox), kiểm soát toàn vẹn mã hai tầng (Two-Layer Code Integrity) và động cơ chính sách an ninh tự trị ngoại tuyến, giúp bảo vệ các tài nguyên trọng yếu mà không phụ thuộc hoàn toàn vào dịch vụ đám mây hay các giả định an toàn ngây thơ.

---

## 1. Kiến Trúc Tổng Thể

CyberV áp dụng mô hình phân tách ranh giới bảo mật nghiêm ngặt tương tự như kiến trúc Sandbox của Chromium và Windows Virtualization-Based Security (VBS):

```text
                                INTERNET / DASHBOARD
                                         │
                                         ▼
        ┌─────────────────────────────────────────────────────────────────┐
        │            CYBERV WORKER DAEMON (Low Integrity / Sandbox)       │
        │  • Chạy trong AppContainer / Restricted Token                  │
        │  • Giao tiếp Supabase HTTPS, WebSocket, Dashboard IPC           │
        │  • Xử lý và phân tích cú pháp JSON từ bên ngoài                │
        │  • TUYỆT ĐỐI KHÔNG GIỮ PRIVATE KEY, KHÔNG CÓ HANDLE TPM/DRIVER  │
        └────────────────────────────────┬────────────────────────────────┘
                                         │
                        MUTUAL HARDENED IPC CHANNEL
                        • Named Pipe DACL (Chỉ cấp quyền cho Worker SID)
                        • Thẩm định Client Process Authenticode & Token SID
                        • Trao đổi khóa phiên Ephemeral X25519 + ChaCha20
                        • Số thứ tự tuần tự tăng dần (Monotonic Anti-Replay)
                        • Giới hạn kích thước khung nghiêm ngặt (Bounds <= 64 KB)
                                         │
        ┌────────────────────────────────▼────────────────────────────────┐
        │             CYBERV CORE BROKER (High Integrity / SYSTEM)        │
        │  • Giữ độc quyền Identity Vault (Ed25519 Key sealed by DPAPI)   │
        │  • Trực tiếp giao tiếp chip TPM 2.0 (NVRAM Monotonic Counter)    │
        │  • Quản lý Handle kết nối Driver Kernel (\Device\CyberVProbe)   │
        │  • Cổng Thẩm định Tiếp nhận Chính sách (Policy Admission)       │
        │  • Động cơ Phán quyết An ninh Cục bộ Tự trị (Autonomous Engine) │
        │  • ZERO LISTENING SOCKETS, ZERO ARBITRARY INTERNET PARSERS      │
        └─────────────────────────────────────────────────────────────────┘
```

---

## 2. Các Tính Năng Kỹ Thuật Cốt Lõi

### 2.1. Đồ Thị Bằng Chứng Thiết Bị (Tiered Evidence Graph Engine)
* **Quan sát phần cứng đa tầng (SHA-512 FIPS 180-4)**: Thu thập số sê-ri, mã định danh và thông số từ CPU, Motherboard, RAM và Ổ đĩa lưu trữ.
* **Nút ảo & Tỷ lệ bất biến (Virtual Nodes & Virtual Points)**: Chuyển đổi dữ liệu thô thành các cam kết băm và tỷ lệ dung sai topo học. Hệ thống không bao giờ truyền số sê-ri phần cứng trần lên máy chủ hay lưu trữ thô trong cơ sở dữ liệu.

### 2.2. Chống Tua Ngược Trạng Thái Bằng TPM 2.0 (Contradiction Anti-Rollback)
* **Mô hình Khách quan**: Không tuyên bố viển vông rằng ngăn chặn được việc người dùng khôi phục snapshot máy ảo hay clone đĩa. Thay vào đó, CyberV sử dụng chip TPM 2.0 vật lý để thiết lập cơ chế **Phát hiện Bất nhất (Contradiction Detection)**:
  $$\text{Software Version} < \texttt{TPM\_NV\_COUNTER} \implies \text{Snapshot Rollback Detected} \implies \text{Restricted / Lockdown}$$
* **Bốn Cấp độ Đảm bảo (`TpmAssuranceType`)**:
  1. `HardwareBacked`: Discrete TPM 2.0 / fTPM vật lý trên bo mạch.
  2. `VtpmBacked`: Virtual TPM trên máy ảo (ghi nhận snapshot máy ảo có thể lưu kèm vTPM).
  3. `OsProtected`: Khóa được bảo vệ bởi Windows DPAPI khi không có TPM.
  4. `SoftwareFallback`: Bộ giả lập phục vụ kiểm thử tự động.
* **Giao dịch Cập nhật Hai Pha (2-Phase Commit with `PendingCommitMarker`)**: Đảm bảo tính chịu lỗi (crash-resilience) khi mất điện giữa lúc hoán đổi binary và tăng TPM counter, loại bỏ nguy cơ hệ thống tự khóa nhầm máy.

### 2.3. Cổng Thẩm Định Tiếp Nhận Chính Sách (Broker Policy Admission)
* Core Broker **không tin tưởng mù quáng vào Worker**: Mọi chính sách gửi qua lệnh `SubmitPolicyForAdmission` phải vượt qua pipeline thẩm định 6 bước độc lập:
  * Xác thực chữ ký số Master Authority Key (Ed25519).
  * Kiểm tra số phiên bản tăng đơn điệu ($\text{version}_{\text{new}} \ge \text{version}_{\text{current}} + 1$).
  * Kiểm tra thời hạn hiệu lực (`not_before` / `not_after`) và Tenant ID.
  * Kiểm tra quy tắc bất biến: Từ chối bất kỳ chính sách nào có dấu hiệu nới lỏng kiểm tra TPM hay tắt bảo vệ driver.

### 2.4. Hai Tầng Code Integrity (Two-Layer Code Integrity)
* **Tầng A (System Level - WDAC)**: Sinh file chính sách Windows Defender Application Control chuẩn (`CIPolicy.xml`) với nguyên tắc **Audit Mode First** (`AuditMode = true` vs `Enforced`) để kiểm toán tương thích trước khi cưỡng chế. Truy vấn trạng thái HVCI/KMCI của kernel qua `NtQuerySystemInformation`.
* **Tầng B (Process Level - Module Inventory)**: Thường xuyên kiểm toán toàn bộ module DLL nạp trong không gian tiến trình CyberV, xác thực chữ ký Authenticode và phát hiện các DLL lạ không có chữ ký.

### 2.5. Phòng Vệ Thụ Động Cấp Tiến Trình (Process Mitigations)
* Kích hoạt từ cấp OS: Arbitrary Code Guard (ACG), Image Load Restrictions (chỉ nạp DLL của Microsoft hoặc mang chữ ký CyberV), Strict Handle Checks, Vô hiệu hóa điểm mở rộng (Extension Points), Tước bỏ đặc quyền nguy hiểm (`SeDebugPrivilege`, `SeLoadDriverPrivilege`).

### 2.6. Tác Chiến Ngoại Tuyến Tự Trị & Vòng Lặp Tin Cậy (Trust Continuity Loop)
* **Không bao giờ Fail-Open**: Khi offline, mất mạng hay Worker bị cô lập, Broker tự đưa ra phán quyết an ninh cục bộ dựa trên bằng chứng phần cứng; tuyệt đối không tự động nới lỏng (`ALLOW`) khi phát hiện bất thường.
* Khép kín vòng phản hồi liên tục: $\text{Evidence} \to \text{Fusion} \to \text{Policy} \to \text{Recovery} \to \text{Re-Observation} \to \text{Freshness} \to \text{Fusion}$.

---

## 3. Đánh Giá Trung Thực: Ưu Điểm & Nhược Điểm Kỹ Thuật

Nhằm đảm bảo tính minh bạch, khách quan và khoa học, dưới đây là phân tích chi tiết về những gì CyberV làm rất tốt và những ranh giới/giới hạn kỹ thuật thực tế của hệ thống:

### 3.1. Ưu Điểm Thực Tế (Real Strengths)

| Ưu Điểm | Cơ Chế Kỹ Thuật | Ý Nghĩa Thực Tiễn |
| :--- | :--- | :--- |
| **Ràng buộc phần cứng thực thụ** | TPM 2.0 NVRAM Monotonic Counter | Kẻ tấn công không thể sao chép ổ đĩa hay tua ngược snapshot mà không bị phát hiện sai lệch counter. |
| **Giảm thiểu bán kính vụ nổ (Blast-Radius)** | Phân rã tiến trình Broker - Worker | Nếu hacker tìm thấy 0-day RCE trong parser HTTP/JSON của Worker, họ chỉ kiểm soát được tiến trình AppContainer; không lấy được khóa riêng tư, không truy cập được TPM hay Driver. |
| **Chống Fake Policy từ máy chủ** | Broker Policy Admission Control | Kể cả khi server backend bị chiếm quyền và đẩy cấu hình độc hại xuống, Broker vẫn từ chối nếu không có chữ ký Master Key hợp lệ hoặc vi phạm quy tắc bất biến. |
| **Độc lập khi mất mạng** | Autonomous Offline Local Engine | Thiết bị vẫn tự bảo vệ và duy trì chính sách an ninh hoàn hảo khi không có kết nối Internet. |
| **Đồ thị bằng chứng xác định** | Topological Graph + SHA-512 | Thay thế các chuỗi băm cứng nhắc (fragile hash) bằng đồ thị dung sai, cho phép nâng cấp RAM/Disk hợp lệ mà không bị văng thiết bị. |

### 3.2. Nhược Điểm & Giới Hạn Kỹ Thuật (Honest Limitations & Trade-offs)

| Giới Hạn / Rủi Ro | Phân Tích Kỹ Thuật Chi Tiết | Giải Pháp & Khuyến Nghị |
| :--- | :--- | :--- |
| **Giới hạn trên Máy ảo (vTPM Snapshot)** | Khi chạy trên máy ảo (VMware/Hyper-V), nếu hypervisor cấu hình lưu toàn bộ trạng thái vTPM trong tệp snapshot (`.vmsn`), counter vTPM có thể bị tua ngược cùng đĩa. | Mức đảm bảo được hạ xuống `VtpmBacked`. Để đạt tính miễn nhiễm snapshot tuyệt đối, bắt buộc phải triển khai trên máy vật lý có chip TPM 2.0 thực sự (`HardwareBacked`). |
| **Rào cản Chữ ký Driver Kernel** | Driver `CyberVProbe.sys` chạy trong Ring 0 Windows x64. Mặc định Windows 64-bit chặn nạp driver không có chữ ký số WHQL. | Trong môi trường phát triển/thử nghiệm, hệ điều hành phải bật chế độ Test-Signing (`bcdedit /set testsigning on`). Triển khai doanh nghiệp cần chứng chỉ EV Code Signing và chứng nhận Microsoft WHQL. |
| **Rủi ro Khóa máy khi cấu hình sai WDAC** | Chính sách Windows Defender Application Control (WDAC) nếu bật chế độ `Enforced` ngay lập tức có thể chặn các ứng dụng hợp lệ của bên thứ ba hoặc gây lỗi khởi động hệ thống. | Luôn tuân thủ nguyên tắc **Audit Mode First** (`is_audit_mode = true`), theo dõi sự kiện qua Windows Event Log (`Microsoft-Windows-CodeIntegrity/Operational`) ít nhất 2–4 tuần trước khi chuyển sang Enforced. |
| **Tấn công Can thiệp Phần cứng Vật lý (Bus Sniffing)** | Kẻ tấn công chuyên nghiệp có thiết bị đo bus phần cứng (LPC/SPI Interposer) kẹp trực tiếp vào chân chip Discrete TPM có thể nghe lén dữ liệu truyền giữa CPU và TPM nếu không bật parameter encryption. | Cần kết hợp bật TPM 2.0 Parameter Encryption và sử dụng chip TPM tích hợp trong CPU (Intel PTT / AMD fTPM) để bus nằm trọn trong die silicon. |
| **Chi phí Tài nguyên và Bộ nhớ** | Kiến trúc phân rã đa tiến trình, mã hóa kênh IPC, và kiểm toán Authenticode các DLL liên tục tiêu tốn một phần tài nguyên CPU và RAM. | Được tối ưu hóa bằng Rust không có garbage collector, chi phí CPU duy trì ở mức $< 1\%$ trong điều kiện hoạt động bình thường. |

---

## 4. Cấu Trúc Mã Nguồn

```text
CyberV/
├── agent/                  # CyberV Agent viết bằng Rust
│   ├── src/
│   │   ├── defense/        # Hệ thống phòng thủ thụ động & chính sách
│   │   │   ├── passive/    # ACG, Privilege, IPC, Two-Layer WDAC, Isolation
│   │   │   └── policy.rs   # Động cơ chính sách an ninh đa chiều
│   │   ├── fingerprint/    # Đồ thị bằng chứng linh kiện & Topological Graph
│   │   ├── hardware/       # Bộ thu thập dữ liệu phần cứng (WMI / Sysinfo)
│   │   ├── identity/       # Identity Vault (Ed25519, DPAPI, Memory Zeroize)
│   │   ├── kernel/         # Giao tiếp Driver Kernel IOCTL (CyberVProbe)
│   │   └── trust/          # TPM 2.0 NV Counter, PCR Quotes, Measured Boot
│   └── Cargo.toml          # Rust dependencies & package configuration
├── dashboard/              # Ứng dụng Quản trị Hạm đội (React + TypeScript + Vite)
│   ├── src/
│   │   ├── components/     # Overview, Device Fleet, Invariants, Hardware Graph
│   │   └── ...
│   └── package.json
├── driver/                 # Windows Kernel Driver (C / WDK)
│   └── CyberVProbe/        # cybervprobe.sys IOCTL & Anti-Tamper Core
├── scripts/                # Kịch bản tự động hóa (PowerShell)
│   ├── build-dashboard.ps1 # Biên dịch frontend bundle
│   ├── check.ps1           # Chốt chặn kiểm tra toàn diện (Fmt, Clippy, Tests)
│   ├── package.ps1         # Đóng gói tự động bản release
│   └── run.ps1             # Khởi chạy Agent
├── .env.example            # Tệp mẫu cấu hình môi trường
└── README.md               # Tài liệu tổng quan dự án
```

---

## 5. Hướng Dẫn Cài Đặt & Chạy Thử

### 5.1. Yêu Cầu Môi Trường
* **Hệ điều hành**: Windows 10 / Windows 11 (64-bit) hoặc Windows Server 2022+.
* **Phần cứng**: Chip TPM 2.0 (Discrete TPM, Intel PTT hoặc AMD fTPM).
* **Công cụ**: 
  * Rust toolchain (1.80+): `rustup default stable`
  * Node.js (18+) & npm
  * PowerShell 5.1+

### 5.2. Khởi Chạy CyberV Core Agent
Không cần tài khoản, không cần mật khẩu, không yêu cầu license key — hệ thống chạy trực tiếp bằng logic định danh thiết bị cốt lõi:

```powershell
# Chạy trực tiếp Agent thu thập thông số phần cứng và khởi tạo đồ thị:
cd "c:\New PJ\CyberV\agent"
cargo run --bin cyberv-agent
```

### 5.3. Khởi Chạy Web Dashboard
Giao diện quản trị hiển thị đồ thị linh kiện phần cứng, trạng thái bất biến và chứng thực:

```powershell
cd "c:\New PJ\CyberV\dashboard"
npm install
npm run dev
```
Truy cập trình duyệt tại địa chỉ: `http://localhost:5173`

### 5.4. Đóng Gói Toàn Diện (Release Package)
Để đóng gói nhị phân Agent và ứng dụng Web thành gói phân phối độc lập:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1
```
Kết quả được xuất ra thư mục `release/`:
* `release/bin/cyberv-agent.exe`: File thực thi của Agent.
* `release/web/`: Toàn bộ tệp tĩnh của Web Dashboard sẵn sàng phục vụ qua bất kỳ HTTP web server nào.

---

## 6. Giấy Phép & Tuyên Bố Miễn Trừ Trách Nhiệm (License & Legal Disclaimer)

Dự án CyberV được phân phối theo giấy phép mã nguồn mở **[Apache License 2.0](file:///c:/New%20PJ/CyberV/LICENSE)**.

### 6.1 Điều khoản sử dụng & Bản quyền (Copyright Notice)
```text
Copyright (c) 2026 Stufusic and CyberV Contributors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
```
Chi tiết đầy đủ các quyền hạn sao chép, phân phối, sửa đổi mã nguồn và cấp quyền sáng chế được quy định tại tệp [`LICENSE`](file:///c:/New%20PJ/CyberV/LICENSE).

### 6.2 Miễn trừ trách nhiệm kỹ thuật & An ninh (Disclaimer of Warranty & Limitation of Liability)
1. **Mục đích nghiên cứu & Thực nghiệm**: CyberV được xây dựng phục vụ nghiên cứu kiến trúc an ninh điểm cuối cấp cao (High-Assurance Endpoint Security), chống giả mạo định danh thiết bị và phân tích tính toàn vẹn hệ thống.
2. **Cảnh báo tương tác cấp thấp (Low-Level Systems & Kernel)**: Phần mềm tương tác trực tiếp với các giao diện phần cứng và hệ điều hành cấp sâu (Windows TBS TPM API, Named Pipe DACL, WMI/PCI Hardware Bus, Windows Defender Application Control - WDAC, và tùy chọn Kernel Driver).
3. **Giới hạn trách nhiệm**:
   - Phần mềm được cung cấp trên nguyên tắc **"NGUYÊN TRẠNG" (AS IS)**, **KHÔNG CÓ BẤT KỲ BẢO ĐẢM NÀO DÙ RÕ RÀNG HAY NGỤ Ý**.
   - Nhóm tác giả và người đóng góp **hoàn toàn không chịu trách nhiệm** đối với bất kỳ khiếu nại, thiệt hại trực tiếp, gián tiếp, ngẫu nhiên hoặc hậu quả nào (bao gồm sự cố mất dữ liệu, lỗi khởi động hệ điều hành (BSOD/boot failure), khóa tiến trình do cấu hình sai WDAC, gián đoạn kinh doanh hoặc hỏng hóc phần cứng) phát sinh từ việc sử dụng, triển khai hoặc chỉnh sửa mã nguồn này.
   - Người vận hành có nghĩa vụ kiểm thử kỹ lưỡng trên môi trường cô lập (Sandbox/Staging) và luôn tuân thủ nguyên tắc *Audit Mode First* trước khi áp dụng bất kỳ chính sách cưỡng chế (Enforcement) nào.

