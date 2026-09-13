# CyberV: Hardware-Anchored Device Binding & Endpoint Trust Platform

<div align="center">

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust: 1.75+](https://img.shields.io/badge/Rust-1.75%2B_Stable-orange.svg)](https://www.rust-lang.org)
[![Platform: Windows 10/11 x64](https://img.shields.io/badge/Platform-Windows_10%2F11_x64-0078D6.svg)](https://microsoft.com/windows)
[![Crypto: FIPS 180-4 & RFC 8032](https://img.shields.io/badge/Crypto-SHA--512_%2F_Ed25519-green.svg)](https://csrc.nist.gov)
[![Kernel: KMDF 1.15](https://img.shields.io/badge/Kernel-KMDF_1.15_Altitude_385201-red.svg)](driver/CyberVProbe)
[![Tests: 240+ Passing](https://img.shields.io/badge/Tests-240%2B_Passing-success.svg)](agent/tests)
[![Mutation Score: 100%](https://img.shields.io/badge/Mutation_Score-100%25_Killed-brightgreen.svg)](Docs/security_baseline.md)

**Nền tảng xác thực định danh thiết bị và phòng vệ điểm cuối gắn chặt phần cứng (Hardware-Anchored Device Identity & Endpoint Trust) thế hệ mới dành cho Windows.**

[Kiến Trúc](#1-kiến-trúc-tổng-thể) • [Tính Năng Cốt Lõi](#2-các-tính-năng-kỹ-thuật-cốt-lõi) • [Bất Biến An Ninh](#3-ma-trận-bất-biến-an-ninh-core-invariants) • [Khởi Chạy Nhanh](#4-hướng-dẫn-cài-đặt--vận-hành) • [Desktop Native UI](#5-giao-diện-máy-trạm-độc-lập-cyberv-uiexe) • [Dịch Vụ Windows SCM](#6-quản-trị-windows-service) • [Driver Kernel](#7-quy-trình-biên-dịch--ký-số-driver) • [Bảo Mật & Đóng Góp](#10-chính-sách-bảo-mật--đóng-góp)

</div>

---

## 1. Kiến Trúc Tổng Thể

Các phương pháp định danh thiết bị truyền thống (như Browser Fingerprinting, MAC Address, CPU-Z GUID hay Registry Keys) rất dễ bị qua mặt thông qua việc sao chép snapshot máy ảo (VM cloning), tua ngược đĩa (snapshot rollback) hoặc can thiệp bộ nhớ tiến trình (memory patching).

**CyberV** giải quyết triệt để bài toán này bằng cách liên kết danh tính thiết bị trực tiếp với các **cam kết topo học phần cứng vật lý**, bảo vệ bởi **chip TPM 2.0**, niêm phong qua **Windows DPAPI**, và được bảo vệ ở cấp **Ring-0 Kernel** bởi trình điều khiển KMDF:

```text
                                  INTERNET / FLEET DASHBOARD
                                              │
                                              ▼
            ┌─────────────────────────────────────────────────────────────────┐
            │            CYBERV WORKER DAEMON (Low Integrity / Sandbox)       │
            │  • Vận hành trong AppContainer / Restricted Token               │
            │  • Giao tiếp WebSocket / HTTPS với Fleet Dashboard              │
            │  • Phân tích cú pháp ngoại vi an toàn (Zero Arbitrary Parsers)  │
            │  • TUYỆT ĐỐI KHÔNG GIỮ PRIVATE KEY, KHÔNG CÓ HANDLE TPM/DRIVER   │
            └────────────────────────────────┬────────────────────────────────┘
                                             │
                            MUTUAL HARDENED IPC CHANNEL
                            • Named Pipe DACL (Chỉ cấp quyền cho Worker SID)
                            • Thẩm định Authenticode & Process Token SID
                            • Trao đổi khóa phiên Ephemeral X25519 + ChaCha20
                            • Số thứ tự đơn điệu chống tấn công Replay (Monotonic)
                            • Giới hạn kích thước khung dữ liệu nghiêm ngặt (<= 64 KB)
                                             │
            ┌────────────────────────────────▼────────────────────────────────┐
            │             CYBERV CORE AGENT / BROKER (Session 0 / SYSTEM)     │
            │  • Đóng gói thành Windows Service native (SERVICE_AUTO_START)   │
            │  • Cơ chế tự phục hồi SCM Auto-Restart (5s / 10s / 30s)         │
            │  • Độc quyền quản lý DPAPI Vault (Khóa Ed25519 & Salt)          │
            │  • Giao tiếp chip TPM 2.0 (NVRAM Monotonic Counter Anti-Rollback│
            │  • Động cơ Phán quyết An ninh Cục bộ Tự trị (Fail-Closed Engine)│
            │  • Giao tiếp Driver Kernel qua DeviceIoControl đặc quyền        │
            └────────────────────────────────┬────────────────────────────────┘
                                             │
                       RING-0 FAST IOCTL / OB_CALLBACKS INTERFACE
                       • Altitude 385201: Tước quyền Terminate / Memory Access
                       • Chống tấn công PID Reuse qua kiểm tra ProcessStartTime
                       • Hợp đồng ABI chuẩn hóa (CYBERV_ABI_VERSION = 1)
                                             │
            ┌────────────────────────────────▼────────────────────────────────┐
            │         CYBERVPROBE.SYS (Windows KMDF Kernel Driver 1.15)       │
            │  • Thu thập cấu trúc Topology PCI / Bus phần cứng độc lập       │
            │  • ObRegisterCallbacks: Chặn PROCESS_TERMINATE, VM_READ/WRITE  │
            │  • SDDL Device Security: Chỉ cho phép SYSTEM & Admins gửi IOCTL │
            └─────────────────────────────────────────────────────────────────┘
```

---

## 2. Các Tính Năng Kỹ Thuật Cốt Lõi

### 2.1. Đồ Thị Bằng Chứng Thiết Bị (Device Evidence Graph Engine)
* **Băm linh kiện đa tầng (SHA-512 FIPS 180-4)**: Thu thập số định danh, cấu hình và mã sê-ri từ CPU, Motherboard, RAM và ổ đĩa lưu trữ.
* **Topological Graph & Ratios**: Thay vì dùng một chuỗi băm đơn lẻ dễ gãy khi người dùng cắm thêm ổ cứng hay RAM, CyberV xây dựng đồ thị topo học kết hợp các tỷ lệ bất biến xác định (Deterministic Evidence Ratios). Hệ thống **tuyệt đối không truyền số sê-ri thô lên mạng**.

### 2.2. Chống Tua Ngược Trạng Thái Bằng TPM 2.0 (Contradiction Anti-Rollback)
* Sử dụng bộ đếm đơn điệu phần cứng (Hardware NV Monotonic Counter) trong chip TPM 2.0 để thiết lập cơ chế **Phát hiện Bất nhất (Contradiction Detection)**:
  $$\text{Software Version} < \texttt{TPM\_NV\_COUNTER} \implies \text{Snapshot Rollback Detected} \implies \text{Immediate Lockdown}$$
* **Hỗ trợ 4 cấp độ đảm bảo (`TpmAssuranceType`)**: `HardwareBacked` (Discrete TPM 2.0 / fTPM), `VtpmBacked` (Virtual TPM trên Hypervisor), `OsProtected` (Windows DPAPI), và `SoftwareFallback` (môi trường kiểm thử).
* **Giao dịch Hai Pha (`PendingCommitMarker`)**: Bảo vệ hệ thống khỏi tình huống mất điện đột ngột hoặc crash giữa lúc ghi đĩa và tăng counter TPM, loại trừ 100% rủi ro tự khóa máy nhầm.

### 2.3. Lá Chắn Tầng Nhân Ring-0 (KMDF Driver `CyberVProbe.sys`)
* **Process Object Callbacks**: Cài đặt `ObRegisterCallbacks` tại Security Altitude `385201`. Bất kỳ tiến trình nào (kể cả phần mềm chạy dưới quyền Administrator có `SeDebugPrivilege`) cố mở handle can thiệp vào `CyberVAgent` đều bị tước lập tức các quyền nguy hiểm:
  - `PROCESS_TERMINATE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_DUP_HANDLE`, `PROCESS_SET_INFORMATION`, `PROCESS_SUSPEND_RESUME`.
* **Phòng vệ PID Reuse**: Thẩm định thời gian khởi tạo tiến trình (`ProcessStartTime`) kết hợp Spinlock đồng bộ, ngăn chặn kẻ tấn công tái sử dụng PID của Agent vừa tắt để lừa Driver.
* **Quy ước ABI chuẩn hóa**: Hợp đồng mã IOCTL đồng bộ tuyệt đối giữa tầng C (`ioctl.h`) và Rust (`agent/src/kernel/protocol.rs`).

### 2.4. Đóng Gói Dịch Vụ Windows Service Thường Trực (SCM Native)
* Tích hợp sâu với Windows Service Control Manager qua `windows-sys` (feature `"Win32_System_Services"`).
* Chạy ngầm trong **Session 0** dưới quyền `NT AUTHORITY\SYSTEM` (`LocalSystem`), không phụ thuộc vào việc người dùng đăng nhập hay đăng xuất.
* Cấu hình **`SERVICE_AUTO_START`** và chính sách tự phục hồi **SCM Failure Recovery Actions** (tự động khởi động lại sau 5s, 10s, 30s khi tiến trình bị dừng bất ngờ).
* Cơ chế ghi log chuyên dụng Session 0 tại `C:\ProgramData\CyberV\logs\agent_service.log`.

### 2.5. Hai Tầng Kiểm Soát Toàn Vẹn Mã (Two-Layer Code Integrity)
* **Tầng Hệ Thống (WDAC)**: Sinh tệp chính sách Windows Defender Application Control chuẩn (`CIPolicy.xml`) tuân thủ nghiêm ngặt nguyên tắc **Audit Mode First** trước khi kích hoạt chế độ Enforced.
* **Tầng Tiến Trình (Module Inventory)**: Kiểm toán liên tục toàn bộ DLL nạp trong không gian bộ nhớ của CyberV, xác minh chữ ký Authenticode và phát hiện các DLL lạ không rõ nguồn gốc.

### 2.6. Phòng Vệ Thụ Động Cấp Tiến Trình (Process Mitigations)
* Kích hoạt Arbitrary Code Guard (ACG), Image Load Restrictions (chỉ nạp DLL của Microsoft hoặc có chữ ký CyberV), Strict Handle Checks, và tước bỏ các đặc quyền nguy hiểm không cần thiết.

---

## 3. Ma Trận Bất Biến An Ninh (Core Invariants)

Hệ thống được thiết kế xoay quanh 8 bất biến an ninh nền tảng đã được kiểm chứng bằng kiểm thử đột biến mã nguồn (**100% Mutation Score**):

| Bất Biến | Tên & Phạm Vi | Cơ Chế Bảo Vệ Cốt Lõi | Hành Vi Vi Phạm |
| :--- | :--- | :--- | :--- |
| **INV-001** | **Fail-Closed Policy** | Policy Engine bắt buộc đưa ra quyết định `Isolate` khi driver bị gỡ hoặc điểm an ninh $\le 3000$. | **Tuyệt đối không bao giờ Fail-Open** ra kết quả `Allow`. |
| **INV-002** | **Verification Separation** | Phân tách rạch ròi cờ `is_hardware_verified`. Không bao giờ ngộ nhận `Unknown` là bằng chứng đã kiểm chứng. | Thiếu driver $\implies$ gán `false`. |
| **INV-003** | **Asymmetric Recovery** | Quy trình khôi phục và tái cấp quyền bắt buộc phải có chữ ký bất đối xứng Ed25519 từ Master Authority. | Bất kỳ chữ ký sai lệch nào đều bị từ chối 100%. |
| **INV-004** | **Kernel Shielding & ABI** | Trình điều khiển KMDF tước quyền can thiệp tiến trình qua `ObRegisterCallbacks` và gỡ bỏ sạch sẽ khi unload. | Chống Terminate, DLL Injection, PID Reuse. |
| **INV-005** | **Package Staging Gate** | Gói cập nhật phần mềm chưa được xác thực chữ ký và băm cam kết bị chặn tuyệt đối ở cổng Staging. | Trả về `Err("Package unverified")`. |
| **INV-006** | **Contradiction & Resilience** | Phát hiện bất nhất counter TPM lập tức khóa bảo vệ; EventBus tự phục hồi khi Mutex bị nhiễm độc (Poisoned). | Tự cứu hàng đợi sự kiện, không làm treo hệ thống. |
| **INV-007** | **Telemetry Integrity** | Các module kiểm toán tiến trình và đặc quyền báo cáo trung thực cờ `is_verified` từ hệ điều hành. | Ngăn chặn việc làm giả cờ xác minh. |
| **INV-008** | **Guaranteed Memory Zeroize** | Vùng nhớ nhạy cảm chứa khóa bí mật, seed được xóa sạch bằng `zeroize::Zeroize` khi giải phóng (`Drop`). | Chống tối ưu hóa loại bỏ Dead-Store của compiler. |

---

## 4. Hướng Dẫn Cài Đặt & Vận Hành

### 4.1. Tiền Đề Môi Trường (Prerequisites)
* **Hệ điều hành**: Windows 10 (1909+ 64-bit), Windows 11 (64-bit), hoặc Windows Server 2019/2022/2025.
* **Rust Toolchain**: 1.75.0+ (`x86_64-pc-windows-msvc`).
* **Visual Studio Build Tools**: VS 2022 C++ Build Tools và Windows 10/11 SDK.
* **Node.js**: LTS 18+ & npm (để chạy Web Dashboard).
* **PowerShell**: 5.1 hoặc PowerShell 7+.

### 4.2. Khởi Chạy Nhanh CyberV Agent (Chế Độ Tương Tác)
```powershell
# Chạy trực tiếp Agent để quan sát phần cứng và xây dựng đồ thị topo:
cd "c:\New PJ\CyberV\agent"
cargo run --bin cyberv-agent -- run
```

### 4.3. Khởi Chạy Web Dashboard
```powershell
cd "c:\New PJ\CyberV\dashboard"
npm install
npm run dev
```
Truy cập giao diện tại: **`http://localhost:5173`**

---

## 5. Giao Diện Máy Trạm Độc Lập (CyberV-UI.exe)

Bên cạnh giao diện web hạm đội (Fleet Web Dashboard), CyberV cung cấp ứng dụng máy trạm độc lập chuyên dụng viết bằng **Python 3.13 / PySide6 (Qt)** được đóng gói thành tệp thực thi duy nhất:
👉 **`dist/CyberV-UI/CyberV-UI/CyberV-UI.exe`**

```text
┌────────────────────────────────────────────────────────────────────────┐
│               CyberV-UI.exe (Desktop Native Client - Ring-3)           │
│  • Tự động thu thập phần cứng máy thật (CPU, RAM, Mainboard, TPM 2.0)  │
│  • Bảng chẩn đoán kỹ thuật 4 tầng (4-Tier Self-Test Diagnostics)       │
│  • Cổng khôi phục mật mã Ed25519 có thời hạn (Recovery Attestation)   │
│  • Khay hệ thống thông minh (System Tray Dynamic Status & Alerts)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Windows Named Pipe: \\.\pipe\CyberVIPC
                                    │ (Bắt tay mã hóa Nonce Handshake)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               CyberVAgent (Windows Service - Session 0 SYSTEM)         │
│  • Tự khởi động cùng máy tính 24/7 (SERVICE_AUTO_START)                │
│  • Nạp và duy trì kết nối IOCTL với Driver Kernel Ring-0               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ IOCTL Fast Channel (Altitude 385201)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               CyberVProbe.sys (KMDF Filter Driver - Ring-0 Kernel)     │
│  • ObRegisterCallbacks: Chặn Terminate, Read/Write VM bộ nhớ           │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.1. Giải Thích Trạng Thái Ban Đầu Khi Mở Ứng Dụng
Khi người dùng mới tải về hoặc mở trực tiếp `CyberV-UI.exe` trên máy tính chưa cài đặt dịch vụ, ứng dụng sẽ hiển thị:
* Trạng thái chính: **`● LOCAL ASSESSMENT`** *(Lam Sapphire `#58A6FF`)*
* Lá chắn tầng nhân: **`CALLBACK NOT ACTIVE: Kernel object protection is unavailable`** (Driver status: `NOT_INSTALLED`)
* Chẩn đoán 4 tầng: **`[1] DRIVER: FAIL`**, **`[2] CORE AGENT: FAIL`**

> [!IMPORTANT]
> **Triết lý Trung Thực Kỹ Thuật (Technical Truth & Zero Deceptive Signals):**
> Trong kiến trúc bảo mật Windows, một ứng dụng đồ họa User-mode (Ring-3) chạy bằng quyền người dùng thông thường **TUYỆT ĐỐI KHÔNG THỂ VÀ KHÔNG ĐƯỢC PHÉP tự ý nạp mã vào Kernel Ring-0**. 
> CyberV kiên quyết **nói thật với người dùng**:
> - Phần cứng máy tính của bạn đã được đọc thành công ở tầng User-Mode (`✓ ĐÃ QUAN SÁT (OBSERVED)`).
> - Lá chắn tầng nhân và dịch vụ chạy ngầm chưa được nạp nên hiển thị `○ CHƯA KÍCH HOẠT (INACTIVE)`, hoàn toàn không dùng đồng hồ hay thanh phần trăm giả tạo cảm giác an toàn giả mạo.

### 5.2. Ba Chế Độ Khởi Chạy Của CyberV-UI

#### 1. Chế Độ Đánh Giá Cục Bộ (Local Assessment Mode - Mặc định)
Nhấp đúp chuột vào `CyberV-UI.exe` hoặc chạy lệnh:
```powershell
& "dist\CyberV-UI\CyberV-UI\CyberV-UI.exe"
```
* **Đặc điểm:** Hoạt động ngay lập tức, **không đòi hỏi quyền Administrator**.
* **Chức năng:** Đọc thông số phần cứng thật của máy qua Win32 WMI APIs, tính mã băm nhận diện cục bộ (Local Hardware Fingerprint SHA-512), kiểm tra trạng thái chip TPM 2.0 (`DETECTED` hoặc `NOT_DETECTED`).

#### 2. Chế Độ Mô Phỏng Đầy Đủ (Full Protected Simulation / Demo Mode)
Khởi chạy kèm tham số hồ sơ mô phỏng:
```powershell
& "dist\CyberV-UI\CyberV-UI\CyberV-UI.exe" --mock=protected
```
* **Đặc điểm:** Dành cho việc thuyết trình, kiểm thử giao diện hoặc trải nghiệm luồng an ninh hoàn chỉnh khi chưa nạp driver thật.
* **Chức năng:** Trạng thái chuyển sang `■ PROTECTED` (Lục Bảo `#3FB950`), toàn bộ 4 tầng chẩn đoán xanh lá `PASS`, lá chắn Ring-0 hiển thị `Altitude 385201 ACTIVE`, các quyền can thiệp bị tước đoạt `STRIPPED (BLOCKED)`.

#### 3. Chế Độ Bảo Vệ Thật 24/7 (Real Protected Mode - Windows Service & Ring-0)
Để kích hoạt lá chắn bảo vệ nhân thật trên máy tính:
* **Bước 1 (Kích hoạt Dịch vụ Agent):** Ngay trên trang **TỔNG QUAN (Dashboard)**, bấm nút:
  > **`[🚀 Kích Hoạt Bảo Vệ Ngầm 24/7 (Windows Service)]`**
  Hệ thống sẽ bật hộp thoại **Windows UAC**, chọn **Yes** để cấp quyền Administrator. Kịch bản [`scripts/install-agent-service.ps1`](scripts/install-agent-service.ps1) sẽ tự động biên dịch, đăng ký Windows Service tự khởi động cùng máy tính.
* **Bước 2 (Nạp Driver Tầng Nhân `CyberVProbe.sys`):**
  Yêu cầu máy có cài Visual Studio 2022 + WDK (hoặc sử dụng bản driver đã biên dịch):
  ```powershell
  # Mở PowerShell bằng Run as Administrator:
  powershell -ExecutionPolicy Bypass -File "scripts\build-driver.ps1"
  powershell -ExecutionPolicy Bypass -File "scripts\install-driver.ps1"
  ```
  *(Đối với Windows 10/11 x64 thử nghiệm nội bộ, bật `bcdedit /set testsigning on` và khởi động lại máy trước khi nạp driver tự ký).*

### 5.3. Đóng Gói Nhị Phân Giao Diện (Rebuilding UI Executable)
Nếu bạn thay đổi mã nguồn trong thư mục `cyberv_ui/`, đóng gói lại file thực thi bằng kịch bản:
```powershell
powershell -ExecutionPolicy Bypass -File "scripts\build-ui.ps1"
```
Tệp thực thi độc lập sẽ được tạo ra tại `dist/CyberV-UI/CyberV-UI/CyberV-UI.exe`.

---

## 6. Quản Trị Windows Service

CyberV Agent hỗ trợ đầy đủ vòng đời dịch vụ Windows Service Control Manager (SCM):

### Sử dụng PowerShell Automation Script (Khuyến nghị)
Mở PowerShell dưới quyền **Administrator**:
```powershell
# Cài đặt dịch vụ, cấu hình Auto-Restart và khởi chạy:
.\scripts\install-agent-service.ps1

# Gỡ bỏ dịch vụ khỏi Windows SCM:
.\scripts\uninstall-agent-service.ps1
```

### Sử dụng Trực Tiếp CLI `cyberv-agent.exe`
```powershell
# Kiểm tra trạng thái hiện tại của dịch vụ:
target\release\cyberv-agent.exe status

# Cài đặt dịch vụ (SERVICE_AUTO_START, LocalSystem):
target\release\cyberv-agent.exe install

# Bật dịch vụ:
target\release\cyberv-agent.exe start

# Dừng dịch vụ an toàn:
target\release\cyberv-agent.exe stop

# Gỡ bỏ dịch vụ:
target\release\cyberv-agent.exe uninstall
```

---

## 7. Quy Trình Biên Dịch & Ký Số Driver

Trình điều khiển kernel [`driver/CyberVProbe`](driver/CyberVProbe) cung cấp lá chắn Ring-0 bảo vệ Agent:

### 1. Biên dịch Driver KMDF
Yêu cầu Visual Studio 2022 kèm Windows Driver Kit (WDK):
```powershell
# Kiểm tra môi trường biên dịch hoặc thực hiện build:
.\scripts\build-driver.ps1 -CheckOnly
.\scripts\build-driver.ps1 -Configuration Release
```

### 2. Ký số Thử Nghiệm (Test-Signing)
Sử dụng `signtool.exe` từ Windows SDK để tự động tạo chứng chỉ root và ký số driver:
```powershell
.\scripts\sign-driver.ps1
```

### 3. Nạp Driver vào Windows SCM
```powershell
# Cài đặt và khởi động driver service:
.\scripts\install-driver.ps1

# Gỡ bỏ driver service:
.\scripts\uninstall-driver.ps1
```

---

## 8. Kiểm Thử Chất Lượng & Chịu Tải

### Chạy Toàn Bộ Test Suite (240+ bài test)
```powershell
cd agent
cargo test
```

### Chạy Kiểm Thử Chịu Tải Cao (High-Load Stress Tests)
```powershell
cargo test --test kernel_security_stress_tests -- --nocapture
```
* **Event Bus Throughput:** Xử lý **10.000 sự kiện an ninh trong 3.67ms** (~2.7 triệu sự kiện/giây).
* **Policy Engine Speed:** Đánh giá **1.000 lượt quyết định trong 2.87ms** (~348.000 lượt/giây).
* **Cryptographic Fuzzing:** Thực hiện **1.000 chu kỳ ký số Ed25519** với 100% tỷ lệ phát hiện chữ ký giả mạo.

### Chạy Kiểm Thử Đột Biến Mã (Mutation Testing)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_mutation_tests.ps1
```
* Đánh giá 16/16 mutants tiêm lỗi mã nguồn thực tế.
* Kết quả: **16 KILLED, 0 SURVIVED (100.0% Mutation Score)**.

### Chạy Bộ Kiểm Thử Giao Diện & Bất Biến An Ninh (UI Test Suite - 30 Tests)
```powershell
python -m unittest discover -s cyberv_ui/tests -p "test_*.py" -v
```
* Kiểm thử Anti-Downgrade Invariant, Local Assessment Mode, Handshake Protocol, và Visual Truth Palette: **30/30 PASSED (100%)**.

---

## 9. Cấu Trúc Dự Án

```text
CyberV/
├── agent/                       # CyberV Core Agent (Rust)
│   ├── src/
│   │   ├── defense/             # Policy Engine, ACG, Isolation, Staging, Recovery
│   │   ├── fingerprint/         # Device Evidence Graph, Topological Nodes, State Hasher
│   │   ├── hardware/            # Hardware Observation (WMI, CPU, Board, RAM, Disk)
│   │   ├── identity/            # DPAPI Vault, Ed25519 Keypair, CSPRNG, Zeroize
│   │   ├── kernel/              # IOCTL Protocol & Kernel Probe Client
│   │   ├── service.rs           # Windows Service SCM Dispatcher & Lifecycle Manager
│   │   └── trust/               # TPM 2.0 NV Counter, Contradiction Detection, PCRs
│   └── tests/                   # 10+ Test Suites (Audit, Stress, Mutation Oracles)
├── cyberv_ui/                   # Desktop Native UI Client (Python / PySide6 Qt)
│   ├── hardware/                # Local Probed Hardware Collector & TPM Probe
│   ├── ipc/                     # Hardened Named Pipe Client & Handshake Protocol
│   ├── models/                  # 5-State Protection Models & Security Events
│   ├── security/                # Display Policy Gatekeeper (Anti-Downgrade Invariant)
│   ├── services/                # Background Polling & UAC Elevation Controller
│   ├── ui/                      # Trang giao diện, Thẻ phân rã 2 khối, Widgets, System Tray
│   └── tests/                   # 30 Unit, Fault Injection & Adversarial Tests
├── dashboard/                   # Fleet Management UI (React, TypeScript, Vite)
├── dist/                        # Nhị phân thực thi độc lập (dist/CyberV-UI/CyberV-UI/CyberV-UI.exe)
├── driver/                      # Windows KMDF Kernel Driver (C / WDK)
│   └── CyberVProbe/             # ObRegisterCallbacks, Device ACL, IOCTL Core
├── scripts/                     # Kịch bản tự động hóa PowerShell
│   ├── build-driver.ps1         # Biên dịch KMDF Driver qua MSBuild
│   ├── sign-driver.ps1          # Ký số driver với signtool.exe
│   ├── install-driver.ps1       # Cài đặt driver kernel qua SCM
│   ├── uninstall-driver.ps1     # Gỡ bỏ driver kernel
│   ├── build-ui.ps1             # Đóng gói Desktop UI với PyInstaller
│   ├── install-agent-service.ps1# Cài đặt Agent thành Windows Service tự khởi động
│   ├── uninstall-agent-service.ps1 # Gỡ bỏ Agent Windows Service
│   ├── run_mutation_tests.ps1   # Động cơ kiểm thử đột biến mã nguồn
│   └── package.ps1              # Đóng gói bản xuất xưởng toàn diện
├── Docs/                        # Tài liệu đặc tả kỹ thuật & Security Baseline
├── LICENSE                      # Apache License 2.0 & Legal Disclaimer
├── SECURITY.md                  # Chính sách báo cáo lỗ hổng an ninh bảo mật
├── USER_GUIDE.md                # Sổ tay hướng dẫn sử dụng & vận hành chi tiết
└── README.md                    # Tài liệu này
```

---

## 10. Chính Sách Bảo Mật & Đóng Góp

* **Báo cáo Lỗ hổng:** Vui lòng tham khảo [**`SECURITY.md`**](SECURITY.md) để gửi báo cáo bảo mật riêng tư đến ban quản trị thay vì mở Public Issue.
* **Đóng góp Mã nguồn (Contributing):** Mọi đóng góp Pull Request bắt buộc phải vượt qua toàn bộ test suite (`cargo test`) và không được vi phạm bất kỳ bất biến an ninh nào (INV-001 đến INV-008).

---

## 11. Giấy Phép & Tuyên Bố Miễn Trừ Trách Nhiệm (License & Legal Disclaimer)

Dự án CyberV được phát hành theo giấy phép mã nguồn mở **[Apache License 2.0](LICENSE)**.

```text
Copyright (c) 2026 Stufusic and CyberV Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

### Miễn Trừ Trách Nhiệm Kỹ Thuật (Disclaimer)
> **CẢNH BÁO:** CyberV tương tác trực tiếp với các giao diện hệ thống cấp thấp (Low-Level Windows Interfaces) bao gồm: Windows TBS TPM API, Named Pipe DACLs, phần cứng PCI/WMI, Windows Defender Application Control (WDAC), và trình điều khiển Kernel Ring-0. 
> 
> Phần mềm được cung cấp trên nguyên tắc **"NGUYÊN TRẠNG" (AS IS)**, **KHÔNG CÓ BẢO ĐẢM DƯỚI BẤT KỲ HÌNH THỨC NÀO**. Tác giả và những người đóng góp hoàn toàn không chịu trách nhiệm đối với bất kỳ rủi ro, hư hại, mất mát dữ liệu, lỗi màn hình xanh (BSOD) hay gián đoạn hệ thống phát sinh từ việc sử dụng phần mềm này. Người sử dụng có trách nhiệm tự kiểm thử kỹ lưỡng trong môi trường Staging/Sandbox an toàn trước khi triển khai trên hệ thống sản xuất.

