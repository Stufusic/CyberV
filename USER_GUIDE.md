# CyberV: Sổ Tay Hướng Dẫn Vận Hành & Triển Khai Toàn Diện

> **Tài liệu hướng dẫn cài đặt, biên dịch, vận hành và quản trị nền tảng CyberV dành cho Quản trị viên Hệ thống (SysAdmins), Kỹ sư An toàn Thông tin (SecOps) và Nhà phát triển (Developers).**

---

## MỤC LỤC

1. [Triết Lý Vận Hành & Mô Hình An Ninh](#1-triết-lý-vận-hành--mô-hình-an-ninh)
2. [Chuẩn Bị Môi Trường & Tiền Đề Hệ Thống](#2-chuẩn-bị-môi-trường--tiền-đề-hệ-thống)
3. [Chế Độ 1: Vận Hành Tương Tác (Interactive Console Mode)](#3-chế-độ-1-vận-hành-tương-tác-interactive-console-mode)
4. [Chế Độ 2: Vận Hành Dịch Vụ Ngầm (Windows Service Mode)](#4-chế-độ-2-vận-hành-dịch-vụ-ngầm-windows-service-mode)
5. [Chế Độ 3: Giao Diện Người Dùng Máy Trạm Độc Lập (CyberV-UI.exe)](#5-chế-độ-3-giao-diện-người-dùng-máy-trạm-độc-lập-cyberv-uiexe)
6. [Quy Trình Triển Khai Lá Chắn Kernel Ring-0 (Driver Pipeline)](#6-quy-trình-triển-khai-lá-chắn-kernel-ring-0-driver-pipeline)
7. [Sử Dụng Giao Diện Quản Trị Hạm Đội (Fleet Web Dashboard)](#7-sử-dụng-giao-diện-quản-trị-hạm-đội-fleet-web-dashboard)
8. [Đóng Gói Xuất Xưởng Bản Phân Phối Độc Lập (Release Packaging)](#8-đóng-gói-xuất-xưởng-bản-phân-phối-độc-lập-release-packaging)
9. [Kiểm Thử An Toàn & Đột Biến Mã (Mutation Testing)](#9-kiểm-thử-an-toàn--đột-biến-mã-mutation-testing)
10. [Bảng Tra Cứu & Xử Lý Sự Cố (Comprehensive Troubleshooting)](#10-bảng-tra-cứu--xử-lý-sự-cố-comprehensive-troubleshooting)

---

## 1. Triết Lý Vận Hành & Mô Hình An Ninh

Trong các hệ thống quản trị điểm cuối truyền thống, danh tính thiết bị thường dựa vào tài khoản người dùng, chứng chỉ phần mềm có thể trích xuất, hoặc các chuỗi băm phần cứng tĩnh (fragile hashes). Mô hình này hoàn toàn bất lực trước:
* **Tấn công tua ngược máy ảo (VM Snapshot Rollback)**: Kẻ tấn công ghi đè lại snapshot cũ để qua mặt thời hạn cấp quyền.
* **Tấn công nhân bản ổ đĩa (Disk Cloning)**: Sao chép toàn bộ hệ điều hành sang máy tính khác.
* **Can thiệp tiến trình cục bộ (Process Tampering)**: Hacker dùng quyền Admin để terminate Agent hoặc inject mã độc vào bộ nhớ.

**CyberV áp dụng triết lý Hardware-Anchored Zero Trust**:
1. **Không phụ thuộc vào tài khoản hay mật khẩu**: Bản thân cấu trúc vật lý của phần cứng và chip TPM 2.0 là gốc rễ định danh duy nhất (Root-of-Trust).
2. **Khóa bất đối xứng Ed25519 bảo vệ bởi DPAPI**: Private key được niêm phong bởi Windows Data Protection API gắn chặt với máy trạm và tự động xóa sạch khỏi RAM bằng thuật toán zeroize khi giải phóng.
3. **Phát hiện bất nhất phần cứng (Contradiction Detection)**: Tự động so sánh phiên bản phần mềm với Hardware NV Monotonic Counter của TPM 2.0. Nếu có bất kỳ sự sai lệch nào do khôi phục snapshot, hệ thống lập tức tự cô lập an toàn.
4. **Lá chắn Ring-0 bảo vệ Agent**: Driver KMDF chặn mọi hành vi terminate, đọc/ghi bộ nhớ tiến trình của Agent kể cả từ tài khoản Administrator.

---

## 2. Chuẩn Bị Môi Trường & Tiền Đề Hệ Thống

### 2.1. Yêu Cầu Phần Cứng & Hệ Điều Hành
* **Hệ điều hành**: Windows 10 (bản 64-bit build 1909 trở lên), Windows 11 (64-bit), hoặc Windows Server 2019/2022/2025.
* **Kiến trúc CPU**: x86_64 (Intel 64 / AMD64).
* **Chip TPM**: Khuyến nghị có chip **TPM 2.0** (Discrete dTPM hoặc Firmware fTPM/Intel PTT). Nếu máy không có TPM, hệ thống tự động chuyển sang chế độ dự phòng an toàn `OsProtected` (DPAPI).
* **RAM & Đĩa trống**: Tối thiểu 4 GB RAM (khuyến nghị 8 GB); 1 GB dung lượng ổ đĩa.

### 2.2. Cài Đặt Công Cụ Biên Dịch (Build Tools)
1. **Rust Toolchain (1.75.0+)**:
   Tải bộ cài tại [rustup.rs](https://rustup.rs/). Chọn mục `x86_64-pc-windows-msvc`.
   Kiểm tra:
   ```powershell
   cargo --version
   rustc --version
   ```
2. **Visual Studio 2022 & C++ Build Tools**:
   Cài đặt Visual Studio 2022 (Community, Professional, hoặc Build Tools) với workload **"Desktop development with C++"** và **Windows 10/11 SDK**.
3. **Node.js (LTS 18+) & npm** (dành cho Web Dashboard):
   Tải tại [nodejs.org](https://nodejs.org/).
   Kiểm tra:
   ```powershell
   node --version
   npm --version
   ```
4. **PowerShell**: PowerShell 5.1 hoặc PowerShell 7+.

---

## 3. Chế Độ 1: Vận Hành Tương Tác (Interactive Console Mode)

Chế độ tương tác được sử dụng trong quá trình phát triển, chẩn đoán lỗi, hoặc thực hiện kiểm toán phần cứng trực tiếp.

Mở cửa sổ PowerShell và di chuyển vào thư mục dự án:

```powershell
cd "c:\New PJ\CyberV\agent"

# Khởi chạy Agent ở chế độ chẩn đoán tương tác:
cargo run --bin cyberv-agent -- run
```

### Các Giai Đoạn Hiển Thị Trên Màn Hình:
1. **Hardware Observation (Quan sát phần cứng)**:
   Liệt kê toàn bộ linh kiện vật lý (CPU, Bo mạch chủ, các thanh RAM, ổ cứng lưu trữ) kèm số serial, dung lượng và trạng thái hoạt động.
2. **Tier 1 Component Hashes (Băm linh kiện đa tầng)**:
   Mỗi linh kiện được băm độc lập bằng chuẩn mã hóa an toàn **SHA-512 (FIPS 180-4 / NSA CNSA Suite)**.
3. **Device Evidence Graph Engine (Đồ thị bằng chứng)**:
   - **Real Nodes**: Các nút đại diện cho linh kiện vật lý.
   - **Virtual Nodes**: Các nút topo liên kết cấu trúc bộ nhớ, bo mạch và lưu trữ.
   - **Virtual Points**: Điểm số định lượng dung sai topo học, cho phép phát hiện nâng cấp phần cứng hợp lệ (như gắn thêm RAM) thay vì coi đó là máy tính lạ.
4. **Device Identity & DPAPI Storage (Kho khóa danh tính)**:
   Khởi tạo hoặc tải cặp khóa bất đối xứng **Ed25519 (RFC 8032)** được niêm phong an toàn bởi Windows DPAPI.
5. **Tier 6 Final State Hash (Trạng thái thiết bị toàn diện)**:
   Tính toán chuỗi băm trạng thái cuối cùng gắn liền với phiên bản hệ điều hành và đồ thị bằng chứng.
6. **Challenge-Response Proof-of-Possession (Diễn tập thử thách)**:
   Mô phỏng máy chủ phát sinh Nonce 256-bit có hạn 60 giây và Agent ký số chứng minh quyền sở hữu thiết bị hợp pháp.

---

## 4. Chế Độ 2: Vận Hành Dịch Vụ Ngầm (Windows Service Mode)

Đây là **chế độ chuẩn cho môi trường doanh nghiệp (Production Deployment)**. CyberV Agent sẽ chạy ngầm liên tục dưới dạng một Native Windows Service trong **Session 0** dưới tài khoản đặc quyền tối cao `NT AUTHORITY\SYSTEM` (`LocalSystem`).

### 4.1. Cài Đặt Dịch Vụ Tự Động Bằng PowerShell Script (Khuyến nghị)
Mở PowerShell dưới quyền **Administrator**:

```powershell
cd "c:\New PJ\CyberV"

# Biên dịch bản Release, đăng ký SCM, cấu hình Auto-Restart và kích hoạt:
.\scripts\install-agent-service.ps1
```

Script sẽ tự động:
1. Kiểm tra đặc quyền Administrator.
2. Biên dịch binary `cyberv-agent.exe` ở chế độ tối ưu hóa `--release`.
3. Đăng ký dịch vụ với tên **`CyberVAgent`** (Chế độ `SERVICE_AUTO_START`).
4. Thiết lập chính sách phục hồi tự động khi tiến trình gặp sự cố (SCM Auto-Restart: 5s, 10s, 30s).
5. Kích hoạt dịch vụ và hiển thị trạng thái `RUNNING`.

### 4.2. Quản Trị Trực Tiếp Bằng Lệnh Dòng Lệnh `cyberv-agent.exe`
Bạn có thể điều khiển trực tiếp dịch vụ bằng binary đã biên dịch:

```powershell
# 1. Tra cứu trạng thái hiện tại:
.\target\release\cyberv-agent.exe status
# Kết quả mẫu:
# [*] Querying CyberV Agent Windows Service status...
# [+] Service Status: NOT_INSTALLED (hoặc RUNNING / STOPPED)

# 2. Đăng ký dịch vụ vào Windows SCM:
.\target\release\cyberv-agent.exe install

# 3. Khởi động dịch vụ:
.\target\release\cyberv-agent.exe start

# 4. Dừng dịch vụ an toàn:
.\target\release\cyberv-agent.exe stop

# 5. Gỡ bỏ dịch vụ khỏi Windows SCM:
.\target\release\cyberv-agent.exe uninstall
```

### 4.3. Theo Dõi Nhật Ký Hoạt Động (Session 0 Logging)
Do chạy trong Session 0 không có cửa sổ hiển thị, toàn bộ nhịp tim an ninh và sự kiện vòng đời của dịch vụ được tự động ghi vào tệp:
👉 **`C:\ProgramData\CyberV\logs\agent_service.log`**

Để theo dõi nhật ký thời gian thực trong PowerShell:
```powershell
Get-Content -Path "C:\ProgramData\CyberV\logs\agent_service.log" -Wait -Tail 20
```

### 4.4. Quản Lý Bằng Giao Diện Đồ Họa Windows (Services GUI)
1. Nhấn tổ hợp phím `Win + R`, gõ `services.msc` và nhấn Enter.
2. Tìm dịch vụ mang tên: **`CyberV Device-Binding Security Agent`** (`CyberVAgent`).
3. Tại đây bạn có thể kiểm tra trạng thái, xem cấu hình Startup Type (`Automatic`), hoặc xem tab **Recovery** để kiểm tra chính sách tự động khởi động lại sau sự cố.

---

## 5. Chế Độ 3: Giao Diện Người Dùng Máy Trạm Độc Lập (CyberV-UI.exe)

Ứng dụng đồ họa máy trạm độc lập (**CyberV Desktop Native Client**) được xây dựng bằng **Python 3.13 / PySide6 (Qt)** và đóng gói sẵn thành tệp thực thi duy nhất:
👉 **`dist/CyberV-UI/CyberV-UI/CyberV-UI.exe`**

Ứng dụng cho phép người dùng cuối, kỹ sư SOC và quản trị viên trực tiếp theo dõi trạng thái neo giữ phần cứng, tự kiểm tra tính toàn vẹn 4 tầng và kích hoạt dịch vụ nền mà không cần mở giao diện web hay terminal.

---

### 5.1. Phân Tách Rõ Ràng 3 Tầng Kiến Trúc Hệ Thống

Để hiểu rõ nguyên lý hiển thị của `CyberV-UI.exe`, cần nắm vững sự phân tách 3 tầng bảo mật trên Windows:

```text
┌──────────────────────────────────────────────────────────────────────────┐
│               [TẦNG 1] CyberV-UI.exe (User-Mode Ring-3)                 │
│  • Chạy bằng quyền người dùng thông thường (Standard User Integrity).    │
│  • Đọc cấu hình máy thật qua Win32 APIs & Registry (CPU, RAM, Mainboard).│
│  • Báo cáo trạng thái strictly "OBSERVED" (Đã quan sát).                 │
│  • TUYỆT ĐỐI KHÔNG THỂ tự tiện nạp mã vào Kernel Ring-0 (Windows ACLs).   │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ Named Pipe: \\.\pipe\CyberVIPC
                                     │ (Thách thức bắt tay mật mã Nonce)
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│               [TẦNG 2] CyberVAgent Service (Session 0 SYSTEM)            │
│  • Dịch vụ Windows Service chạy ngầm 24/7 dưới quyền NT AUTHORITY\SYSTEM.│
│  • Độc quyền quản lý DPAPI Vault, giao tiếp chip TPM 2.0.                │
│  • Mở handle đặc quyền kết nối với Kernel Driver qua Fast IOCTL.         │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ DeviceIoControl (Altitude 385201)
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│               [TẦNG 3] CyberVProbe.sys (Kernel-Mode Ring-0)             │
│  • Driver lọc KMDF được SCM nạp vào không gian nhân Windows.             │
│  • ObRegisterCallbacks: Chặn đứng PROCESS_TERMINATE, PROCESS_VM_READ,...│
│  • Báo cáo trạng thái strictly "VERIFIED" & "ACTIVE".                    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

### 5.2. Giải Đáp: Tại Sao Khi Mới Mở App Lại Báo "LOCAL ASSESSMENT" & Lá Chắn Ring-0 "NOT ACTIVE"?

Khi bạn vừa mở `CyberV-UI.exe` trên một máy tính cá nhân chưa cài đặt dịch vụ nền, bạn sẽ thấy:
1. **Huy hiệu trạng thái:** `● LOCAL ASSESSMENT` *(Màu lam Sapphire `#58A6FF`)*.
2. **Trang Lá Chắn Tầng Nhân:** 
   - Banner màu đỏ: `CALLBACK NOT ACTIVE: Kernel object protection is unavailable.`
   - Trình điều khiển: `NOT_INSTALLED` | Callbacks: `NOT ACTIVE`.
   - Quyền hạn: `UNPROTECTED (PROCESS_TERMINATE, VM_READ, VM_WRITE)`.
3. **Trang Chẩn Đoán Kỹ Thuật 4 Tầng:**
   - `[1] DRIVER: FAIL` (CyberVProbe driver is not loaded in SCM).
   - `[2] CORE AGENT: FAIL` (Agent process is not running or unreachable).
   - `[3] PROTOCOL: PASS` (Hợp đồng ABI và mã IOCTL đồng bộ).
   - `[4] SECURITY: WARN / PASS` (Cơ chế Fail-Closed kích hoạt cảnh báo an toàn).

> [!NOTE]
> **Đây KHÔNG PHẢI là lỗi phần mềm, mà là tính năng BẢO MẬT TRUNG THỰC (Technical Truth):**
> * CyberV tuân thủ nguyên tắc **Zero Deceptive Signals (Không phát tín hiệu an toàn giả tạo)**:
>   - Giao diện User-mode của CyberV đã đọc thành công phần cứng thật của máy bạn (CPU, RAM, Mainboard, TPM) và đánh dấu là `✓ ĐÃ QUAN SÁT (OBSERVED)`.
>   - Tuy nhiên, vì **Dịch vụ Windows Service chưa chạy** và **Driver Ring-0 chưa nạp**, phần mềm **phải nói sự thật 100%** rằng các tiến trình bên ngoài vẫn có thể can thiệp được vào máy. Phần mềm từ chối hiển thị thanh trạng thái màu xanh lá hay thông báo "Máy bạn đang an toàn" như các phần mềm diệt virus kém chất lượng.

---

### 5.3. Ba Chế Độ Sử Dụng Của CyberV-UI

#### 👉 Chế Độ 1: Đánh Giá Cục Bộ (Local Assessment Mode - Mặc định)
* **Cách mở:** Nhấp đúp vào `CyberV-UI.exe` như mọi ứng dụng thông thường.
* **Quyền hạn:** Không cần Administrator, không làm thay đổi bất kỳ file hệ thống nào.
* **Mục đích:** Khảo sát nhanh thông số phần cứng thiết bị, kiểm tra máy có chip TPM 2.0 hay không, tính chuỗi băm nhận dạng phần cứng (Local Hardware Fingerprint SHA-512).

#### 👉 Chế Độ 2: Mô Phỏng Đầy Đủ (Full Protected Simulation / Demo Mode)
* **Cách mở:** Mở PowerShell và chạy:
  ```powershell
  & "dist\CyberV-UI\CyberV-UI\CyberV-UI.exe" --mock=protected
  ```
* **Mục đích:** Dành cho việc thuyết trình, bảo vệ đồ án, kiểm thử QA hoặc trải nghiệm đầy đủ giao diện khi hệ thống đạt trạng thái bảo vệ 100%:
  - Huy hiệu hiển thị `■ PROTECTED` (Xanh lục bảo `#3FB950`).
  - Toàn bộ 4 tầng chẩn đoán đạt `PASS` (13/13 thành phần xanh lá).
  - Lá chắn Ring-0 báo `ACTIVE (Altitude 385201, PsProcessType)` với quyền can thiệp bị tước đoạt `STRIPPED (BLOCKED)`.

#### 👉 Chế Độ 3: Kích Hoạt Bảo Vệ Ngầm Thật 24/7 (Real Production Mode)
Để kích hoạt lá chắn bảo vệ thật sự trên máy tính của bạn:
1. **Kích hoạt Dịch vụ Core Agent:**
   - Tại trang **TỔNG QUAN (Dashboard)**, bấm nút:
     > **`[🚀 Kích Hoạt Bảo Vệ Ngầm 24/7 (Windows Service)]`**
   - Hộp thoại **Windows UAC (User Account Control)** sẽ xuất hiện hỏi quyền Administrator -> Chọn **Yes**.
   - Hoặc mở PowerShell với quyền Administrator và chạy:
     ```powershell
     powershell -ExecutionPolicy Bypass -File "scripts\install-agent-service.ps1"
     ```
   - Sau khi dịch vụ chạy, đường ống IPC `\\.\pipe\CyberVIPC` mở ra, UI sẽ tự động kết nối và chuyển sang chế độ đồng bộ dữ liệu thời gian thực.
2. **Kích hoạt Lá chắn Kernel Ring-0 (`CyberVProbe.sys`):**
   - Xem chi tiết tại [Mục 6: Quy Trình Triển Khai Lá Chắn Kernel Ring-0](#6-quy-trình-triển-khai-lá-chắn-kernel-ring-0-driver-pipeline).
   - Khi driver `CyberVProbe` được nạp vào nhân, toàn bộ mục `[1] DRIVER` trên trang Chẩn đoán sẽ tự động chuyển sang `PASS`.

---

## 6. Quy Trình Triển Khai Lá Chắn Kernel Ring-0 (Driver Pipeline)

Trình điều khiển nhân [`CyberVProbe.sys`](driver/CyberVProbe) cung cấp cơ chế bảo vệ Ring-0 mạnh mẽ chống lại việc tắt cưỡng bức tiến trình, đọc trộm bộ nhớ hoặc tiêm mã độc (DLL Injection).

### 6.1. Bật Chế Độ Test-Signing Trên Windows (Bắt Buộc Khi Thử Nghiệm)
Do Windows 64-bit yêu cầu chữ ký số chứng nhận bởi Microsoft cho driver kernel, khi chạy thử nghiệm trên máy lab/dev, bạn cần bật chế độ Test-Signing:

Mở PowerShell dưới quyền **Administrator**:
```powershell
bcdedit /set testsigning on
```
*(Khởi động lại máy tính một lần để hệ điều hành áp dụng chế độ này)*.

### 5.2. Biên Dịch Driver KMDF
Sử dụng script tự động hóa:
```powershell
cd "c:\New PJ\CyberV"

# Kiểm tra công cụ MSBuild và WDK:
.\scripts\build-driver.ps1 -CheckOnly

# Thực hiện biên dịch driver ra bản Release:
.\scripts\build-driver.ps1 -Configuration Release
```

### 5.3. Ký Số Thử Nghiệm Tự Động (Test-Signing)
Script sẽ tự động tạo chứng chỉ mã gốc self-signed và ký số tệp driver bằng `signtool.exe`:
```powershell
.\scripts\sign-driver.ps1
```

### 5.4. Nạp & Gỡ Bỏ Driver Service
```powershell
# Cài đặt và kích hoạt driver vào nhân Windows:
.\scripts\install-driver.ps1

# Gỡ bỏ driver khi không còn nhu cầu:
.\scripts\uninstall-driver.ps1
```

---

## 7. Sử Dụng Giao Diện Quản Trị Hạm Đội (Fleet Web Dashboard)

Web Dashboard cung cấp giao diện trực quan hóa toàn bộ mạng lưới thiết bị, đồ thị linh kiện và các chỉ số an ninh thời gian thực.

### 7.1. Khởi Chạy Dashboard
Mở cửa sổ PowerShell:
```powershell
cd "c:\New PJ\CyberV\dashboard"

# Cài đặt các gói phụ thuộc (chỉ cần chạy lần đầu):
npm install

# Khởi chạy máy chủ phát triển frontend:
npm run dev
```
Mở trình duyệt truy cập: **`http://localhost:5173`**

### 7.2. Các Tab Tính Năng Chính:
* **Tab "Overview"**:
  - Điểm số an ninh tổng hợp **Composite Security Score** (thang điểm 0 – 10.000).
  - Trạng thái thiết bị (`TRUSTED`, `RESTRICTED`, hoặc `NEEDS_ATTENTION`).
  - Ma trận bất biến an ninh (**Invariants Table**): Kiểm tra tính toàn vẹn của đồ thị topo, tỷ lệ linh kiện hợp lệ, và tình trạng bất nhất counter TPM.
* **Tab "Hardware Graph"**:
  - Sơ đồ trực quan hình cây biểu diễn liên kết từ nút Root xuống từng linh kiện vật lý và các nút topo ảo.
  - Hỗ trợ mở **Canonical JSON Drawer** để kiểm toán chuỗi dữ liệu JSON đã được sắp xếp trước khi băm SHA-512.
* **Tab "Device Fleet"**:
  - Quản lý danh sách các thiết bị trong mạng lưới.
  - Hỗ trợ nút **Revoke Device**: Cho phép tước quyền tin cậy của thiết bị ngay lập tức khi phát hiện nghi vấn an ninh.
* **Tab "Audit Log"**:
  - Lịch sử bất biến ghi lại mọi chu kỳ chứng thực (Heartbeat Attestation) kèm băm cam kết và dấu thời gian.

---

## 8. Đóng Gói Xuất Xưởng Bản Phân Phối Độc Lập (Release Packaging)

Khi cần bàn giao sản phẩm hoặc triển khai lên các máy tính mục tiêu mà không yêu cầu cài đặt Rust, Node.js hay Visual Studio:

Chạy script đóng gói tự động:
```powershell
cd "c:\New PJ\CyberV"
powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1
```

Sau khi chạy xong, thư mục **`release/`** độc lập sẽ được tạo ra với cấu trúc chuẩn:
```text
release/
├── bin/
│   ├── cyberv-agent.exe          # Tệp thực thi Agent tối ưu hóa Release
│   └── CyberV-UI.exe             # Desktop Native UI Client (PySide6)
├── web/                          # Toàn bộ tệp tĩnh HTML/CSS/JS của Web Dashboard
├── scripts/                      # Bộ PowerShell scripts cài đặt Service và Driver
│   ├── install-agent-service.ps1
│   ├── uninstall-agent-service.ps1
│   ├── build-driver.ps1
│   ├── sign-driver.ps1
│   ├── install-driver.ps1
│   └── uninstall-driver.ps1
├── driver/                       # Mã nguồn và dự án KMDF Driver
└── .env.example                  # Tệp mẫu cấu hình môi trường
```

Để triển khai trên máy đích: Chỉ cần sao chép thư mục `release/` sang máy mới và chạy `.\scripts\install-agent-service.ps1` dưới quyền Administrator.

---

## 9. Kiểm Thử An Toàn & Đột Biến Mã (Mutation Testing)

CyberV sở hữu bộ kiểm thử nghiêm ngặt bậc nhất để chứng minh tính toán học của hệ thống an ninh:

### 9.1. Kiểm Thử Toàn Bộ Test Suite (240+ Bài Kiểm Thử)
```powershell
cd "c:\New PJ\CyberV\agent"
cargo test
```

### 9.2. Kiểm Thử Chịu Tải Cao (High-Load Stress Tests)
Kiểm thử sức chịu đựng của Event Bus đa luồng và động cơ phán quyết chính sách:
```powershell
cargo test --test kernel_security_stress_tests -- --nocapture
```
* **Thông lượng Event Bus:** Xử lý và trích xuất **10.000 sự kiện an ninh trong 3.67ms** (~2.7 triệu sự kiện/giây) qua 20 luồng đồng thời mà không suy hao.
* **Tốc độ Policy Engine:** Đánh giá **1.000 lượt quyết định trong 2.87ms** (~348.000 lượt/giây).
* **Fuzzing Chữ Ký Ed25519:** 1.000 chu kỳ thử thách - xác thực; tỷ lệ chặn đứng chữ ký giả mạo đạt **100%**.

### 9.3. Kiểm Thử Đột Biến Mã Nguồn (Mutation Testing Engine)
Chạy động cơ tiêm lỗi mã nguồn tự động để kiểm tra tỷ lệ phát hiện lỗi:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_mutation_tests.ps1
```
* **Tổng số mutants tiêm vào hệ thống:** 16 lỗi nghiêm trọng (xâm phạm INV-001 đến INV-008).
* **Tỷ lệ Mutant bị tiêu diệt (Killed Score):** **100.0% (16/16 Mutants Killed, 0 Mutants Survived)**.
* Mã nguồn gốc được tự động khôi phục 100% nguyên vẹn sau khi kiểm thử kết thúc.

### 9.4. Kiểm Thử Giao Diện Desktop & Bất Biến Chống Xuống Cấp (30 Bài Kiểm Thử)
```powershell
python -m unittest discover -s cyberv_ui/tests -p "test_*.py" -v
```
* Kiểm thử Anti-Downgrade Invariant, Local Assessment Mode, Handshake Protocol, và Visual Truth Palette: **30/30 PASSED (100%)**.

---

## 10. Bảng Tra Cứu & Xử Lý Sự Cố (Comprehensive Troubleshooting)

| Hiện Tượng / Mã Lỗi | Nguyên Nhân Gốc | Hướng Dẫn Khắc Phục |
| :--- | :--- | :--- |
| **`CyberV-UI.exe` hiển thị `● LOCAL ASSESSMENT` và Lá chắn Ring-0 báo `CALLBACK NOT ACTIVE / NOT_INSTALLED`** | Ứng dụng Desktop chạy ở tầng User-mode thông thường (Ring-3). Dịch vụ nền `CyberVAgent` và Driver `CyberVProbe.sys` chưa được cài đặt / nạp vào nhân Windows. | Đây là tính năng **Bảo Mật Trung Thực (Technical Truth)**, không phải lỗi. Để kích hoạt: Bấm nút `[🚀 Kích Hoạt Bảo Vệ Ngầm 24/7]` trên trang Tổng quan để cấp quyền Administrator cài Service, hoặc chạy `CyberV-UI.exe --mock=protected` nếu chỉ muốn trải nghiệm mô phỏng. |
| **Trang Chẩn Đoán 4 Tầng báo: `[1] DRIVER FAIL` và `[2] CORE AGENT FAIL`** | Driver chưa được nạp vào Windows SCM và Service nền chưa chạy trên máy. | 1. Chạy `scripts\install-agent-service.ps1` (Run as Admin) để bật Service -> Tầng `[2]` sẽ chuyển sang `PASS`.<br>2. Chạy `scripts\build-driver.ps1` và `scripts\install-driver.ps1` để nạp driver -> Tầng `[1]` sẽ chuyển sang `PASS`. |
| **`OpenSCManagerW failed (error code: 5)`** | Lệnh được thực thi trong PowerShell thông thường, không có quyền Quản trị viên (Access Denied). | Nhấp chuột phải vào biểu tượng PowerShell và chọn **"Run as Administrator"**, sau đó chạy lại lệnh. |
| **`OpenServiceW failed (error: 1060)`** | Dịch vụ `CyberVAgent` chưa được cài đặt vào hệ thống (`ERROR_SERVICE_DOES_NOT_EXIST`). | Chạy lệnh `cyberv-agent.exe install` hoặc sử dụng script `.\scripts\install-agent-service.ps1`. |
| **`ContradictionRollbackDetected`** | Giá trị TPM NV Counter phần cứng lớn hơn phiên bản lưu trên đĩa (do vừa khôi phục snapshot máy ảo hoặc sao chép ảnh đĩa cũ). | Đây là tính năng bảo vệ chống sao chép của CyberV. Hãy cập nhật phần mềm lên bản mới nhất hoặc thực hiện quy trình khôi phục có chữ ký từ Master Authority Key. |
| **`TpmError::NotPresent`** | Máy tính không có chip TPM 2.0 hoặc TPM bị tắt trong BIOS/UEFI. | 1. Bật Intel PTT hoặc AMD fTPM trong thiết lập BIOS.<br>2. Nếu chạy trên máy ảo, cấu hình thêm chip vTPM.<br>3. Agent sẽ tự động chuyển sang chế độ dự phòng an toàn `OsProtected` bằng DPAPI. |
| **Lỗi nạp Driver: `StartService failed (error: 577)`** | Windows chặn nạp driver do chữ ký số không hợp lệ trong môi trường 64-bit (`Windows cannot verify the digital signature`). | 1. Kích hoạt chế độ Test-Signing: `bcdedit /set testsigning on` rồi khởi động lại máy.<br>2. Chạy `.\scripts\sign-driver.ps1` để đưa chứng chỉ vào kho `TrustedPublisher`. |
| **Giao diện Dashboard không cập nhật dữ liệu** | Chưa khởi chạy Agent hoặc kênh IPC Named Pipe bị chặn. | Kiểm tra trạng thái Agent: `cyberv-agent.exe status`. Đảm bảo dịch vụ đang ở trạng thái `RUNNING`. |
| **Cảnh báo Mutex Poisoning trong Event Bus** | Có một luồng tiến trình bị panic đột ngột khi đang giữ khóa Mutex. | CyberV tích hợp cơ chế tự phục hồi INV-006: Hàng đợi sự kiện tự động giải cứu dữ liệu qua `poisoned.into_inner()` mà không làm gián đoạn hệ thống. |

