# CyberV: Yêu Cầu Hệ Thống & Tiền Đề Kỹ Thuật (System & Technical Requirements)

Tài liệu này quy định chi tiết các tiêu chuẩn phần cứng, hệ điều hành, quyền hạn quản trị và môi trường phát triển cần thiết để vận hành và biên dịch CyberV.

---

## 1. Bảng Ma Trận Tương Thích (Compatibility Matrix)

| Thành Phần | Cấu Hình Tối Thiểu | Cấu Hình Khuyến Nghị | Ghi Chú An Ninh |
| :--- | :--- | :--- | :--- |
| **Kiến Trúc CPU** | x86_64 (Intel 64 / AMD64) | x86_64 hỗ trợ RDRAND & AVX2 | Cung cấp entropy cho sinh khóa |
| **Bảo Mật Phần Cứng** | Windows DPAPI (Không TPM) | Chip TPM 2.0 (dTPM / fTPM) | TPM 2.0 cần cho NV Anti-Rollback |
| **Hệ Điều Hành** | Windows 10 Version 1909 (64-bit) | Windows 11 23H2+ / Server 2022 | Hỗ trợ đầy đủ AppContainer & WDAC |
| **Chế Độ Khởi Động** | Legacy BIOS hoặc UEFI | UEFI Secure Boot BẬT | Ngăn chặn Rootkit trước khi nạp OS |
| **Bộ Nhớ (RAM)** | 4 GB RAM | 8 GB RAM trở lên | Phục vụ tính toán đồ thị SHA-512 |
| **Dung Lượng Đĩa** | 500 MB dung lượng trống | 2 GB NVMe SSD | Dành cho mã nguồn, DB cache & build |

---

## 2. Yêu Cầu Phần Cứng Chi Tiết (Hardware Requirements)

### 2.1. Chip Bảo Mật TPM (Trusted Platform Module 2.0)
* **Khuyến nghị cao nhất**: **Discrete TPM 2.0 (dTPM)** từ các nhà sản xuất Infineon, Nuvoton, STMicroelectronics, hoặc **Firmware TPM (fTPM)** (Intel PTT / AMD fTPM) được kích hoạt trong BIOS/UEFI.
* **Chỉ số đảm bảo**:
  * Khi có TPM 2.0: Agent kích hoạt `HardwareBacked` với NV Monotonic Counter (`0x01800001`) để chống tua ngược đĩa (snapshot rollback).
  * Khi chạy trên máy ảo (Hyper-V, VMware ESXi có vTPM): Agent ghi nhận `VtpmBacked`.
  * Khi không có TPM: Agent tự động hạ cấp xuống `OsProtected` (bảo vệ bởi Windows DPAPI) để duy trì hoạt động mà không bị crash.

### 2.2. Bo Mạch Chủ & Bus Phần Cứng (Motherboard & Hardware Bus)
* Hỗ trợ chuẩn ACPI và SMBIOS 2.8+ để truy vấn số sê-ri bo mạch chủ, chassis và bảng cấu hình bộ nhớ qua Windows WMI.
* Bus kết nối lưu trữ: Hỗ trợ NVMe (PCIe), SATA (AHCI) hoặc SAS. Các thiết bị USB di động không được khuyến nghị làm điểm neo định danh chính vì tính biến động cao.

---

## 3. Yêu Cầu Hệ Điều Hành & Dịch Vụ Hệ Thống (OS & Windows Services)

### 3.1. Phiên Bản Windows Được Hỗ Trợ
* **Windows 11**: Tất cả các phiên bản 64-bit (Pro, Enterprise, Education).
* **Windows 10**: Phiên bản 1909 (Build 18363) trở lên, 64-bit (Pro, Enterprise).
* **Windows Server**: Windows Server 2019, 2022, 2025 (Standard / Datacenter).
* *(Lưu ý: Không hỗ trợ Windows 32-bit (x86) hoặc Windows 7/8/8.1 do thiếu các API cô lập bảo mật hiện đại).*

### 3.2. Các Dịch Vụ & Thư Viện Hệ Thống Mặc Định Bắt Buộc
CyberV sử dụng các thư viện tích hợp sẵn của Windows (Inbox DLLs), không cần cài thêm runtime bên ngoài:
1. **Windows TPM Base Services (`TBS`)**:
   * Dịch vụ: `TBS` (`tbs.dll`).
   * Mục đích: Cung cấp giao diện trao đổi lệnh chuẩn TCG với chip TPM 2.0.
2. **Windows Management Instrumentation (`WMI`)**:
   * Dịch vụ: `winmgmt` (`wbemdisp.dll`, `wbemprox.dll`).
   * Mục đích: Thu thập định danh phần cứng (Win32_Processor, Win32_BaseBoard, Win32_PhysicalMemory, Win32_DiskDrive).
3. **Data Protection API (`DPAPI`)**:
   * Thư viện: `crypt32.dll` (`NCrypt` / `BCrypt`).
   * Mục đích: Niêm phong khóa danh tính Ed25519 bằng khóa dẫn xuất từ tài khoản SYSTEM / Người dùng.
4. **Named Pipes & Security Subsystem (`advapi32.dll`, `kernel32.dll`)**:
   * Mục đích: Thiết lập kênh giao tiếp liên tiến trình (IPC) với DACL bảo vệ nghiêm ngặt.

---

## 4. Yêu Cầu Quyền Hạn Quản Trị & Mức Toàn Vẹn (Privilege & Integrity Levels)

Kiến trúc CyberV được chia làm hai tiến trình với yêu cầu quyền hạn khác nhau:

```text
┌──────────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Tiến Trình                           │ Quyền Hạn & Mức Toàn Vẹn (Integrity Level)            │
├──────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Core Broker (cyberv-agent)           │ • Yêu cầu: Administrator hoặc NT AUTHORITY\SYSTEM     │
│                                      │ • Mức toàn vẹn: High Integrity / System Integrity      │
│                                      │ • Mục đích: Quản lý TPM, Vault, Driver handle & WDAC   │
├──────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Worker Daemon (Network / Dashboard)  │ • Yêu cầu: Standard User Token                         │
│                                      │ • Mức toàn vẹn: Low Integrity (AppContainer Sandbox)   │
│                                      │ • Mục đích: Tiếp nhận JSON, mạng HTTPS, Dashboard IPC  │
└──────────────────────────────────────┴────────────────────────────────────────────────────────┘
```

> [!NOTE]
> **Chế độ Chạy Thử Nghiệm (User-Mode Standalone)**:
> Nếu không có quyền Administrator, bạn vẫn có thể chạy `cyberv-agent` dưới quyền tài khoản người dùng bình thường. Khi đó:
> * Hệ thống sẽ đọc phần cứng qua WMI người dùng và niêm phong khóa qua User-level DPAPI.
> * Các thao tác ghi TPM NVRAM hoặc nạp Driver Kernel sẽ tự động chuyển sang chế độ giả lập an toàn (Mock/Audit Mode).

---

## 5. Yêu Cầu Driver Kernel (`CyberVProbe.sys` - Tùy Chọn)

Driver kernel là một lớp tùy chọn (Defense-in-Depth) phục vụ kiểm chứng chéo phần cứng trực tiếp tại Ring 0:
* **Môi trường Phát triển (Development)**: Bắt buộc bật chế độ kiểm thử chữ ký của Windows:
  ```powershell
  # Chạy bằng quyền Administrator và khởi động lại máy:
  bcdedit /set testsigning on
  ```
* **Môi trường Sản xuất (Production)**: File `cybervprobe.sys` phải được ký số bởi chứng chỉ số EV (Extended Validation) và được chứng nhận qua cổng **Microsoft WHQL (Windows Hardware Quality Labs)**.
* Nếu không có driver, Agent vẫn vận hành 100% bình thường thông qua WMI và native Win32 API.

---

## 6. Yêu Cầu Công Cụ Biên Dịch & Phát Triển (Build & Developer Toolchain)

Nếu bạn cần tự biên dịch lại từ mã nguồn:

### 6.1. Rust Toolchain
* **Phiên bản**: Rust 1.75.0 trở lên (khuyến nghị phiên bản Stable mới nhất, ví dụ: Rust 1.80+).
* **Target**: `x86_64-pc-windows-msvc`.
* **Cài đặt**: Qua [rustup.rs](https://rustup.rs/).

### 6.2. C/C++ Build Environment
* **Visual Studio 2019 / 2022** kèm gói **Desktop development with C++** HOẶC **Microsoft C++ Build Tools**.
* **Windows 10 / 11 SDK** (cung cấp các header file Win32 và thư viện liên kết `tbs.lib`, `crypt32.lib`, v.v.).

### 6.3. Node.js & Web Toolchain (Dành cho Dashboard)
* **Node.js**: Phiên bản LTS 18.x, 20.x, hoặc 22.x.
* **Package Manager**: `npm` phiên bản 9.x+ (đi kèm Node.js).

### 6.4. Shell Thực Thi
* **PowerShell**: PowerShell 5.1 (mặc định của Windows) hoặc **PowerShell 7+ (Core)**.
* Thiết lập chính sách thực thi script cục bộ (nếu gặp lỗi chặn script khi chạy `.ps1`):
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

---

## 7. Yêu Cầu Mạng & Cổng Kết Nối (Network Requirements)

* **Chế độ Ngoại Tuyến Độc Lập (Offline Standalone - Mặc định)**:
  * **Cổng mở ngoài**: **0 (Không mở bất kỳ cổng TCP/UDP nào ra bên ngoài)**.
  * Toàn bộ phán quyết an ninh và phát hiện tua ngược đều diễn ra cục bộ trên máy.
* **Chế độ Web Dashboard Cục Bộ**:
  * Cổng mặc định: `http://localhost:5173` (chỉ lắng nghe cục bộ `127.0.0.1`).
* **Chế độ Đồng Bộ Đám Mây (Tùy chọn)**:
  * Cho phép kết nối HTTPS ra ngoài tới máy chủ Supabase / Backend qua cổng **TCP 443 (Outbound)**. Không yêu cầu mở cổng Inbound.
