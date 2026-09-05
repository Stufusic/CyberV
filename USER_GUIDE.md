# CyberV: Hướng Dẫn Sử Dụng & Triển Khai Thực Tế

> **Tài liệu hướng dẫn vận hành phiên bản Đóng gói Lõi (Core Logic Engine) không yêu cầu License Key, Tài khoản, Mật khẩu hay Google OAuth.**

---

## 1. Triết Lý Vận Hành Phiên Bản Cốt Lõi

Trong phiên bản này, toàn bộ logic định danh và phòng vệ của CyberV vận hành độc lập dựa trên **nguyên lý Zero-Trust gắn chặt phần cứng (Hardware-Anchored Zero Trust)**:

* **Không cần đăng ký tài khoản (Username / Password)**: Bản thân chiếc máy tính và cấu hình phần cứng độc nhất của nó chính là tài khoản định danh duy nhất.
* **Không cần Google Auth / 2FA bên ngoài**: Chữ ký mật mã Ed25519 được sinh từ entropy phần cứng và niêm phong bởi Windows DPAPI / TPM 2.0 đóng vai trò là nhân tố xác thực thứ hai bất biến.
* **Không cần nhập License Key**: Thiết bị tự đo lường tính toàn vẹn của mình; nếu phát hiện bị sao chép sang máy khác hoặc bị tua ngược đĩa, hệ thống tự động khóa bảo vệ theo chính sách cục bộ.

---

## 2. Chuẩn Bị Môi Trường

Để biên dịch và chạy CyberV từ mã nguồn:

### 2.1. Cài đặt công cụ bắt buộc:
1. **Rust Toolchain**:
   Tải tại [rustup.rs](https://rustup.rs/) (chọn phiên bản 64-bit Stable cho Windows).
   Kiểm tra sau khi cài:
   ```powershell
   cargo --version
   rustc --version
   ```
2. **Node.js (LTS 18+) & npm**:
   Tải tại [nodejs.org](https://nodejs.org/).
   Kiểm tra sau khi cài:
   ```powershell
   node --version
   npm --version
   ```
3. **PowerShell 5.1 hoặc PowerShell 7+** (đã có sẵn trên Windows 10/11).

---

## 3. Khởi Chạy Nhanh CyberV

### Bước 1: Khởi chạy CyberV Core Agent (Backend Daemon)
Mở cửa sổ PowerShell:

```powershell
cd "c:\New PJ\CyberV\agent"

# Chạy trực tiếp Agent:
cargo run --bin cyberv-agent
```

**Những gì bạn sẽ quan sát được trên màn hình Terminal:**
1. **Quan sát phần cứng (Hardware Observation)**: Danh sách chi tiết CPU, Motherboard, RAM, Ổ đĩa kèm trạng thái hoạt động.
2. **Băm linh kiện cấp 1 (Tier 1 Component Hashes)**: Các chuỗi băm SHA-512 FIPS 180-4 của từng linh kiện.
3. **Đồ thị Bằng chứng (Device Evidence Graph)**:
   * **Real Nodes**: Các nút đại diện cho linh kiện vật lý.
   * **Virtual Nodes**: Nút ảo đại diện cho cấu trúc liên kết Topology của bo mạch, bộ nhớ và lưu trữ.
   * **Virtual Points**: Điểm số bất biến xác định tính toàn vẹn của phần cứng.
4. **Trạng thái Khóa Định danh (Identity Vault)**: Tự động khởi tạo hoặc tải khóa Ed25519 đã được niêm phong an toàn.
5. **TPM 2.0 NV Monotonic Counter**: Hiển thị giá trị counter phần cứng hiện tại và xác nhận không có hành vi tua ngược đĩa.

---

### Bước 2: Khởi chạy Giao diện Quản trị (Web Dashboard)
Mở một cửa sổ PowerShell thứ hai:

```powershell
cd "c:\New PJ\CyberV\dashboard"

# Cài đặt dependencies (chỉ cần chạy lần đầu):
npm install

# Khởi chạy máy chủ phát triển frontend:
npm run dev
```

Mở trình duyệt web truy cập vào: **`http://localhost:5173`**

---

## 4. Hướng Dẫn Sử Dụng Giao Diện Web Dashboard

Giao diện Dashboard cung cấp góc nhìn trực quan về toàn bộ hệ sinh thái bảo mật của thiết bị:

### 4.1. Tab "Overview" (Tổng Quan & Chỉ Số Bất Biến)
* **Status Card**: Hiển thị trạng thái thiết bị (`TRUSTED`, `RESTRICTED`, hoặc `NEEDS_ATTENTION`).
* **Composite Security Score**: Điểm số phòng vệ tổng hợp tính theo trọng số nguyên (0 – 10.000).
* **Identity Vault Status**: Trạng thái niêm phong của khóa Ed25519 và trạng thái kết nối DPAPI/TPM.
* **Invariants Table**: Kiểm tra các quy tắc bất biến toán học:
  * *Topological Edge Invariant*: Cấu trúc liên kết linh kiện không bị xáo trộn.
  * *Component Threshold Invariant*: Ít nhất 75% linh kiện cốt lõi giữ nguyên.
  * *Anti-Rollback Counter Invariant*: Giá trị phần cứng TPM không mâu thuẫn với đĩa.

### 4.2. Tab "Hardware Graph" (Cấu Trúc Liên Kết Phần Cứng)
* Hiển thị cây phân cấp topo từ Root Device Node xuống từng linh kiện.
* Cho phép mở **Canonical JSON Drawer** để xem nội dung JSON chuẩn hóa đã được sắp xếp khóa bảng chữ cái trước khi băm SHA-512.

### 4.3. Tab "Device Fleet" (Danh Sách Thiết Bị)
* Xem danh sách các thiết bị trong mạng lưới.
* Nút **Revoke Device**: Cho phép thu hồi quyền tin cậy của thiết bị ngay lập tức nếu phát hiện bất thường.

### 4.4. Tab "Audit Log" (Nhật Ký Kiểm Toán Bất Biến)
* Ghi lại toàn bộ lịch sử các chu kỳ chứng thực (Heartbeat Attestation) và sự kiện phần cứng.
* Mỗi bản ghi chứa băm cam kết, dấu thời gian và ID chứng thực.

---

## 5. Đóng Gói Thành Bản Phân Phối Độc Lập (Standalone Release)

Nếu bạn muốn đóng gói toàn bộ dự án thành file chạy độc lập để cài đặt trên máy tính khác mà không cần cài Rust hay Node.js trên máy đích:

Chạy script đóng gói tự động:
```powershell
cd "c:\New PJ\CyberV"
powershell -ExecutionPolicy Bypass -File .\scripts\package.ps1
```

Sau khi chạy xong, thư mục **`release/`** sẽ được tạo ra với cấu trúc:
* **`release/bin/cyberv-agent.exe`**: Nhị phân Agent đã được tối ưu hóa Release (nhỏ gọn, tốc độ cao).
* **`release/web/`**: Bộ tệp HTML/CSS/JS tĩnh của Dashboard sẵn sàng phục vụ.
* **`release/.env.example`**: Tệp mẫu cấu hình môi trường.

---

## 6. Xử Lý Các Tình Huống Thường Gặp (Troubleshooting)

| Hiện Tượng | Nguyên Nhân | Cách Xử Lý |
| :--- | :--- | :--- |
| **Báo lỗi `TpmError::NotPresent`** | Máy tính không có chip TPM 2.0 hoặc TPM bị tắt trong BIOS. | 1. Bật Intel PTT hoặc AMD fTPM trong BIOS/UEFI.<br>2. Nếu chạy trên máy ảo, thêm vTPM trong cấu hình máy ảo.<br>3. Agent tự động kích hoạt chế độ dự phòng an toàn `OsProtected` với DPAPI. |
| **Báo lỗi `ContradictionRollbackDetected`** | Phiên bản phần mềm trên đĩa nhỏ hơn giá trị TPM Hardware Counter (do vừa restore snapshot máy ảo hoặc clone đĩa cũ). | Đây là tính năng bảo vệ của CyberV. Hãy cập nhật lại phần mềm lên phiên bản mới nhất khớp với giá trị TPM counter hoặc thực hiện quy trình phục hồi có ký số bởi Master Authority. |
| **Dashboard không hiển thị dữ liệu** | Chưa khởi chạy Agent hoặc cổng IPC bị chặn. | Đảm bảo `cyberv-agent.exe` đang chạy trong một cửa sổ PowerShell riêng biệt. |
| **Báo lỗi quyền truy cập Named Pipe** | Tài khoản hiện tại không có quyền truy cập Named Pipe của CyberV. | Chạy PowerShell dưới quyền Administrator nếu bạn muốn quản lý toàn diện các tiến trình cấp cao. |
