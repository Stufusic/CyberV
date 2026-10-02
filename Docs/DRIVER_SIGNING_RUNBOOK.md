# CyberV Driver Signing & Distribution Runbook (Phase 2-6)

> Mục tiêu: `CyberVProbe.sys` phải được ký số đúng quy trình để nạp được trên
> Windows 10/11 x64 — đặc biệt khi **Memory Integrity (HVCI)** bật mặc định trên
> Windows 11, nơi driver chưa ký hoặc ký bằng test cert sẽ bị chặn.

## 1. Chuỗi các mức ký

| Mức | Yêu cầu | Chạy được ở đâu |
|-----|---------|-----------------|
| Test signing | `bcdedit /set testsigning on`, self-signed cert | Máy dev, HVCI tắt |
| **Attestation signing (khuyến nghị)** | EV Code Signing cert + Microsoft Hardware Dev Center, submit CAB qua Partner Center | Mọi máy, HVCI bật, không cần WHQL test |
| Full WHQL | EV cert + HLK test results | Mọi máy + logo Windows |

Lộ trình khuyến nghị: attestation signing trước (không cần chạy HLK), WHQL sau
khi driver ổn định.

## 2. Quy trình Attestation Signing

### 2.1 Chuẩn bị
1. Mua **EV Code Signing certificate** (DigiCert/Sectigo/GlobalSign).
2. Đăng kí [Microsoft Hardware Dev Center](https://partner.microsoft.com/dashboard/hardware)
   và liên kết EV cert với tài khoản.

### 2.2 Build & đóng gói
```powershell
# Build Release x64 (CI đã chạy: msbuild CyberVProbe.sln /p:Configuration=Release /p:Platform=x64)
msbuild driver\CyberVProbe\CyberVProbe.sln /p:Configuration=Release /p:Platform=x64 /m

# Sinh stub catalog cho submit (bản signed cuối do Microsoft phát hành)
# Package gồm: CyberVProbe.sys + CyberVProbe.inf (đã có KmdfService — xem fix C3/H1)
inf2cat /driver:driver\CyberVProbe\x64\Release\CyberVProbe /os:10_X64 /uselocaltime

# Đóng CAB để submit
cabarc n CyberVProbe_Submit.CAB driver\CyberVProbe\x64\Release\CyberVProbe\*
```

> LƯU Ý: `CatalogFile = CyberVProbe.cat` trong INF hiện trỏ tới catalog chưa
> tồn tại — file `.cat` chính thức chỉ có sau khi Microsoft attestation-sign
> và trả về package. Không phân phối package có `.cat` tự sinh bằng cert thường
> (kernel mode yêu cầu Microsoft-cross-signed hoặc attestation).

### 2.3 Submit qua Partner Center
1. Partner Center → **Driver** → **New driver** → upload `CyberVProbe_Submit.CAB`.
2. Chọn **Attestation signing** (không cần HLK).
3. Sau khi sign xong: tải package signed (chứa `.cat` do Microsoft ký) về.
4. Gắn bản signed vào release; **không bao giờ rebuild lại .sys sau bước này**
   (mọi thay đổi phải submit lại).

### 2.4 Kiểm tra trên máy đích
```powershell
# Xác minh chữ ký kernel driver
Get-AuthenticodeSignature .\CyberVProbe.sys | Format-List
signtool verify /kp CyberVProbe.sys

# Bật Memory Integrity để xác minh driver vẫn nạp được (Windows 11 mặc định bật)
# Windows Security -> Device Security -> Core isolation -> Memory integrity
pnputil /add-driver CyberVProbe.inf /install
sc query CyberVProbe
```

## 3. CI hiện trạng

- `.github/workflows/rust.yml` job `driver-build`: msbuild x64 Release + ABI
  guard (CTL_CODE + `ClientAbiVersion` khớp giữa `ioctl.h` và Rust).
- `agent/tests/kernel_abi_sync_tests.rs`: parse `ioctl.h` và so khớp IOCTL
  constants + ABI version với `kernel/protocol.rs` — chạy trên mỗi PR.
- Signing **không tự động trong CI** vì cần EV cert private key trong HSM.
  Khi có cert: thêm job release dùng [Azure Trusted Signing](https://learn.microsoft.com/windows/apps/develop/signing/trusted-signing-overview)
  hoặc self-hosted runner cắm HSM, gated bởi secret `DRIVER_SIGNING_ENABLED`.

## 4. Checklist trước mỗi release driver

- [ ] `cargo test` xanh (gồm `kernel_abi_sync_tests`)
- [ ] CI `driver-build` job xanh (msbuild, không warning WDK nghiêm trọng)
- [ ] `InfVerif /v` không lỗi (chạy local với WDK)
- [ ] Driver build dùng `NonPagedPoolNx` opt-in nếu bắt đầu cấp phát pool
- [ ] Submit attestation signing + tải package signed
- [ ] Test cài trên Win10 21H2 + Win11 23H2 với Memory Integrity BẬT
- [ ] Kiểm tra unload sạch không BSOD (`sc stop CyberVProbe` → ObCallbacks unregister đúng thứ tự)
