# ====================================================================
# CyberV: Package Release ZIP for End-Users
# Creates: CyberV-UI-v1.0.0-win64.zip per README.md section 4.1
# ====================================================================
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$StageDir = Join-Path $RootDir "release\CyberV-UI-v1.0.0-win64"
$ZipPath = Join-Path $RootDir "release\CyberV-UI-v1.0.0-win64.zip"
$RootZipPath = Join-Path $RootDir "CyberV-UI-v1.0.0-win64.zip"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV: Packaging End-User Release ZIP            " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Clean staging directory
Write-Host "[1/6] Chuẩn bị thư mục staging..." -ForegroundColor Yellow
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

$BinDir = Join-Path $StageDir "bin"
$ScriptsDir = Join-Path $StageDir "scripts"
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null

# 2. Copy UI binary & runtime
Write-Host "[2/6] Sao chép giao diện CyberV-UI.exe & _internal..." -ForegroundColor Yellow
$UiExe = Join-Path $RootDir "dist\CyberV-UI\CyberV-UI\CyberV-UI.exe"
$UiInternal = Join-Path $RootDir "dist\CyberV-UI\CyberV-UI\_internal"
if (Test-Path $UiExe) {
    Copy-Item $UiExe -Destination $StageDir -Force
    Copy-Item $UiInternal -Destination (Join-Path $StageDir "_internal") -Recurse -Force
    Write-Host "  -> Đã sao chép CyberV-UI.exe" -ForegroundColor Green
} else {
    Write-Error "Không tìm thấy dist/CyberV-UI/CyberV-UI/CyberV-UI.exe! Hãy chạy scripts\build-ui.ps1 trước."
}

# 3. Copy Rust release binaries
Write-Host "[3/6] Sao chép Core Agent & Keygen..." -ForegroundColor Yellow
$AgentExe = Join-Path $RootDir "target\release\cyberv-agent.exe"
$KeygenExe = Join-Path $RootDir "target\release\cyberv-keygen.exe"
if (Test-Path $AgentExe) {
    Copy-Item $AgentExe -Destination $BinDir -Force
    Write-Host "  -> Đã sao chép cyberv-agent.exe" -ForegroundColor Green
}
if (Test-Path $KeygenExe) {
    Copy-Item $KeygenExe -Destination $BinDir -Force
    Write-Host "  -> Đã sao chép cyberv-keygen.exe" -ForegroundColor Green
}

# 4. Copy management scripts
Write-Host "[4/6] Sao chép các kịch bản quản trị dịch vụ..." -ForegroundColor Yellow
Copy-Item (Join-Path $RootDir "scripts\install-agent-service.ps1") -Destination $ScriptsDir -Force
Copy-Item (Join-Path $RootDir "scripts\uninstall-agent-service.ps1") -Destination $ScriptsDir -Force

# 5. Create user documentation & checksums
Write-Host "[5/6] Tạo tài liệu hướng dẫn sử dụng và mã băm SHA-256..." -ForegroundColor Yellow
@'
================================================================================
                    CYBERV - HƯỚNG DẪN SỬ DỤNG CHO NGƯỜI DÙNG
               Hardware-Anchored Device Identity & Endpoint Trust
================================================================================

Phiên bản: v1.0.0 (Windows 10/11 x64)
Nền tảng: Windows 64-bit (Hỗ trợ Windows 10 build 1909+ và Windows 11)

--------------------------------------------------------------------------------
1. GIỚI THIỆU NHANH
--------------------------------------------------------------------------------
CyberV là nền tảng bảo vệ định danh thiết bị và phòng vệ điểm cuối thế hệ mới,
gắn chặt danh tính máy tính vào chip TPM 2.0, topo phần cứng vật lý và tầng
nhân hạt nhân Ring-0. Bản phát hành này là phiên bản Portable độc lập, người
dùng KHÔNG CẦN cài đặt Python, Rust hay bất kỳ thư viện ngoài nào.

--------------------------------------------------------------------------------
2. CÁCH KHỞI CHẠY GIAO DIỆN (DESKTOP NATIVE UI)
--------------------------------------------------------------------------------
Bước 1: Giải nén toàn bộ tệp zip này vào một thư mục (ví dụ: C:\CyberV\ hoặc Desktop).
Bước 2: Nhấp đúp chuột vào tệp:
        👉 CyberV-UI.exe

* Giao diện đồ họa sẽ khởi động ngay lập tức trong vòng 1-2 giây.
* Ứng dụng tự động phát hiện và hiển thị:
  - Thông tin vi xử lý (CPU), dung lượng bộ nhớ (RAM).
  - Bo mạch chủ (Motherboard) và trạng thái chip bảo mật TPM 2.0.
  - Điểm số tin cậy phần cứng (Hardware Trust Score).

* Các chế độ chạy qua dòng lệnh (Command Line - Tùy chọn):
  - Chạy bình thường:
      .\CyberV-UI.exe
  - Chạy chế độ kết nối trực tiếp với Core Agent đang chạy ngầm:
      .\CyberV-UI.exe --live
  - Chạy chế độ mô phỏng kịch bản an ninh có TPM:
      .\CyberV-UI.exe --mock=protected

--------------------------------------------------------------------------------
3. KÍCH HOẠT DỊCH VỤ BẢO VỆ NGẦM 24/7 (WINDOWS SERVICE)
--------------------------------------------------------------------------------
Để hệ thống tự động bảo vệ liên tục ngay cả khi tắt giao diện hoặc đăng xuất:

Cách 1 (Qua giao diện đồ họa):
- Trên cửa sổ CyberV-UI, tại màn hình 'TỔNG QUAN', nhấn nút:
  [🚀 Kích Hoạt Bảo Vệ Ngầm 24/7 (Windows Service)]
- Khi Windows hiện thông báo UAC yêu cầu quyền Administrator, bấm 'Yes'.

Cách 2 (Qua PowerShell với quyền Administrator):
- Mở PowerShell dưới quyền 'Run as Administrator'.
- Chuyển đến thư mục đã giải nén:
    cd "C:\CyberV\scripts"
- Chạy lệnh cài đặt:
    powershell -ExecutionPolicy Bypass -File .\install-agent-service.ps1
- Để gỡ bỏ dịch vụ khi không dùng:
    powershell -ExecutionPolicy Bypass -File .\uninstall-agent-service.ps1

--------------------------------------------------------------------------------
4. BẢO MẬT VÀ NGUYÊN TẮC FAIL-CLOSED
--------------------------------------------------------------------------------
- Hệ thống áp dụng nguyên tắc Fail-Closed: Tuyệt đối không giả mạo kết quả xác thực.
- Nếu máy tính không có chip TPM 2.0 hoặc probe phần cứng không đọc được, hệ thống
  sẽ báo trạng thái 'Unknown / Fallback' trung thực, không cấp quyền vượt mức.
- Mọi khóa bí mật được lưu trong Windows DPAPI Vault và tự động hủy an toàn trong
  bộ nhớ RAM khi hoàn tất chu trình.

--------------------------------------------------------------------------------
5. HỖ TRỢ VÀ ĐÓNG GÓP
--------------------------------------------------------------------------------
- Mã nguồn chính thức: https://github.com/Stufusic/CyberV
- Báo cáo lỗi / Liên hệ: Xem tệp SECURITY.md trên repository GitHub.
================================================================================
'@ | Set-Content (Join-Path $StageDir "HUONG_DAN_SU_DUNG.txt") -Encoding UTF8

$Files = Get-ChildItem $StageDir -Recurse -File
$HashLines = $Files | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $h, $_.FullName.Substring($StageDir.Length + 1).Replace('\', '/')
}
$HashLines | Set-Content (Join-Path $StageDir "SHA256SUMS.txt") -Encoding ASCII

# 6. Compress ZIP
Write-Host "[6/6] Đang nén tệp CyberV-UI-v1.0.0-win64.zip..." -ForegroundColor Yellow
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -CompressionLevel Optimal
Copy-Item $ZipPath -Destination $RootZipPath -Force

$zipSize = (Get-Item $ZipPath).Length / 1MB
Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  ĐÓNG GÓI HOÀN TẤT THÀNH CÔNG!" -ForegroundColor Green
Write-Host ("  File phát hành: {0} ({1:N2} MB)" -f $ZipPath, $zipSize) -ForegroundColor Green
Write-Host ("  Bản sao tại gốc: {0}" -f $RootZipPath) -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
