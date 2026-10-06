# ====================================================================
# CyberV: Khởi Chạy Nền Tảng Mô Phỏng Đối Kháng MITRE Caldera
# Tự động chuẩn bị môi trường và khởi động máy chủ Caldera C2 nội bộ
# Truy cập giao diện: http://localhost:8888
# Tài khoản mặc định: 
#   - Red Team (Tấn công):  admin / admin  (hoặc red / admin)
#   - Blue Team (Phòng thủ): blue / admin
# ====================================================================

$ErrorActionPreference = "Continue"

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "       CYBERV - KHỞI ĐỘNG HỆ THỐNG MÔ PHỎNG ĐỐI KHÁNG MITRE CALDERA " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$CalderaDir = Join-Path $RootDir "tools\caldera"

if (-not (Test-Path $CalderaDir)) {
    Write-Error "[-] Không tìm thấy thư mục tools/caldera!"
    exit 1
}

Set-Location $CalderaDir

# 1. Kiểm tra Python
Write-Host "`n[1/3] Đang kiểm tra môi trường Python..." -ForegroundColor Yellow
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Write-Error "[-] Không tìm thấy python trên hệ thống!"
    exit 1
}

# 2. Cài đặt các thư viện cần thiết cho Caldera
Write-Host "`n[2/3] Kiểm tra & Cài đặt các thư viện phụ thuộc của Caldera..." -ForegroundColor Yellow
Write-Host "  -> Đang thực thi: pip install -r requirements.txt (vui lòng chờ trong giây lát)..." -ForegroundColor Cyan
python -m pip install -r requirements.txt --quiet --disable-pip-version-check

# 3. Khởi chạy Caldera Server
Write-Host "`n[3/3] Đang khởi động Caldera Adversary Emulation Server..." -ForegroundColor Yellow
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "  CALDERA ĐANG CHẠY TẠI ĐỊA CHỈ: http://localhost:8888" -ForegroundColor Green
Write-Host "  Thông tin đăng nhập Web Console:" -ForegroundColor White
Write-Host "    - Red Team (Adversary Operation): User: admin  / Pass: admin" -ForegroundColor Yellow
Write-Host "    - Blue Team (Defender Monitoring): User: blue   / Pass: admin" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "Nhấn Ctrl+C để dừng máy chủ Caldera khi hoàn tất thử nghiệm.`n" -ForegroundColor Gray

# Khởi chạy server ở chế độ insecure/local test
python server.py --insecure
