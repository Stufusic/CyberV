# ====================================================================
# CyberV: Build Desktop Native UI (PySide6) Executable
# Ref: Docs/ui.md & Docs/ủiv.md
# ====================================================================
$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV Desktop Native UI — PyInstaller Packaging  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

# Verify Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python phát hiện: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "[-] Không tìm thấy Python trên hệ thống!"
}

# Verify PyInstaller
try {
    $pyinstallerVersion = python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
    Write-Host "[+] PyInstaller phát hiện: v$pyinstallerVersion" -ForegroundColor Green
} catch {
    Write-Host "[-] PyInstaller chưa được cài đặt. Đang cài đặt..." -ForegroundColor Yellow
    pip install pyinstaller
}

$DistDir = Join-Path $ProjectRoot "dist\CyberV-UI"
$BuildDir = Join-Path $ProjectRoot "build\CyberV-UI"
$EntryScript = Join-Path $ProjectRoot "cyberv_ui\main.py"
$MockProfilesDir = Join-Path $ProjectRoot "cyberv_ui\mock_profiles"

# Terminate any running instances to release file locks
Get-Process -Name "CyberV-UI" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Write-Host "`n[1/3] Chuẩn bị đóng gói Desktop Native Client..." -ForegroundColor Yellow
Write-Host "  Source: $EntryScript"
Write-Host "  Target Output: $DistDir"

$pyinstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--windowed",
    "--name=CyberV-UI",
    "--distpath=$DistDir",
    "--workpath=$BuildDir",
    "--add-data=$MockProfilesDir;cyberv_ui/mock_profiles",
    "$EntryScript"
)

Write-Host "`n[2/3] Đang biên dịch với PyInstaller..." -ForegroundColor Yellow
python @pyinstallerArgs

Write-Host "`n[3/3] Kiểm tra file thực thi đã tạo..." -ForegroundColor Yellow
$ExePath = Join-Path $DistDir "CyberV-UI\CyberV-UI.exe"
if (Test-Path $ExePath) {
    $exeSize = (Get-Item $ExePath).Length / 1MB
    Write-Host "[+] Đóng gói THÀNH CÔNG!" -ForegroundColor Green
    Write-Host "    Đường dẫn thực thi: $ExePath" -ForegroundColor Green
    Write-Host "    Dung lượng nhị phân: $('{0:N2}' -f $exeSize) MB" -ForegroundColor Green
    Write-Host "`nKhởi chạy thử nghiệm:" -ForegroundColor Cyan
    Write-Host "  & `"$ExePath`" --mock=protected" -ForegroundColor Gray
    Write-Host "  & `"$ExePath`" --live" -ForegroundColor Gray
} else {
    Write-Error "[-] Không tìm thấy file thực thi sau khi biên dịch!"
}
