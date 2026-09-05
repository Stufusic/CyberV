# ====================================================================
# CyberV: Package Core Engine & Dashboard Application
# ====================================================================
$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV: Packaging Core Agent & Dashboard Application" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$RootDir = (Get-Item $PSScriptRoot).Parent.FullName
$OutputDir = Join-Path $RootDir "release"

# 1. Tạo thư mục release sạch
if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Path $OutputDir | Out-Null
$BinDir = Join-Path $OutputDir "bin"
$WebDir = Join-Path $OutputDir "web"
New-Item -ItemType Directory -Path $BinDir | Out-Null
New-Item -ItemType Directory -Path $WebDir | Out-Null

# 2. Biên dịch CyberV Core Agent ở chế độ Release
Write-Host "`n[1/2] Đang biên dịch CyberV Core Agent (Release)..." -ForegroundColor Yellow
Set-Location (Join-Path $RootDir "agent")
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --bin cyberv-agent

$AgentExe = Join-Path $RootDir "target\release\cyberv-agent.exe"
if (Test-Path $AgentExe) {
    Copy-Item $AgentExe -Destination $BinDir
    Write-Host "  -> Đã sao chép cyberv-agent.exe vào release/bin/" -ForegroundColor Green
} else {
    Write-Error "Không tìm thấy cyberv-agent.exe sau khi biên dịch!"
}

# 3. Biên dịch Dashboard Web Frontend
Write-Host "`n[2/2] Đang đóng gói Web Dashboard (Vite Production)..." -ForegroundColor Yellow
Set-Location (Join-Path $RootDir "dashboard")
npm run build

$DashboardDist = Join-Path $RootDir "dashboard\dist"
if (Test-Path $DashboardDist) {
    Copy-Item (Join-Path $DashboardDist "*") -Destination $WebDir -Recurse
    Write-Host "  -> Đã sao chép giao diện Web vào release/web/" -ForegroundColor Green
} else {
    Write-Error "Không tìm thấy thư mục dashboard/dist!"
}

# 4. Sao chép các tệp cấu hình mẫu
Copy-Item (Join-Path $RootDir ".env.example") -Destination (Join-Path $OutputDir ".env.example")

Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  ĐÓNG GÓI HOÀN TẤT THÀNH CÔNG!" -ForegroundColor Green
Write-Host "  Thư mục: $OutputDir" -ForegroundColor Green
Write-Host "    - Core Agent Binary:  release/bin/cyberv-agent.exe" -ForegroundColor White
Write-Host "    - Web Dashboard:      release/web/" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor Green
