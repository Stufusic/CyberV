# ====================================================================
# CyberV: Build Frontend Dashboard Production Bundle
# ====================================================================
$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV Web Dashboard — Build Production" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$DashboardDir = Join-Path $PSScriptRoot "..\dashboard"
Set-Location $DashboardDir

Write-Host "Đang biên dịch TypeScript và đóng gói Vite bundle..." -ForegroundColor Yellow
npm run build

Write-Host "`nĐóng gói Web Dashboard thành công vào thư mục dist/!" -ForegroundColor Green
