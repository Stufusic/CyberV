# ====================================================================
# CyberV: Run Frontend Dashboard Dev Server
# ====================================================================
$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV Web Dashboard — Khởi Chạy Dev Server" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$DashboardDir = Join-Path $PSScriptRoot "..\dashboard"
Set-Location $DashboardDir

Write-Host "Đang khởi chạy Vite dev server..." -ForegroundColor Yellow
npm run dev
