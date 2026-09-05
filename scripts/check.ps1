# CyberV Quality & Security Verification Script (PowerShell)
# Rule.md Điều 24: AI-generated code MUST pass compiler, unit test, lint, static analysis

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV Quality & Security Check" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Đảm bảo Cargo trong PATH
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
}

# 2. Format Check
Write-Host "`n[1/3] Kiểm tra định dạng mã nguồn (cargo fmt)..." -ForegroundColor Yellow
cargo fmt --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "LỖI: Format không đạt chuẩn. Hãy chạy 'cargo fmt'." -ForegroundColor Red
    exit 1
}
Write-Host "Format đạt chuẩn." -ForegroundColor Green

# 3. Clippy Lint Check
Write-Host "`n[2/3] Kiểm tra phân tích tĩnh (cargo clippy)..." -ForegroundColor Yellow
cargo clippy --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "LỖI: Clippy phát hiện cảnh báo/lỗi." -ForegroundColor Red
    exit 1
}
Write-Host "Clippy đạt chuẩn không có warning." -ForegroundColor Green

# 4. Unit & Integration Tests
Write-Host "`n[3/3] Chạy bộ kiểm thử tự động (cargo test)..." -ForegroundColor Yellow
cargo test --all-targets
if ($LASTEXITCODE -ne 0) {
    Write-Host "LỖI: Một hoặc nhiều bài test bị thất bại." -ForegroundColor Red
    exit 1
}
Write-Host "Toàn bộ kiểm thử hoàn tất thành công!" -ForegroundColor Green

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "  TẤT CẢ CHỐT CHẶN AN NINH & CHẤT LƯỢNG ĐÃ ĐẠT!" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
