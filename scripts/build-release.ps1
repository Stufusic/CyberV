# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
#
# PROPRIETARY & SOURCE CODE LICENSE NOTICE
# This software is protected by international copyright laws and treaties.
# Unauthorized reproduction, reverse engineering, or distribution of this code,
# or any portion of it, is strictly prohibited without explicit written consent.
#
# DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
# OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
# ============================================================================
# ====================================================================
# CyberV R1 — Release Build Spine (HYBRID_DISTRIBUTION_PLAN §4 R1)
# Artifact: agent exe (CRT tĩnh) + UI exe (PyInstaller) + driver + hashes
#           + SBOM-lite + CyberV-Setup.exe (Inno, nếu có ISCC).
# Nguyên tắc: mỗi bước thất bại được BÁO RIÊNG — script không chết giữa
# chừng và tổng kết cuối cùng phải trung thực những gì thiếu.
# ====================================================================
$ErrorActionPreference = "Continue"

$RootDir = (Get-Item $PSScriptRoot).Parent.FullName
$OutDir = Join-Path $RootDir "release"
$GitRev = ""
try { $GitRev = (git -C $RootDir rev-parse --short HEAD) } catch { $GitRev = "unknown" }

Write-Host "==== CyberV R1 build spine (rev $GitRev) ====" -ForegroundColor Cyan

# [1/6] Core Agent — Rust release, CRT tĩnh (xem .cargo/config.toml)
Write-Host "`n[1/6] Cargo build (release, --locked)..." -ForegroundColor Yellow
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --locked --bin cyberv-agent --manifest-path (Join-Path $RootDir "agent\Cargo.toml")
$AgentExe = Join-Path $RootDir "target\release\cyberv-agent.exe"
$Step1 = Test-Path $AgentExe
if ($Step1) {
    New-Item -ItemType Directory -Path (Join-Path $OutDir "bin") -Force | Out-Null
    Copy-Item $AgentExe (Join-Path $OutDir "bin") -Force
    Write-Host "  OK: bin/cyberv-agent.exe" -ForegroundColor Green
} else {
    Write-Host "  THẤT BẠI: cyberv-agent.exe không tồn tại" -ForegroundColor Red
}

# [2/6] UI — PyInstaller qua build-ui.ps1 (nếu có môi trường)
Write-Host "`n[2/6] UI (PyInstaller)..." -ForegroundColor Yellow
$UiSpec = Join-Path $RootDir "CyberV-UI.spec"
$Step2 = $false
if (Test-Path $UiSpec) {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build-ui.ps1")
    # Tìm exe PyInstaller sinh ra trong dist/
    $UiExe = Get-ChildItem (Join-Path $RootDir "dist") -Recurse -Filter "CyberV*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($UiExe) {
        $UiDir = Join-Path $OutDir "ui"
        New-Item -ItemType Directory -Path $UiDir -Force | Out-Null
        # onefile: copy exe; onedir: copy cả thư mục cùng tên
        Copy-Item $UiExe.FullName $UiDir -Force
        $Sib = Join-Path $UiExe.DirectoryName "_internal"
        if (Test-Path $Sib) { Copy-Item $Sib (Join-Path $UiDir "_internal") -Recurse -Force }
        $Step2 = $true
        Write-Host "  OK: ui/$($UiExe.Name)" -ForegroundColor Green
    } else {
        Write-Host "  THẤT BẠI: không tìm thấy CyberV*.exe trong dist/" -ForegroundColor Red
    }
} else {
    Write-Host "  BỎ QUA: không có CyberV-UI.spec" -ForegroundColor DarkYellow
}

# [3/6] Driver — chỉ đóng gói SYS ĐÃ BUILD (WDK); cảnh báo trung thực nếu chưa ký
Write-Host "`n[3/6] Driver (CyberVProbe.sys)..." -ForegroundColor Yellow
$Step3 = $false
$SysCandidates = @(
    (Join-Path $RootDir "driver\CyberVProbe\x64\Release\CyberVProbe.sys"),
    (Join-Path $RootDir "driver\CyberVProbe\x64\Debug\CyberVProbe.sys")
)
$Sys = $SysCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($Sys) {
    New-Item -ItemType Directory -Path (Join-Path $OutDir "driver-bin") -Force | Out-Null
    Copy-Item $Sys (Join-Path $OutDir "driver-bin") -Force
    $Cat = Get-ChildItem (Split-Path $Sys) -Filter "*.cat" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Cat) {
        Copy-Item $Cat.FullName (Join-Path $OutDir "driver-bin") -Force
        Write-Host "  OK: driver-bin/ (có catalog $($Cat.Name))" -ForegroundColor Green
    } else {
        Write-Host "  OK nhưng CHƯA KÝ: không có .cat — driver sẽ KHÔNG load trên máy người dùng (cần M1 attestation signing, xem Docs/DRIVER_SIGNING_RUNBOOK.md)" -ForegroundColor DarkYellow
    }
    $Step3 = $true
} else {
    Write-Host "  BỎ QUA: chưa build driver (máy dev cần WDK — CI job driver-build)" -ForegroundColor DarkYellow
}

# [4/6] SHA256SUMS — băm mọi artifact trong release/
Write-Host "`n[4/6] SHA256SUMS..." -ForegroundColor Yellow
$Files = Get-ChildItem $OutDir -Recurse -File -ErrorAction SilentlyContinue
$UiLabel = if ($Step2) { 'co' } else { 'KHONG CO' }
$DrvLabel = if ($Step3) { 'co' } else { 'KHONG CO' }
$HashLines = $Files | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $h, $_.FullName.Substring($OutDir.Length + 1).Replace('\', '/')
}
$HashLines | Set-Content (Join-Path $OutDir "SHA256SUMS.txt") -Encoding ASCII
Write-Host "  OK: $($Files.Count) file đã băm -> SHA256SUMS.txt" -ForegroundColor Green

# [5/6] SBOM-lite — danh sách thành phần + nguồn (trung thực: không phải CycloneDX)
Write-Host "`n[5/6] SBOM-lite..." -ForegroundColor Yellow
@"
CyberV SBOM-lite (đơn giản hóa — không thay thế CycloneDX đầy đủ)
git_rev: $GitRev
build_date_utc: $((Get-Date).ToUniversalTime().ToString("o"))
components:
  - cyberv-agent.exe   (Rust, workspace agent, static CRT + CFG)
  - CyberVUI.exe       (PySide6 + PyInstaller)   [$UiLabel]
  - CyberVProbe.sys    (C/KMDF)                  [$DrvLabel]
  - signer: xem Docs/DRIVER_SIGNING_RUNBOOK.md (attestation/EV — D.1)
"@ | Set-Content (Join-Path $OutDir "SBOM.txt") -Encoding UTF8
Write-Host "  OK: SBOM.txt" -ForegroundColor Green

# [6/6] Inno Setup — build CyberV-Setup.exe nếu máy có ISCC
Write-Host "`n[6/6] Installer (Inno Setup)..." -ForegroundColor Yellow
$IsccCandidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
)
$Iscc = $IsccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
$Iss = Join-Path $RootDir "installer\CyberV-Setup.iss"
if (-not (Test-Path $Iss)) {
    Write-Host "  BỎ QUA: installer/CyberV-Setup.iss không tồn tại" -ForegroundColor DarkYellow
} elseif ($Iscc) {
    & $Iscc $Iss
    if (Test-Path (Join-Path $OutDir "CyberV-Setup.exe")) {
        Write-Host "  OK: CyberV-Setup.exe" -ForegroundColor Green
    } else {
        Write-Host "  THẤT BẠI: ISCC chạy nhưng không có output" -ForegroundColor Red
    }
} else {
    Write-Host "  BỎ QUA: chưa cài Inno Setup 6 (ISCC.exe) — cài rồi chạy lại script này" -ForegroundColor DarkYellow
}

# ---- Tổng kết trung thực ----
Write-Host "`n==== TỔNG KẾT R1 ====" -ForegroundColor Cyan
$AgentLabel = if ($Step1) { 'OK' } else { 'FAIL' }
$InnoDone = Test-Path (Join-Path $OutDir "CyberV-Setup.exe")
$InnoLabel = if ($InnoDone) { 'OK' } else { 'chua co' }
Write-Host ("agent: {0} | UI: {1} | driver: {2}" -f $AgentLabel, $UiLabel, $DrvLabel)
Write-Host ("Installer Inno: {0}" -f $InnoLabel)
Write-Host "Lưu ý: driver unsigned KHÔNG load trên máy người dùng — xem RUNBOOK M1." -ForegroundColor DarkYellow
