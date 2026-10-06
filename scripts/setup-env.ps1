# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
# CyberV: Kiểm Tra & Tự Động Thiết Lập Môi Trường (Python, Rust, C/C++)
# Tự động phát hiện thiếu và tải/cài đặt đầy đủ các công cụ & thư viện
# ====================================================================

$ErrorActionPreference = "Continue"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  CyberV: Automated Environment & Toolchain Setup  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RootDir

# Helper: Làm mới biến môi trường PATH từ Registry
function Refresh-EnvPath {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $env:PATH = "$cargoBin;$userPath;$machinePath;$env:PATH"
}
Refresh-EnvPath

# ====================================================================
# [1/3] KIỂM TRA & THIẾT LẬP PYTHON (3.10+) VÀ THƯ VIỆN
# ====================================================================
Write-Host "`n[1/3] Đang kiểm tra môi trường Python..." -ForegroundColor Yellow

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
$PythonOk = $false

if ($PythonCmd) {
    try {
        $pyVerStr = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        $pyMajor = [int]($pyVerStr.Split('.')[0])
        $pyMinor = [int]($pyVerStr.Split('.')[1])
        if ($pyMajor -ge 3 -and $pyMinor -ge 10) {
            $PythonOk = $true
            Write-Host "  [+] Python đã sẵn sàng: v$pyVerStr ($($PythonCmd.Source))" -ForegroundColor Green
        }
    } catch {
        $PythonOk = $false
    }
}

if (-not $PythonOk) {
    Write-Host "  [-] Python 3.10+ chưa có trên hệ thống. Đang tự động tải về và cài đặt..." -ForegroundColor Yellow
    $WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        Write-Host "  -> Cài đặt Python 3.11 qua Windows Package Manager (winget)..." -ForegroundColor Cyan
        & winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
    } else {
        Write-Host "  -> Đang tải bộ cài Python từ python.org..." -ForegroundColor Cyan
        $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
        $pyInstaller = Join-Path $env:TEMP "python-installer.exe"
        Invoke-WebRequest -Uri $pyUrl -OutFile $pyInstaller
        Write-Host "  -> Đang chạy bộ cài đặt Python..." -ForegroundColor Cyan
        Start-Process -FilePath $pyInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait
    }
    Refresh-EnvPath
}

# Kiểm tra và cài đặt các thư viện Python phụ thuộc
Write-Host "  -> Đang kiểm tra các thư viện Python (PySide6, cryptography, pytest, pyinstaller)..." -ForegroundColor Cyan
$PyLibsMissing = $false
try {
    & python -c "import PySide6, cryptography, pytest, PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) { $PyLibsMissing = $true }
} catch {
    $PyLibsMissing = $true
}

if ($PyLibsMissing) {
    Write-Host "  [-] Thiếu một số thư viện Python. Đang tự động cài đặt qua pip..." -ForegroundColor Yellow
    $ReqFile = Join-Path $RootDir "cyberv_ui\requirements.txt"
    & python -m pip install --upgrade pip --quiet
    if (Test-Path $ReqFile) {
        & python -m pip install -r $ReqFile --quiet
    }
    & python -m pip install pyinstaller pytest --quiet
    Write-Host "  [+] Đã cài đặt xong toàn bộ thư viện Python!" -ForegroundColor Green
} else {
    Write-Host "  [+] Toàn bộ thư viện Python đã đầy đủ!" -ForegroundColor Green
}

# ====================================================================
# [2/3] KIỂM TRA & THIẾT LẬP RUST (CARGO, RUSTC, CLIPPY, FMT)
# ====================================================================
Write-Host "`n[2/3] Đang kiểm tra môi trường Rust..." -ForegroundColor Yellow

$CargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $CargoCmd) {
    # Kiểm tra trong ~/.cargo/bin
    $cargoPath = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $cargoPath) {
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
        $CargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
    }
}

if ($CargoCmd) {
    $rustcVer = & rustc --version 2>$null
    Write-Host "  [+] Rust toolchain đã sẵn sàng: $rustcVer" -ForegroundColor Green
} else {
    Write-Host "  [-] Rust chưa được cài đặt. Đang tự động tải về rustup..." -ForegroundColor Yellow
    $WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        Write-Host "  -> Cài đặt Rustup qua winget..." -ForegroundColor Cyan
        & winget install Rustlang.Rustup --silent --accept-package-agreements --accept-source-agreements
    } else {
        $rustupUrl = "https://win.rustup.rs/x86_64"
        $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri $rustupUrl -OutFile $rustupExe
        Write-Host "  -> Đang thiết lập Rust toolchain..." -ForegroundColor Cyan
        Start-Process -FilePath $rustupExe -ArgumentList "-y --default-toolchain stable" -Wait
    }
    Refresh-EnvPath
}

# Đảm bảo các component cần thiết của Rust: clippy, rustfmt
Write-Host "  -> Kiểm tra component clippy & rustfmt..." -ForegroundColor Cyan
try {
    & rustup component add clippy rustfmt 2>$null
} catch {}
Write-Host "  [+] Rust toolchain và components đã hoàn tất!" -ForegroundColor Green

# ====================================================================
# [3/3] KIỂM TRA & THIẾT LẬP C/C++ COMPILER & BUILD TOOLS (MSVC)
# ====================================================================
Write-Host "`n[3/3] Đang kiểm tra môi trường biên dịch C/C++ (MSVC / Visual Studio Build Tools)..." -ForegroundColor Yellow

$VsWhereCandidates = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
    "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
)
$VsWhere = $VsWhereCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
$CppToolsInstalled = $false

if ($VsWhere) {
    $vcToolsPath = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vcToolsPath) {
        $CppToolsInstalled = $true
        Write-Host "  [+] Phát hiện Visual Studio C++ Build Tools tại: $vcToolsPath" -ForegroundColor Green
    }
}

if (-not $CppToolsInstalled) {
    $ClCmd = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($ClCmd) {
        $CppToolsInstalled = $true
        Write-Host "  [+] Phát hiện trình biên dịch MSVC cl.exe trong PATH." -ForegroundColor Green
    }
}

if (-not $CppToolsInstalled) {
    Write-Host "  [-] Visual Studio C++ Build Tools (MSVC) chưa được phát hiện." -ForegroundColor Yellow
    Write-Host "      (Cần thiết để biên dịch Rust native CRT, link C libraries và WDK Driver)" -ForegroundColor Yellow
    $WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        Write-Host "  -> Đang tự động cài đặt Visual Studio 2022 Build Tools qua winget..." -ForegroundColor Cyan
        Write-Host "     (Quá trình này có thể mất vài phút tùy tốc độ mạng)..." -ForegroundColor Cyan
        & winget install Microsoft.VisualStudio.2022.BuildTools --silent --accept-package-agreements --accept-source-agreements --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    } else {
        Write-Host "  -> Đang tải về Visual Studio Build Tools Bootstrapper..." -ForegroundColor Cyan
        $vsUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
        $vsInstaller = Join-Path $env:TEMP "vs_BuildTools.exe"
        Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller
        Write-Host "  -> Đang cài đặt Workload C++ Build Tools..." -ForegroundColor Cyan
        Start-Process -FilePath $vsInstaller -ArgumentList "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" -Wait
    }
    Refresh-EnvPath
} else {
    Write-Host "  [+] Môi trường C/C++ đã hoàn tất!" -ForegroundColor Green
}

# ====================================================================
# TỔNG KẾT & HƯỚNG DẪN TIẾP THEO
# ====================================================================
Write-Host "`n====================================================" -ForegroundColor Green
Write-Host "  KIỂM TRA & THIẾT LẬP MÔI TRƯỜNG HOÀN TẤT!" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  - Python:    Đầy đủ (Python 3.10+, PySide6, cryptography, pytest, pyinstaller)" -ForegroundColor White
Write-Host "  - Rust:      Đầy đủ (cargo, rustc, clippy, rustfmt)" -ForegroundColor White
Write-Host "  - C / C++:   Đầy đủ (MSVC Build Tools, C++ Linker)" -ForegroundColor White
Write-Host "`nCác thao tác bạn có thể thực hiện ngay:" -ForegroundColor Cyan
Write-Host "  1. Chạy ứng dụng giao diện máy trạm:      python -m cyberv_ui.main" -ForegroundColor Gray
Write-Host "  2. Chạy Core Agent (Rust):                cargo run --bin cyberv-agent -- run" -ForegroundColor Gray
Write-Host "  3. Chạy toàn bộ kiểm thử bảo mật:         cargo test --workspace --release" -ForegroundColor Gray
Write-Host "  4. Đóng gói bản phát hành độc lập (.zip): powershell -File scripts\package-zip.ps1" -ForegroundColor Gray
Write-Host "====================================================" -ForegroundColor Green
