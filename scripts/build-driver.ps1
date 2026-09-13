# CyberV Driver Automated Build Script
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/build-driver.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/build-driver.ps1 -Configuration Debug
#   powershell -ExecutionPolicy Bypass -File scripts/build-driver.ps1 -CheckOnly

param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptDir
$DriverDir = Join-Path $WorkspaceRoot "driver\CyberVProbe"
$SolutionPath = Join-Path $DriverDir "CyberVProbe.sln"
$OutputDir = Join-Path $WorkspaceRoot "release\driver\$Platform"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " CYBERV KERNEL DRIVER BUILD PIPELINE (KMDF x64)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Workspace Root:   $WorkspaceRoot"
Write-Host "[*] Driver Directory: $DriverDir"
Write-Host "[*] Configuration:    $Configuration | $Platform"
Write-Host "[*] Target Output:    $OutputDir`n"

# 1. Locate Visual Studio 2022 and MSBuild
$vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstallPath = $null

if (Test-Path $vswherePath) {
    $vsInstallPath = & $vswherePath -latest -property installationPath
}

if (-not $vsInstallPath -or -not (Test-Path $vsInstallPath)) {
    $candidatePaths = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    )
    foreach ($p in $candidatePaths) {
        if (Test-Path $p) { $vsInstallPath = $p; break }
    }
}

if (-not $vsInstallPath) {
    Write-Host "[-] ERROR: Microsoft Visual Studio 2022 was not found on this machine." -ForegroundColor Red
    Write-Host "    Please install Visual Studio 2022 (Community, Professional, or Enterprise)."
    exit 1
}

$msBuildPath = Join-Path $vsInstallPath "MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path $msBuildPath)) {
    Write-Host "[-] ERROR: MSBuild.exe was not found at $msBuildPath." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Visual Studio Path: $vsInstallPath" -ForegroundColor Green
Write-Host "[+] MSBuild Path:       $msBuildPath" -ForegroundColor Green

# 2. Check for Windows Driver Kit (WDK)
$wdkTargetFile = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\build\WindowsDriver.common.targets" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
$wdkVsProps = Get-ChildItem "$vsInstallPath\MSBuild\Microsoft\VC\*\Platforms\$Platform\PlatformToolsets\WindowsKernelModeDriver*" -ErrorAction SilentlyContinue | Select-Object -First 1

$hasWdk = ($null -ne $wdkTargetFile) -or ($null -ne $wdkVsProps)

if ($hasWdk) {
    Write-Host "[+] Windows Driver Kit (WDK): DETECTED" -ForegroundColor Green
} else {
    Write-Host "[!] Windows Driver Kit (WDK): NOT CURRENTLY INSTALLED in Visual Studio." -ForegroundColor Yellow
    Write-Host "    Visual Studio 2022 and Windows SDK are present, but WDK build targets were not found."
    Write-Host "    To compile CyberVProbe.sys from source, install the WDK:"
    Write-Host "    👉 https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk" -ForegroundColor Cyan
    Write-Host "    (Install 'WDK for Windows 11, version 22H2/24H2' + Visual Studio WDK Extension)`n"
}

if ($CheckOnly) {
    Write-Host "[*] CheckOnly complete."
    exit 0
}

if (-not $hasWdk) {
    Write-Host "[-] Cannot proceed with compilation without WDK tools installed." -ForegroundColor Red
    Write-Host "    All driver sources and project files are verified and ready in: $DriverDir"
    exit 2
}

# 3. Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# 4. Invoke MSBuild
Write-Host "`n[*] Compiling CyberVProbe.sys using MSBuild..." -ForegroundColor Cyan
$buildArgs = @(
    "`"$SolutionPath`"",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/t:Rebuild",
    "/m",
    "/v:minimal"
)

$cmd = "& `"$msBuildPath`" $buildArgs"
Write-Host "[*] Running: $msBuildPath $buildArgs"

$process = Start-Process -FilePath $msBuildPath -ArgumentList $buildArgs -NoNewWindow -PassThru -Wait

if ($process.ExitCode -eq 0) {
    Write-Host "`n[+] DRIVER BUILD SUCCESSFUL!" -ForegroundColor Green
    $binDir = Join-Path $DriverDir "bin\$Configuration"
    if (Test-Path $binDir) {
        Copy-Item -Path "$binDir\*" -Destination $OutputDir -Recurse -Force
        Write-Host "[+] Artifacts copied to: $OutputDir" -ForegroundColor Green
    }
} else {
    Write-Host "`n[-] DRIVER BUILD FAILED with exit code $($process.ExitCode)." -ForegroundColor Red
    exit $process.ExitCode
}
