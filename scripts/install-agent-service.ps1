# ==============================================================================
# CyberV Agent - Windows Service Installation & Deployment Script
# Description: Builds release agent binary, registers SCM service, and starts daemon.
# Requirements: Run as Administrator in PowerShell
# ==============================================================================

[CmdletBinding()]
param (
    [switch]$StartImmediately = $true,
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CyberV Agent - Windows Service Installation" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Check Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to register Windows Services."
    Write-Warning "Please relaunch PowerShell as Administrator and run this script again."
    exit 1
}

$RootDir = (Resolve-Path "$PSScriptRoot\..").Path
$AgentDir = Join-Path $RootDir "agent"
$ReleaseExe = Join-Path $RootDir "target\release\cyberv-agent.exe"

# 2. Build Release Binary if requested or missing
if (-not $SkipBuild -or -not (Test-Path $ReleaseExe)) {
    Write-Host "[*] Building CyberV Agent in release mode..." -ForegroundColor Yellow
    Push-Location $AgentDir
    try {
        cargo build --release --bin cyberv-agent
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $ReleaseExe)) {
    Write-Error "Release binary not found at: $ReleaseExe"
    exit 1
}

Write-Host "[+] Release binary located: $ReleaseExe" -ForegroundColor Green

# 3. Register Windows Service via CyberV Agent CLI
Write-Host "[*] Registering CyberV Agent with Windows Service Control Manager..." -ForegroundColor Yellow
& $ReleaseExe install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service installation failed with exit code $LASTEXITCODE"
    exit 1
}

# 4. Configure SCM Failure Actions (Auto-Restart on Crash / Failure)
Write-Host "[*] Configuring SCM Failure Recovery Actions (Auto-Restart)..." -ForegroundColor Yellow
try {
    sc.exe failure CyberVAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Write-Host "  -> Auto-Restart policy configured: 5s, 10s, 30s delay" -ForegroundColor Green
} catch {
    Write-Warning "Could not set failure actions: $_"
}

# 5. Start Service if requested
if ($StartImmediately) {
    Write-Host "[*] Starting CyberV Agent service..." -ForegroundColor Yellow
    & $ReleaseExe start
    Start-Sleep -Seconds 2
    
    Write-Host "[*] Querying service status..." -ForegroundColor Yellow
    & $ReleaseExe status
}

Write-Host "`n[+] CyberV Agent service installed and configured successfully!" -ForegroundColor Green
