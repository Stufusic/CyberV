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
# CyberV Kernel Driver Installation & Start Script
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File scripts/install-driver.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/install-driver.ps1 -DriverPath "release/driver/x64/CyberVProbe.sys"

param(
    [string]$DriverPath = "release/driver/x64/CyberVProbe.sys",
    [string]$ServiceName = "CyberVProbe"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[-] ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "    Please re-open PowerShell as Administrator (Run as Administrator)."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptDir
$FullDriverPath = Join-Path $WorkspaceRoot $DriverPath

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " CYBERV KERNEL DRIVER INSTALLATION PIPELINE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Service Name:    $ServiceName"
Write-Host "[*] Driver Path:     $FullDriverPath`n"

if (-not (Test-Path $FullDriverPath)) {
    Write-Host "[-] ERROR: Driver file not found at: $FullDriverPath" -ForegroundColor Red
    Write-Host "    Compile the driver first using: scripts/build-driver.ps1"
    exit 1
}

# Check if service already exists
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "[*] Service '$ServiceName' already exists. Stopping and removing old instance..." -ForegroundColor Yellow
    & sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Create driver service
Write-Host "[*] Registering kernel driver service with SCM..." -ForegroundColor Cyan
$createOutput = & sc.exe create $ServiceName binPath= "$FullDriverPath" type= kernel start= demand DisplayName= "CyberV Hardware Security Probe Driver"
Write-Host $createOutput

# Start driver service
Write-Host "[*] Starting kernel driver service..." -ForegroundColor Cyan
$startOutput = & sc.exe start $ServiceName
Write-Host $startOutput

# Check status
Start-Sleep -Seconds 1
$queryOutput = & sc.exe query $ServiceName
Write-Host "`n[+] Service Status:" -ForegroundColor Green
Write-Host $queryOutput

if ($queryOutput -match "RUNNING") {
    Write-Host "`n[+] SUCCESS: CyberV Kernel Driver is RUNNING!" -ForegroundColor Green
    Write-Host "    Process protection and IOCTL interface \\.\CyberVProbe are now ACTIVE." -ForegroundColor Green
} else {
    Write-Host "`n[!] Driver service was registered but not running. Check Windows Event Viewer (System log)." -ForegroundColor Yellow
}
