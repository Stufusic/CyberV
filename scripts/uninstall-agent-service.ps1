# ==============================================================================
# CyberV Agent - Windows Service Uninstallation Script
# Description: Stops and unregisters CyberV Agent service from SCM.
# Requirements: Run as Administrator in PowerShell
# ==============================================================================

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  CyberV Agent - Windows Service Uninstallation" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Check Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to modify Windows Services."
    Write-Warning "Please relaunch PowerShell as Administrator and run this script again."
    exit 1
}

$RootDir = (Resolve-Path "$PSScriptRoot\..").Path
$ReleaseExe = Join-Path $RootDir "target\release\cyberv-agent.exe"
$DebugExe = Join-Path $RootDir "target\debug\cyberv-agent.exe"

$AgentExe = if (Test-Path $ReleaseExe) { $ReleaseExe } elseif (Test-Path $DebugExe) { $DebugExe } else { $null }

if ($AgentExe) {
    Write-Host "[*] Stopping and removing service via CyberV Agent CLI..." -ForegroundColor Yellow
    & $AgentExe stop
    & $AgentExe uninstall
} else {
    Write-Host "[*] Executable not found locally, falling back to sc.exe..." -ForegroundColor Yellow
    sc.exe stop CyberVAgent
    Start-Sleep -Seconds 1
    sc.exe delete CyberVAgent
}

Write-Host "[+] CyberV Agent service uninstallation completed." -ForegroundColor Green
