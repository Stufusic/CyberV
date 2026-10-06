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
