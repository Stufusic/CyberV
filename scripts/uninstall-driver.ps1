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
# CyberV Kernel Driver Stop & Uninstallation Script
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File scripts/uninstall-driver.ps1

param(
    [string]$ServiceName = "CyberVProbe"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[-] ERROR: This script requires Administrator privileges." -ForegroundColor Red
    exit 1
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " CYBERV KERNEL DRIVER UNINSTALLATION" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Service Name: $ServiceName`n"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "[+] Service '$ServiceName' is not registered. Nothing to remove." -ForegroundColor Green
    exit 0
}

Write-Host "[*] Stopping driver service..." -ForegroundColor Cyan
& sc.exe stop $ServiceName

Start-Sleep -Seconds 1

Write-Host "[*] Deleting driver service registration..." -ForegroundColor Cyan
& sc.exe delete $ServiceName

Write-Host "[+] Driver uninstalled successfully." -ForegroundColor Green
