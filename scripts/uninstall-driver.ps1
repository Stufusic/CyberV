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
