# CyberV Driver Code Signing Pipeline
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/sign-driver.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/sign-driver.ps1 -DriverPath "release/driver/x64/CyberVProbe.sys"
#   powershell -ExecutionPolicy Bypass -File scripts/sign-driver.ps1 -CreateCertOnly

param(
    [string]$DriverPath = "release/driver/x64/CyberVProbe.sys",
    [switch]$CreateCertOnly,
    [string]$CertSubject = "CN=CyberV Security Test Driver CA"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptDir
$TargetDriverFile = Join-Path $WorkspaceRoot $DriverPath

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " CYBERV KERNEL DRIVER TEST-SIGNING PIPELINE" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Target Driver:   $TargetDriverFile"
Write-Host "[*] Cert Subject:    $CertSubject`n"

# 1. Locate SignTool.exe from Windows SDK
$sdkBinDirs = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object -Descending
if (-not $sdkBinDirs -or $sdkBinDirs.Count -eq 0) {
    Write-Host "[-] ERROR: signtool.exe was not found in Windows Kits." -ForegroundColor Red
    exit 1
}
$signtoolPath = $sdkBinDirs[0].FullName
Write-Host "[+] Found SignTool:  $signtoolPath" -ForegroundColor Green

# 2. Check or Create Self-Signed Code Signing Certificate
$existingCert = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $CertSubject } | Select-Object -First 1

if (-not $existingCert) {
    Write-Host "[*] Creating new self-signed Code Signing Certificate..." -ForegroundColor Cyan
    try {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert `
            -Subject $CertSubject `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -KeyUsage DigitalSignature `
            -FriendlyName "CyberV Kernel Driver Test Certificate" `
            -NotAfter (Get-Date).AddYears(5)
        Write-Host "[+] Created certificate thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

        # Install into Trusted Root and Trusted Publisher stores
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $rootStore.Open("ReadWrite")
        $rootStore.Add($cert)
        $rootStore.Close()

        $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
        $pubStore.Open("ReadWrite")
        $pubStore.Add($cert)
        $pubStore.Close()
        Write-Host "[+] Certificate installed into LocalMachine Root & TrustedPublisher stores." -ForegroundColor Green
        $existingCert = $cert
    }
    catch {
        Write-Host "[!] Note: Administrator privileges are required to install certificates into LocalMachine store." -ForegroundColor Yellow
        Write-Host "    Error: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "[+] Using existing certificate: $($existingCert.Thumbprint)" -ForegroundColor Green
}

if ($CreateCertOnly) {
    Write-Host "[+] Certificate setup complete."
    exit 0
}

# 3. Verify driver file existence
if (-not (Test-Path $TargetDriverFile)) {
    Write-Host "[!] Target driver file not found at: $TargetDriverFile" -ForegroundColor Yellow
    Write-Host "    Build the driver first using: scripts/build-driver.ps1"
    exit 0
}

# 4. Sign driver binary using signtool.exe
Write-Host "`n[*] Signing driver binary with SHA-256..." -ForegroundColor Cyan
$signArgs = @(
    "sign",
    "/sm",
    "/s", "My",
    "/n", "CyberV Security Test Driver CA",
    "/fd", "SHA256",
    "/v",
    "`"$TargetDriverFile`""
)

$process = Start-Process -FilePath $signtoolPath -ArgumentList $signArgs -NoNewWindow -PassThru -Wait

if ($process.ExitCode -eq 0) {
    Write-Host "`n[+] DRIVER SIGNING SUCCESSFUL!" -ForegroundColor Green
    Write-Host "[*] Verifying signature..."
    Start-Process -FilePath $signtoolPath -ArgumentList @("verify", "/pa", "/v", "`"$TargetDriverFile`"") -NoNewWindow -Wait
    
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "[!] IMPORTANT FOR LOADING ON WINDOWS 64-BIT:" -ForegroundColor Yellow
    Write-Host "    To load test-signed kernel drivers on Windows, run as Administrator:"
    Write-Host "    bcdedit /set testsigning on" -ForegroundColor Cyan
    Write-Host "    (Requires system restart if not previously enabled)"
    Write-Host "=================================================================" -ForegroundColor Cyan
} else {
    Write-Host "`n[-] DRIVER SIGNING FAILED with exit code $($process.ExitCode)." -ForegroundColor Red
    exit $process.ExitCode
}
