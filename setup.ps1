# ====================================================================
# CyberV: Quick Setup Alias
# Automatically verifies & installs Python, Rust, and C/C++ toolchains
# ====================================================================
$Script = Join-Path $PSScriptRoot "scripts\setup-env.ps1"
& powershell -ExecutionPolicy Bypass -File $Script
