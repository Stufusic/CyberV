# CyberV Automated Safe Mutation Testing Runner (Tier 2)
# Ref: Docs/mutesst.md & Docs/newpl.md (Phase 13)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/run_mutation_tests.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/run_mutation_tests.ps1 -MutantFilter MUT-01

param(
    [string]$MutantFilter = "ALL",
    [switch]$VerboseLog
)

$ErrorActionPreference = "Stop"

# Base directory is workspace root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptDir
$AgentDir = Join-Path $WorkspaceRoot "agent"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " CYBERV HIGH-ASSURANCE SECURITY MUTATION TESTING RUNNER (TIER 2)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "[*] Workspace Root: $WorkspaceRoot"
Write-Host "[*] Agent CWD:      $AgentDir"
Write-Host "[*] Mutant Filter:  $MutantFilter`n"

# Define 16 Security Mutants across 4 Domains mapped to INV-001 through INV-008
$Mutants = @(
    # DOMAIN 1: Kernel Enforcement & Driver Protection
    @{
        Id = "MUT-01"; Invariant = "INV-001"; Domain = "Kernel Enforcement"
        Description = "Kernel Shield Inactive Fail-Open Bypass"
        RelativePath = "agent/src/defense/policy.rs"
        Original = "} else if !kernel_report.telemetry.is_shield_active || kernel_report.defense_score <= 3000 {"
        Mutated  = "} else if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_01_shield_inactive_forces_isolate"
    },
    @{
        Id = "MUT-09"; Invariant = "INV-004"; Domain = "Kernel Enforcement"
        Description = "IOCTL ABI Code Regression (0x80006000 -> 0x80002000)"
        RelativePath = "agent/src/kernel/protocol.rs"
        Original = "pub const IOCTL_CYBERV_GET_PCI_INFO: u32 = 0x80006000;"
        Mutated  = "pub const IOCTL_CYBERV_GET_PCI_INFO: u32 = 0x80002000;"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_09_ioctl_abi_contract"
    },
    @{
        Id = "MUT-12"; Invariant = "INV-004"; Domain = "Kernel Enforcement"
        Description = "Caller PID Ownership Validation Bypass"
        RelativePath = "agent/tests/kernel_security_fault_injection_tests.rs"
        Original = "if caller_pid != target_pid && caller_pid != 4 {"
        Mutated  = "if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_12_unauthorized_pid_registration_rejected"
    },
    @{
        Id = "MUT-13"; Invariant = "INV-004"; Domain = "Kernel Enforcement"
        Description = "Driver Unload Cleanup Omission"
        RelativePath = "agent/tests/kernel_security_fault_injection_tests.rs"
        Original = "self.callbacks_registered = false;"
        Mutated  = "// self.callbacks_registered = false;"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_13_driver_unload_cleanup_omission"
    },
    @{
        Id = "MUT-14"; Invariant = "INV-001"; Domain = "Kernel Enforcement"
        Description = "Driver Unreachable Score Degradation Masking"
        RelativePath = "agent/src/defense/kernel/anti_tamper.rs"
        Original = "if !driver_reachable {`r`n            is_tampering_detected = true;`r`n            defense_score = 3000;"
        Mutated  = "if !driver_reachable {`r`n            is_tampering_detected = false;`r`n            defense_score = 10000;"
        OriginalFallback = "if !driver_reachable {`n            is_tampering_detected = true;`n            defense_score = 3000;"
        MutatedFallback  = "if !driver_reachable {`n            is_tampering_detected = false;`n            defense_score = 10000;"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_14_driver_unreachable_must_degrade_score"
    },
    @{
        Id = "MUT-15"; Invariant = "INV-004"; Domain = "Kernel Enforcement"
        Description = "PID Reuse Window Timestamp Check Bypass"
        RelativePath = "agent/tests/kernel_security_fault_injection_tests.rs"
        Original = "if stored_pid == incoming_pid && stored_create_time != incoming_create_time {"
        Mutated  = "if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_15_pid_reuse_different_time_rejected"
    },
    @{
        Id = "MUT-16"; Invariant = "INV-004"; Domain = "Kernel Enforcement"
        Description = "Kernel Target Process Check Bypass"
        RelativePath = "agent/tests/kernel_security_fault_injection_tests.rs"
        Original = "if target_pid == protected_pid {"
        Mutated  = "if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_16_target_process_check_bypass"
    },

    # DOMAIN 2: Security Decision & Policy Engine
    @{
        Id = "MUT-02"; Invariant = "INV-001"; Domain = "Policy Decision"
        Description = "Critical Score Degradation Threshold Bypass"
        RelativePath = "agent/src/defense/policy.rs"
        Original = "let decision = if composite_score < config.step_up_threshold {"
        Mutated  = "let decision = if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_02_critically_degraded_score_must_isolate"
    },
    @{
        Id = "MUT-03"; Invariant = "INV-002"; Domain = "Policy Decision"
        Description = "Missing Driver Falsely Marked Hardware Verified"
        RelativePath = "agent/src/kernel/cross_validator.rs"
        Original = "status: ValidationStatus::Unknown,`r`n                consistency_score: 10000,`r`n                penalty: 0,`r`n                is_hardware_verified: false,"
        Mutated  = "status: ValidationStatus::Unknown,`r`n                consistency_score: 10000,`r`n                penalty: 0,`r`n                is_hardware_verified: true,"
        OriginalFallback = "status: ValidationStatus::Unknown,`n                consistency_score: 10000,`n                penalty: 0,`n                is_hardware_verified: false,"
        MutatedFallback  = "status: ValidationStatus::Unknown,`n                consistency_score: 10000,`n                penalty: 0,`n                is_hardware_verified: true,"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_03_missing_driver_never_verified"
    },
    @{
        Id = "MUT-11"; Invariant = "INV-007"; Domain = "Policy Decision"
        Description = "Process Mitigation Fallback Verification Flag Inversion"
        RelativePath = "agent/src/defense/passive/process_mitigations.rs"
        Original = "is_verified: true,"
        Mutated  = "is_verified: false,"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_11_unverified_mitigations_honesty"
    },

    # DOMAIN 3: State Machine, Anti-Rollback & Replay
    @{
        Id = "MUT-05"; Invariant = "INV-003"; Domain = "State Integrity"
        Description = "Replayed Challenge ID Check Bypass"
        RelativePath = "agent/src/defense/recovery/re_attestation.rs"
        Original = "if challenge.challenge_id != proof.challenge_id {"
        Mutated  = "if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_05_replayed_challenge_must_be_rejected"
    },
    @{
        Id = "MUT-06"; Invariant = "INV-005"; Domain = "State Integrity"
        Description = "Unverified Package Staging Gate Bypass"
        RelativePath = "agent/src/defense/passive/update/staging.rs"
        Original = "UpdateStagingState::Current => {`r`n                if is_verification_passed {"
        Mutated  = "UpdateStagingState::Current => {`r`n                if true {"
        OriginalFallback = "UpdateStagingState::Current => {`n                if is_verification_passed {"
        MutatedFallback  = "UpdateStagingState::Current => {`n                if true {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_06_unverified_package_cannot_stage"
    },
    @{
        Id = "MUT-07"; Invariant = "INV-006"; Domain = "State Integrity"
        Description = "TPM Counter Rollback Contradiction Bypass"
        RelativePath = "agent/src/defense/passive/update/staging.rs"
        Original = "// Không có marker: kiểm tra xem có contradiction giữa version và counter không`r`n                if (active_version as u64) < tpm_counter {"
        Mutated  = "// Không có marker: kiểm tra xem có contradiction giữa version và counter không`r`n                if false {"
        OriginalFallback = "// Không có marker: kiểm tra xem có contradiction giữa version và counter không`n                if (active_version as u64) < tpm_counter {"
        MutatedFallback  = "// Không có marker: kiểm tra xem có contradiction giữa version và counter không`n                if false {"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_07_tpm_counter_rollback_detected"
    },

    # DOMAIN 4: Recovery, Concurrency & Memory Resilience
    @{
        Id = "MUT-04"; Invariant = "INV-003"; Domain = "Recovery & Crypto"
        Description = "Ed25519 Asymmetric Signature Verification Bypass"
        RelativePath = "agent/src/defense/recovery/re_attestation.rs"
        Original = "verifying_key`r`n                .verify_strict(&canonical_msg, &signature)`r`n                .map_err(|_| `"Invalid admin authorization signature (Ed25519 verification failed)`")?;"
        Mutated  = "let _ = (&verifying_key, &canonical_msg, &signature);"
        OriginalFallback = "verifying_key`n                .verify_strict(&canonical_msg, &signature)`n                .map_err(|_| `"Invalid admin authorization signature (Ed25519 verification failed)`")?;"
        MutatedFallback  = "let _ = (&verifying_key, &canonical_msg, &signature);"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_04_forged_ed25519_signature_rejected"
    },
    @{
        Id = "MUT-08"; Invariant = "INV-006"; Domain = "Recovery & Concurrency"
        Description = "EventBus Mutex Poison Recovery Silent Drop"
        RelativePath = "agent/src/defense/passive/event_bus.rs"
        Original = "Err(poisoned) => {`r`n                let mut lock = poisoned.into_inner();`r`n                lock.push(event);`r`n            }"
        Mutated  = "Err(_) => return,"
        OriginalFallback = "Err(poisoned) => {`n                let mut lock = poisoned.into_inner();`n                lock.push(event);`n            }"
        MutatedFallback  = "Err(_) => return,"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_08_mutex_poison_preserves_events"
    },
    @{
        Id = "MUT-10"; Invariant = "INV-008"; Domain = "Memory Isolation"
        Description = "Secure Buffer Zeroization Elimination (Dead-Store)"
        RelativePath = "agent/src/defense/enclave/boundary.rs"
        Original = "self.data.zeroize();"
        Mutated  = "// self.data.zeroize();"
        TestTarget = "kernel_security_fault_injection_tests"
        TestFilter = "test_mutant_10_enclave_buffer_zeroize_on_drop"
    }
)

# Results tracking
$Results = @()
$KilledTestCount = 0
$KilledCompileCount = 0
$SurvivedCount = 0
$RunnerErrorCount = 0

foreach ($m in $Mutants) {
    if ($MutantFilter -ne "ALL" -and $m.Id -ne $MutantFilter) {
        continue
    }

    $filePath = Join-Path $WorkspaceRoot $m.RelativePath
    $bakPath = $filePath + ".mut_bak"

    Write-Host "[*] Evaluating $($m.Id) [$($m.Invariant)] - $($m.Description)..." -NoNewline

    if (-not (Test-Path $filePath)) {
        Write-Host " [RUNNER_ERROR: File Not Found]" -ForegroundColor Red
        $Results += @{
            Id = $m.Id; Invariant = $m.Invariant; Status = "RUNNER_ERROR"; Reason = "File not found"
        }
        $RunnerErrorCount++
        continue
    }

    # Safe atomic byte read
    $originalBytes = [System.IO.File]::ReadAllBytes($filePath)
    $originalText = [System.Text.Encoding]::UTF8.GetString($originalBytes)

    # Determine match
    $targetOrig = $m.Original
    $targetMut = $m.Mutated

    if (-not $originalText.Contains($targetOrig) -and $m.ContainsKey("OriginalFallback")) {
        if ($originalText.Contains($m.OriginalFallback)) {
            $targetOrig = $m.OriginalFallback
            $targetMut = $m.MutatedFallback
        }
    }

    # Verify single occurrence
    $idx1 = $originalText.IndexOf($targetOrig)
    if ($idx1 -lt 0) {
        Write-Host " [RUNNER_ERROR: Substring Not Found]" -ForegroundColor Red
        if ($VerboseLog) { Write-Host "DEBUG: Missing: $targetOrig" }
        $Results += @{
            Id = $m.Id; Invariant = $m.Invariant; Status = "RUNNER_ERROR"; Reason = "Substring not found"
        }
        $RunnerErrorCount++
        continue
    }

    $idx2 = $originalText.IndexOf($targetOrig, $idx1 + $targetOrig.Length)
    if ($idx2 -ge 0) {
        Write-Host " [RUNNER_ERROR: Multiple Matches Found]" -ForegroundColor Red
        $Results += @{
            Id = $m.Id; Invariant = $m.Invariant; Status = "RUNNER_ERROR"; Reason = "Multiple occurrences of target string"
        }
        $RunnerErrorCount++
        continue
    }

    # Create safe backup file
    [System.IO.File]::WriteAllBytes($bakPath, $originalBytes)

    $mutatedText = $originalText.Substring(0, $idx1) + $targetMut + $originalText.Substring($idx1 + $targetOrig.Length)

    $status = "UNKNOWN"
    $reason = ""

    try {
        # Apply mutation
        $mutatedBytes = [System.Text.Encoding]::UTF8.GetBytes($mutatedText)
        [System.IO.File]::WriteAllBytes($filePath, $mutatedBytes)

        # Execute targeted cargo test
        $cargoArgs = "test --test $($m.TestTarget) $($m.TestFilter) -- --nocapture"
        
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "cargo"
        $pinfo.Arguments = $cargoArgs
        $pinfo.WorkingDirectory = $AgentDir
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.UseShellExecute = $false
        $pinfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $pinfo
        $process.Start() | Out-Null
        
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        [void]$process.WaitForExit(60000) # 60s timeout

        $combinedOutput = "$stdout`n$stderr"
        $exitCode = $process.ExitCode

        if ($exitCode -ne 0) {
            if ($combinedOutput.Contains("could not compile") -or $combinedOutput.Contains("error[E")) {
                $status = "KILLED_COMPILE_FAILURE"
                $reason = "Compiler rejected mutated syntax"
                $KilledCompileCount++
                Write-Host " [KILLED - COMPILE ERROR]" -ForegroundColor Yellow
            } else {
                $status = "KILLED_TEST_FAILURE"
                $reason = "Test oracle caught mutation"
                $KilledTestCount++
                Write-Host " [KILLED by $($m.TestFilter)]" -ForegroundColor Green
            }
        } else {
            $status = "SURVIVED"
            $reason = "Test passed despite active mutation (BLIND SPOT!)"
            $SurvivedCount++
            Write-Host " [SURVIVED - BLIND SPOT DETECTED!]" -ForegroundColor Red
        }

        if ($VerboseLog) {
            Write-Host "=== Output ===" -ForegroundColor Gray
            Write-Host $combinedOutput -ForegroundColor Gray
            Write-Host "==============" -ForegroundColor Gray
        }
    }
    catch {
        $status = "RUNNER_ERROR"
        $reason = $_.Exception.Message
        $RunnerErrorCount++
        Write-Host " [RUNNER EXCEPTION: $($_.Exception.Message)]" -ForegroundColor Red
    }
    finally {
        # Strict restoration of exact original bytes
        if (Test-Path $bakPath) {
            [System.IO.File]::WriteAllBytes($filePath, $originalBytes)
            Remove-Item -Path $bakPath -Force -ErrorAction SilentlyContinue
        }
    }

    $Results += @{
        Id = $m.Id
        Invariant = $m.Invariant
        Domain = $m.Domain
        Description = $m.Description
        Status = $status
        Reason = $reason
    }
}

# Summary calculations
$TotalTested = $Results.Count
$ValidMutants = $KilledTestCount + $KilledCompileCount + $SurvivedCount
$MutationScore = 0.0
if ($ValidMutants -gt 0) {
    $MutationScore = [Math]::Round((($KilledTestCount + $KilledCompileCount) / $ValidMutants) * 100.0, 2)
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " MUTATION TESTING RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$Results | ForEach-Object {
    $color = "Green"
    if ($_.Status -eq "SURVIVED") { $color = "Red" }
    elseif ($_.Status -eq "RUNNER_ERROR") { $color = "Magenta" }
    elseif ($_.Status -eq "KILLED_COMPILE_FAILURE") { $color = "Yellow" }

    Write-Host ("{0,-8} | {1,-8} | {2,-24} | {3}" -f $_.Id, $_.Invariant, $_.Status, $_.Description) -ForegroundColor $color
}

Write-Host "-----------------------------------------------------------------"
Write-Host "Total Mutants Evaluated:   $TotalTested"
Write-Host "Mutants Killed by Test:    $KilledTestCount" -ForegroundColor Green
Write-Host "Mutants Killed by Compile: $KilledCompileCount" -ForegroundColor Yellow
Write-Host "Mutants Survived:          $SurvivedCount" -ForegroundColor $(if ($SurvivedCount -eq 0) { "Green" } else { "Red" })
Write-Host "Runner Errors:             $RunnerErrorCount"
Write-Host "-----------------------------------------------------------------"
Write-Host "CATALOGUE MUTATION SCORE:  $MutationScore%" -ForegroundColor $(if ($MutationScore -eq 100.0) { "Green" } else { "Yellow" })
Write-Host "=================================================================`n"

# Invariant Resistance Breakdown
Write-Host "=== SECURITY INVARIANT RESISTANCE BREAKDOWN ===" -ForegroundColor Cyan
$Invariants = @("INV-001", "INV-002", "INV-003", "INV-004", "INV-005", "INV-006", "INV-007", "INV-008")
foreach ($inv in $Invariants) {
    $invMutants = @($Results | Where-Object { $_.Invariant -eq $inv })
    $invTotal = $invMutants.Count
    $invKilled = @($invMutants | Where-Object { $_.Status -like "KILLED*" }).Count
    if ($invTotal -gt 0) {
        $invPct = [Math]::Round(($invKilled / $invTotal) * 100.0, 1)
        Write-Host ("{0,-10}: {1,3}% ({2}/{3} Mutants Killed)" -f $inv, $invPct, $invKilled, $invTotal) -ForegroundColor $(if ($invPct -eq 100.0) { "Green" } else { "Red" })
    }
}
Write-Host "===============================================" -ForegroundColor Cyan

# Final sanity check: ensure working tree is clean
$gitStatus = & git status -s
if ($gitStatus -match "\.mut_bak") {
    Write-Warning "Residual backup files found! Cleaning..."
    Get-ChildItem -Path $WorkspaceRoot -Filter "*.mut_bak" -Recurse | Remove-Item -Force
}
