# Security Policy & Vulnerability Disclosure

## 1. Supported Versions

We take the security of CyberV seriously. Because CyberV operates with elevated privileges on Windows (including Session 0 `LocalSystem` service execution, hardware bus communication, and optional Ring-0 kernel drivers), we prioritize prompt remediation of any security vulnerabilities.

| Version | Supported          |
| :------ | :----------------- |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## 2. Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in CyberV, please report it privately:

1. **Email:** Send a detailed advisory report to **`stufusiclab@gmail.com`**.
2. **Subject Line:** `[VULNERABILITY] CyberV - <Brief Component Name>`
3. **Information to Include:**
   - Affected component(s) (e.g., `agent/src/service.rs`, `driver/CyberVProbe`, `DPAPI Vault`, `TPM NV Counter`).
   - Step-by-step reproduction instructions or a minimal Proof-of-Concept (PoC).
   - Potential security impact (e.g., privilege escalation, denial of service, policy bypass, state rollback).
   - Any proposed remediation or patch.

---

## 3. Our Security Commitments

* **Initial Acknowledgment:** Within **48 hours** of receiving your report.
* **Triage & Assessment:** Within **5 business days**, confirming whether the issue is reproducible and assessing its severity (CVSS v3).
* **Coordinated Disclosure:** We adhere to responsible coordinated disclosure guidelines:
  - We will work closely with the reporter to develop and test a fix.
  - A patch will be prepared and released before public advisory publication.
  - Reporters will be credited in the release notes and advisory (unless requested otherwise).

---

## 4. Security Invariant Boundaries

When reporting issues, please reference our core security invariants documented in [`Docs/security_baseline.md`](Docs/security_baseline.md):

* **INV-001 (Fail-Closed Policy):** The policy engine must NEVER default to `Allow` when kernel defenses or driver probes are unreachable, unverified, or degraded.
* **INV-002 (Verification Separation):** Missing or unknown telemetry must NEVER be conflated with verified hardware evidence.
* **INV-003 (Asymmetric Recovery):** System recovery and state re-attestation MUST require a valid asymmetric Ed25519 cryptographic signature.
* **INV-004 (Kernel Shielding):** Protected processes must be shielded from handle duplication, termination, and memory tampering; driver unload must unregister callbacks cleanly.
* **INV-005 (Package Staging):** Unverified packages must be strictly blocked from advancing in update staging pipelines.
* **INV-006 (Contradiction & Resilience):** Hardware rollback contradictions (TPM NV counter mismatch) must force immediate lockdown; event queues must gracefully recover from mutex poisoning.
* **INV-007 (Telemetry Integrity):** Inspection fallback states must accurately report verification flags.
* **INV-008 (Sensitive Memory Zeroization):** Cryptographic keys, seeds, and sensitive enclave memory MUST be guaranteed zeroized on drop.
