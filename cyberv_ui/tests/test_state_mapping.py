"""
Unit Tests for State Mapping & Display Policy Invariants
Ref: Docs/ui.md Section 24, Docs/ủiv.md Section 3
"""

import unittest
from cyberv_ui.models.protection import ProtectionState
from cyberv_ui.security.display_policy import resolve_display_state


class TestStateMapping(unittest.TestCase):

    def test_invariant_0_ipc_disconnected_first_run(self):
        """When IPC is disconnected on first run (session_was_protected=False), state MUST be LOCAL ASSESSMENT."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            is_ipc_connected=False,
            session_was_protected=False,
            raw_reason="Agent pipe offline",
        )
        self.assertEqual(res.state, ProtectionState.LOCAL)
        self.assertEqual(res.substate, "LOCAL_ASSESSMENT")
        self.assertEqual(res.confidence, "MEDIUM")

    def test_invariant_0_anti_downgrade_disconnect(self):
        """When IPC is disconnected after being protected (session_was_protected=True), state MUST be DEGRADED."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            is_ipc_connected=False,
            session_was_protected=True,
            raw_reason="Agent pipe severed",
        )
        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "IPC_DISCONNECTED")
        self.assertEqual(res.confidence, "LOW")

    def test_invariant_1_tpm_contradiction_lockdown(self):
        """TPM rollback contradiction MUST force ISOLATED state."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            tpm_contradiction=True,
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.ISOLATED)
        self.assertEqual(res.substate, "EMERGENCY_LOCKDOWN")
        self.assertEqual(res.confidence, "HIGH")

    def test_invariant_2_recovery_mode(self):
        """Recovery flag forces RECOVERY state."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            in_recovery=True,
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.RECOVERY)
        self.assertEqual(res.substate, "ADMIN_ATTESTATION_REQUIRED")

    def test_invariant_3_kernel_driver_missing_never_protected(self):
        """If kernel driver is unavailable, state can NEVER be PROTECTED."""
        res = resolve_display_state(
            kernel_available=False,
            callback_active=False,
            policy_decision="PROTECT",
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "KERNEL_PROBE_OFFLINE")
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)

    def test_invariant_4_callbacks_inactive_never_protected(self):
        """If cross validator callbacks are inactive, state must be DEGRADED."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=False,
            policy_decision="PROTECT",
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "CALLBACK_NOT_REGISTERED")
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)

    def test_invariant_5_hardware_unverified_degraded(self):
        """If hardware topology is unverified, state is DEGRADED."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=False,
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "EVIDENCE_UNVERIFIED")

    def test_invariant_6_all_healthy_protected(self):
        """When all security criteria pass, state is PROTECTED."""
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            tpm_contradiction=False,
            in_recovery=False,
            is_ipc_connected=True,
        )
        self.assertEqual(res.state, ProtectionState.PROTECTED)
        self.assertEqual(res.substate, "KERNEL_SHIELD_ACTIVE")
        self.assertEqual(res.confidence, "HIGH")

    def test_golden_rule_unknown_and_degraded_not_protected(self):
        """Zero Deceptive Signals: UNKNOWN != PROTECTED and DEGRADED != PROTECTED."""
        self.assertNotEqual(ProtectionState.UNKNOWN, ProtectionState.PROTECTED)
        self.assertNotEqual(ProtectionState.DEGRADED, ProtectionState.PROTECTED)
        self.assertNotEqual(ProtectionState.ISOLATED, ProtectionState.PROTECTED)


if __name__ == "__main__":
    unittest.main()
