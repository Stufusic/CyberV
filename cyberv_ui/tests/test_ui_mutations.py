"""
UI Mutation Testing Suite (MUT-UI-01 through MUT-UI-04)
Ref: Docs/ủiv.md Section 9 & implementation_plan.md Phase 6
Verifies that code mutations or faulty display logic cannot produce deceptive security signals.
"""

import unittest
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QColor

from cyberv_ui.models.protection import ProtectionState, ProtectionStateInfo
from cyberv_ui.security.display_policy import resolve_display_state
from cyberv_ui.styles.palette import ThemePalette
from cyberv_ui.ui.widgets.status_badge import StatusBadgeWidget


class TestUiMutations(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a single QApplication for widget instantiation tests
        cls.app = QApplication.instance() or QApplication([])

    def test_mut_ui_01_unknown_state_never_green(self):
        """
        MUT-UI-01: When state is UNKNOWN, the visual badge MUST be muted gray/steel (#8B949E),
        and under NO circumstances render as green (#3FB950) or show deceptive 'Protected' text.
        """
        badge = StatusBadgeWidget(state="UNKNOWN", substate="DISCONNECTED")
        palette_token = ThemePalette.get_status_token("UNKNOWN")

        # Color mutation assertion: Must be neutral gray/steel, NEVER green
        self.assertEqual(palette_token.primary.upper(), "#8B949E")
        self.assertEqual(palette_token.bright.upper(), "#C9D1D9")
        self.assertNotEqual(palette_token.bright.upper(), "#3FB950")  # Never green
        self.assertNotEqual(palette_token.primary.upper(), "#2EA043")  # Never green

        # Badge widget state text
        self.assertEqual(badge.state_text.upper(), "UNKNOWN")
        self.assertNotIn("PROTECTED", badge.state_text.upper())

    def test_mut_ui_02_ipc_disconnected_mutation_kill(self):
        """
        MUT-UI-02: If IPC is disconnected (is_ipc_connected=False), mutating any other
        parameter (e.g. kernel_available=True, policy_decision='PROTECT') must NEVER
        yield PROTECTED state. Any mutation attempting to return PROTECTED must be killed.
        """
        mutated_permutations = [
            {"kernel_available": True, "callback_active": True, "policy_decision": "PROTECT"},
            {"kernel_available": True, "callback_active": True, "policy_decision": "ACTIVE"},
            {"kernel_available": True, "callback_active": True, "policy_decision": "PERFECT"},
        ]

        for perm in mutated_permutations:
            # Case 1: First run with no IPC -> LOCAL ASSESSMENT, NEVER PROTECTED
            res_local = resolve_display_state(
                kernel_available=perm["kernel_available"],
                callback_active=perm["callback_active"],
                policy_decision=perm["policy_decision"],
                is_ipc_connected=False,
                session_was_protected=False,
            )
            self.assertNotEqual(res_local.state, ProtectionState.PROTECTED)
            self.assertEqual(res_local.state, ProtectionState.LOCAL)

            # Case 2: Protected session losing IPC -> DEGRADED (Anti-Downgrade), NEVER PROTECTED
            res_degraded = resolve_display_state(
                kernel_available=perm["kernel_available"],
                callback_active=perm["callback_active"],
                policy_decision=perm["policy_decision"],
                is_ipc_connected=False,
                session_was_protected=True,
            )
            self.assertNotEqual(res_degraded.state, ProtectionState.PROTECTED)
            self.assertEqual(res_degraded.state, ProtectionState.DEGRADED)

    def test_mut_ui_03_missing_kernel_driver_mutation_kill(self):
        """
        MUT-UI-03: If kernel driver is missing (kernel_available=False), mutating policy_decision
        to 'PROTECT' must be caught and resolved to DEGRADED, NEVER PROTECTED.
        """
        res = resolve_display_state(
            kernel_available=False,  # Driver is not loaded!
            callback_active=False,
            policy_decision="PROTECT",  # Falsely optimistic policy
            is_ipc_connected=True,
        )

        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "KERNEL_PROBE_OFFLINE")
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)

    def test_mut_ui_04_unverified_hardware_mutation_kill(self):
        """
        MUT-UI-04: If hardware_verified is False (unverified topology or uncommitted hash),
        mutating policy_decision to 'PROTECT' must be downgraded to DEGRADED.
        """
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=False,  # Hardware unverified!
            is_ipc_connected=True,
        )

        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "EVIDENCE_UNVERIFIED")
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)


if __name__ == "__main__":
    unittest.main()
