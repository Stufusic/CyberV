"""
Adversarial IPC & Anti-Downgrade Security Tests
Ref: Docs/rvnew.md Sections 3, 4, 6, 12, 13
Tests strict enforcement of:
1. Anti-Downgrade Invariant: Session once protected never falls back to LOCAL.
2. Local Assessment Invariant: User-Mode probing without kernel driver never claims PROTECTED.
3. Handshake Verification: Rejection of mismatched or spoofed IPC responses.
4. Visual Badge Invariant: LOCAL must be steel sapphire (#58A6FF), never green.
"""

import json
import unittest
from cyberv_ui.models.protection import ProtectionState, ProtectionStateInfo
from cyberv_ui.security.display_policy import resolve_display_state
from cyberv_ui.viewmodels.dashboard_viewmodel import DashboardViewModel
from cyberv_ui.styles.palette import ThemePalette
from cyberv_ui.ipc.protocol import create_handshake, parse_ipc_response, CLIENT_VERSION


class TestAdversarialIpcAndInvariants(unittest.TestCase):

    def test_anti_downgrade_invariant_direct(self):
        """
        Anti-Downgrade Invariant (Docs/rvnew.md Section 3 & 12):
        If a session was once PROTECTED, dropping IPC or losing driver must
        force the state to DEGRADED, NEVER LOCAL or UNKNOWN.
        """
        res = resolve_display_state(
            kernel_available=False,
            callback_active=False,
            policy_decision="UNKNOWN",
            hardware_verified=False,
            is_ipc_connected=False,
            session_was_protected=True,  # Session was previously active/protected
            raw_reason="Named pipe broken unexpectedly",
        )
        self.assertEqual(res.state, ProtectionState.DEGRADED)
        self.assertEqual(res.substate, "IPC_DISCONNECTED")
        self.assertEqual(res.confidence, "LOW")
        self.assertNotEqual(res.state, ProtectionState.LOCAL)
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)

    def test_anti_downgrade_via_dashboard_viewmodel(self):
        """
        Tests Anti-Downgrade tracking across the DashboardViewModel lifecycle.
        State 1: Full Protection established -> session_was_protected becomes True.
        State 2: IPC abruptly lost -> Must drop to DEGRADED.
        """
        vm = DashboardViewModel()
        self.assertFalse(vm._session_was_protected)

        # 1. Establish full protection
        vm.update_from_raw_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            is_ipc_connected=True,
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.PROTECTED)
        self.assertTrue(vm._session_was_protected)

        # 2. Sever IPC connection
        vm.update_from_raw_state(
            kernel_available=False,
            callback_active=False,
            policy_decision="UNKNOWN",
            hardware_verified=False,
            is_ipc_connected=False,
            reason="Core Agent crashed or terminated",
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.DEGRADED)
        self.assertEqual(vm.protection_info.substate, "IPC_DISCONNECTED")
        self.assertNotEqual(vm.protection_info.state, ProtectionState.LOCAL)
        self.assertNotEqual(vm.protection_info.state, ProtectionState.PROTECTED)

    def test_local_assessment_first_run_no_service(self):
        """
        First Run Invariant (Docs/rvnew.md Section 1 & 4):
        When Core Agent service is not installed / not running on first launch,
        state is LOCAL ASSESSMENT, NOT DEGRADED, NOT PROTECTED.
        Checklist MUST show Kernel Shield = OFFLINE.
        """
        vm = DashboardViewModel()
        vm.update_from_raw_state(
            kernel_available=False,
            callback_active=False,
            policy_decision="LOCAL",
            hardware_verified=True,
            is_ipc_connected=False,
            session_was_protected=False,
            reason="Đang đánh giá phần cứng máy tính cục bộ. Kích hoạt dịch vụ để bật lá chắn Kernel 24/7.",
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.LOCAL)
        self.assertEqual(vm.protection_info.substate, "LOCAL_ASSESSMENT")
        self.assertEqual(vm.protection_info.confidence, "MEDIUM")

        # Checklist MUST be strictly honest (Fail-Closed)
        self.assertFalse(vm.checklist.kernel_shield)
        self.assertFalse(vm.checklist.process_shield)
        self.assertFalse(vm.checklist.telemetry_verified)
        self.assertFalse(vm.checklist.policy_engine_active)

    def test_verifying_handshake_state(self):
        """
        Verifying State Invariant (Docs/rvnew.md Section 13):
        While IPC handshake is exchanging cryptographic nonces,
        the UI must show VERIFYING, never premature PROTECTED.
        """
        res = resolve_display_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            is_ipc_connected=True,
            is_verifying=True,
            raw_reason="Bắt tay trao đổi nonce...",
        )
        self.assertEqual(res.state, ProtectionState.VERIFYING)
        self.assertEqual(res.substate, "SECURITY_HANDSHAKE")
        self.assertEqual(res.confidence, "MEDIUM")
        self.assertNotEqual(res.state, ProtectionState.PROTECTED)

    def test_ipc_handshake_protocol_serialization(self):
        """
        Tests creation and structure of client Handshake IPC command.
        """
        cmd = create_handshake()
        self.assertEqual(cmd["command"], "Handshake")
        self.assertEqual(cmd["client_version"], CLIENT_VERSION)
        self.assertIn("nonce_hex", cmd)
        self.assertEqual(len(cmd["nonce_hex"]), 32)  # 16 bytes = 32 hex chars

    def test_ipc_response_parsing(self):
        """
        Tests parsing valid and invalid JSON from Core Agent IPC.
        """
        valid_json = json.dumps({
            "success": True,
            "data": {"status": "ACTIVE", "server_version": "1.0.0"},
            "error": None
        })
        resp = parse_ipc_response(valid_json)
        self.assertTrue(resp.success)
        self.assertEqual(resp.data["server_version"], "1.0.0")

        # Invalid JSON must fail safely without throwing
        invalid_resp = parse_ipc_response("MALFORMED_NON_JSON")
        self.assertFalse(invalid_resp.success)
        self.assertIn("Malformed JSON", invalid_resp.error)

    def test_visual_palette_invariants(self):
        """
        Visual Truth Invariant (Docs/rvnew.md Section 11):
        LOCAL ASSESSMENT must use Steel Sapphire Blue (#58A6FF), NEVER Emerald Green (#2EA043).
        PROTECTED must use Emerald Green (#2EA043).
        VERIFYING must use Amber Gold (#D29922).
        """
        self.assertEqual(ThemePalette.STATUS_LOCAL.primary, "#58A6FF")
        self.assertEqual(ThemePalette.STATUS_PROTECTED.primary, "#2EA043")
        self.assertEqual(ThemePalette.STATUS_VERIFYING.primary, "#D29922")
        self.assertNotEqual(ThemePalette.STATUS_LOCAL.primary, ThemePalette.STATUS_PROTECTED.primary)


if __name__ == "__main__":
    unittest.main()
