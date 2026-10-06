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
"""
Fault Injection and Edge Case Tests for CyberV UI
Tests behavior under subsystem failures, driver crashes, and malformed IPC packets.
"""

import unittest
from cyberv_ui.ipc.protocol import (
    IpcMessageEnvelope,
    IpcResponseEnvelope,
    MAX_IPC_MESSAGE_SIZE,
    MessageTooLargeError,
    EmptyPayloadError,
    DeserializationError,
)
from cyberv_ui.models.protection import ProtectionState
from cyberv_ui.security.display_policy import resolve_display_state
from cyberv_ui.viewmodels.dashboard_viewmodel import DashboardViewModel
from cyberv_ui.viewmodels.protection_viewmodel import ProtectionViewModel


class TestFaultInjection(unittest.TestCase):

    def test_malformed_oversized_ipc_packet(self):
        """Messages > 64KB must be rejected immediately to prevent buffer overrun."""
        huge_payload = b"A" * (MAX_IPC_MESSAGE_SIZE + 10)
        with self.assertRaises(MessageTooLargeError):
            IpcMessageEnvelope.from_bytes(huge_payload)

        with self.assertRaises(MessageTooLargeError):
            IpcResponseEnvelope.from_bytes(huge_payload)

    def test_empty_ipc_payload(self):
        """Empty IPC payloads must raise EmptyPayloadError."""
        with self.assertRaises(EmptyPayloadError):
            IpcMessageEnvelope.from_bytes(b"")

        with self.assertRaises(EmptyPayloadError):
            IpcResponseEnvelope.from_bytes(b"")

    def test_corrupted_json_payload(self):
        """Non-JSON or malformed payload must raise DeserializationError."""
        with self.assertRaises(DeserializationError):
            IpcMessageEnvelope.from_bytes(b"{not: valid, json")

    def test_agent_abrupt_disconnect_fault(self):
        """If IPC connection is severed, UI must fail-closed to UNKNOWN."""
        vm = DashboardViewModel()
        # Initially healthy
        vm.update_from_raw_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            is_ipc_connected=True,
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.PROTECTED)

        # Fault injected: Pipe disconnected (Anti-Downgrade Invariant: Protected -> DEGRADED)
        vm.update_from_raw_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            is_ipc_connected=False,
            reason="Named pipe broken",
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.DEGRADED)
        self.assertEqual(vm.protection_info.substate, "IPC_DISCONNECTED")

    def test_driver_unloaded_while_agent_online(self):
        """If KMDF driver is unloaded while agent runs, state must drop to DEGRADED."""
        vm = DashboardViewModel()
        vm.update_from_raw_state(
            kernel_available=False,
            callback_active=False,
            policy_decision="PROTECT",
            is_ipc_connected=True,
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.DEGRADED)
        self.assertEqual(vm.protection_info.substate, "KERNEL_PROBE_OFFLINE")

    def test_tamper_attempt_tpm_rollback_fault(self):
        """If TPM monotonic counter decreases, emergency lockdown must engage."""
        vm = DashboardViewModel()
        vm.update_from_raw_state(
            kernel_available=True,
            callback_active=True,
            policy_decision="PROTECT",
            hardware_verified=True,
            tpm_contradiction=True,
            is_ipc_connected=True,
        )
        self.assertEqual(vm.protection_info.state, ProtectionState.ISOLATED)
        self.assertEqual(vm.protection_info.substate, "EMERGENCY_LOCKDOWN")


if __name__ == "__main__":
    unittest.main()
