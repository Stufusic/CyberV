"""
Mock Service Provider for CyberV UI
Ref: Docs/ủiv.md Section 8

Enables offline development and testing of all security UX states
without requiring live kernel driver or agent SCM service.
"""

import os
import json
from typing import Dict, Any, List
from ..models.protection import ProtectionState, KernelShieldInfo
from ..models.events import SecurityEvent, EventSeverity


class MockServiceProvider:
    PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mock_profiles")

    def __init__(self, profile_name: str = "protected"):
        self.profile_name = profile_name.lower().strip()
        self.data = self._load_profile(self.profile_name)

    def _load_profile(self, profile_name: str) -> Dict[str, Any]:
        file_path = os.path.join(self.PROFILES_DIR, f"{profile_name}.json")
        if not os.path.exists(file_path):
            file_path = os.path.join(self.PROFILES_DIR, "protected.json")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "state": "UNKNOWN",
                "policy_decision": "UNKNOWN",
                "kernel_available": False,
                "callback_active": False,
                "hardware_verified": False,
                "tpm_contradiction": False,
                "in_recovery": False,
                "is_ipc_connected": False,
                "reason": "Failed to load mock profile",
                "since": "Now",
            }

    def populate_viewmodels(
        self,
        dashboard_vm,
        protection_vm,
        events_vm,
        system_vm,
        recovery_vm,
        diagnostics_vm,
    ):
        raw = self.data

        # 1. Parse Events
        events: List[SecurityEvent] = []
        for ev in raw.get("recent_events", []):
            try:
                sev = EventSeverity[ev.get("severity", "INFO")]
            except KeyError:
                sev = EventSeverity.INFO

            events.append(SecurityEvent(
                event_id=ev.get("event_id", "EVT-000"),
                timestamp=ev.get("timestamp", "N/A"),
                source=ev.get("source", "System"),
                event_type=ev.get("event_type", "Notice"),
                severity=sev,
                previous_state=ev.get("previous_state", "UNKNOWN"),
                current_state=ev.get("current_state", "UNKNOWN"),
                trigger=ev.get("trigger", "N/A"),
                evidence=ev.get("evidence", "N/A"),
                reason=ev.get("reason", "N/A"),
            ))

        # 2. Update Dashboard VM
        dashboard_vm.update_from_raw_state(
            kernel_available=raw.get("kernel_available", False),
            callback_active=raw.get("callback_active", False),
            policy_decision=raw.get("policy_decision", "UNKNOWN"),
            hardware_verified=raw.get("hardware_verified", True),
            tpm_contradiction=raw.get("tpm_contradiction", False),
            in_recovery=raw.get("in_recovery", False),
            is_ipc_connected=raw.get("is_ipc_connected", True),
            reason=raw.get("reason"),
            since_str=raw.get("since", "Just now"),
            recent_events=events,
        )

        # 3. Update Protection VM
        d_info = raw.get("driver", {})
        protection_vm.update_shield_info(KernelShieldInfo(
            driver_status=d_info.get("status", "OFFLINE"),
            driver_version=d_info.get("version", "Unknown"),
            loaded_at=d_info.get("loaded_at", "N/A"),
            callback_active=d_info.get("callback_active", False),
            protected_pid=d_info.get("protected_pid", 0),
            blocked_terminations=d_info.get("blocked_terminations", 0),
            blocked_vm_reads=d_info.get("blocked_vm_reads", 0),
            blocked_vm_writes=d_info.get("blocked_vm_writes", 0),
            telemetry_updated_at=d_info.get("telemetry_updated_at", "N/A"),
            pci_observations_count=d_info.get("pci_observations_count", 0),
        ))

        # 4. Update Events VM
        events_vm.set_events(events)

        # 5. Update System VM
        observed = [
            {"component": "CPU Processor", "model": "Intel Core i7-12700K (12 Cores, 20 Threads)", "status": "ACTIVE"},
            {"component": "Motherboard", "model": "ASUSTeK COMPUTER INC. (ROG STRIX Z690-A)", "status": "ACTIVE"},
            {"component": "Memory Module 0", "model": "Corsair Vengeance DDR5 16GB 5600MHz", "status": "ACTIVE"},
            {"component": "Memory Module 1", "model": "Corsair Vengeance DDR5 16GB 5600MHz", "status": "ACTIVE"},
            {"component": "NVMe Storage 0", "model": "Samsung SSD 980 PRO 1TB (PCIe Gen4 x4)", "status": "ACTIVE"},
        ]
        verified = [
            {"tier": "Tier 1: Component Hashes", "algorithm": "SHA-512 FIPS 180-4", "status": "VERIFIED"},
            {"tier": "Tier 2-4: Topology Graph", "nodes": "Root + 5 Real + 3 Virtual Nodes", "status": "VERIFIED" if raw.get("hardware_verified") else "UNVERIFIED"},
            {"tier": "Tier 5: Verification Hash", "commitment": "c8f39a02d41b...e92f", "status": "VERIFIED" if raw.get("hardware_verified") else "UNVERIFIED"},
            {"tier": "Tier 6: Final State Hash", "state_hash": "a401bc77e21a...8831", "status": "VERIFIED" if raw.get("hardware_verified") else "UNVERIFIED"},
            {"tier": "TPM 2.0 NV Monotonic Counter", "counter_index": "0x01800001", "status": "PASS" if not raw.get("tpm_contradiction") else "CONTRADICTION_FAIL"},
        ]
        system_vm.update_hardware_data(observed, verified)

        # 6. Update Recovery VM
        if raw.get("in_recovery"):
            rec_data = raw.get("recovery", {})
            recovery_vm.set_recovery_challenge(
                challenge_id=rec_data.get("challenge_id", "CHAL-DEMO-001"),
                ttl_seconds=rec_data.get("ttl_seconds", 60),
                reason=raw.get("reason", "Recovery Required"),
            )

        # 7. Run initial diagnostics
        diagnostics_vm.run_diagnostics(
            kernel_available=raw.get("kernel_available", False),
            callback_active=raw.get("callback_active", False),
            is_ipc_connected=raw.get("is_ipc_connected", True),
            hardware_verified=raw.get("hardware_verified", True),
        )
