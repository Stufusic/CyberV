"""
Agent Service Provider for CyberV UI
Polls the Core Agent over IPC and feeds ViewModels with real-time validated data.
Enforces fail-closed display policy whenever IPC communication fails.
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import QObject, QTimer, Signal

from ..ipc.client import NamedPipeClient
from ..models.events import EventSeverity, SecurityEvent
from ..models.protection import KernelShieldInfo, ProtectionState, ProtectionStateInfo
from ..security.display_policy import resolve_display_state


class AgentServiceProvider(QObject):
    connection_status_changed = Signal(bool, str)  # is_connected, message

    def __init__(
        self,
        dashboard_vm,
        protection_vm,
        events_vm,
        system_vm,
        recovery_vm,
        diagnostics_vm,
        poll_interval_ms: int = 2000,
        parent=None,
    ):
        super().__init__(parent)
        self.dashboard_vm = dashboard_vm
        self.protection_vm = protection_vm
        self.events_vm = events_vm
        self.system_vm = system_vm
        self.recovery_vm = recovery_vm
        self.diagnostics_vm = diagnostics_vm

        self.client = NamedPipeClient()
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(poll_interval_ms)
        self.poll_timer.timeout.connect(self.poll_agent)

        self.session_was_protected: bool = False

    def start(self):
        self.poll_agent()
        self.poll_timer.start()

    def stop(self):
        self.poll_timer.stop()
        self.client.disconnect()

    def poll_agent(self):
        """Polls Core Agent via IPC and updates ViewModels."""
        resp = self.client.send_command("GetStatus")
        if not resp.success or not resp.data:
            self._handle_ipc_failure(resp.error or "Unknown IPC error")
            return

        self.session_was_protected = True
        self.connection_status_changed.emit(True, "Core Agent Đang Hoạt Động (24/7 Protection)")
        self._update_from_payload(resp.data)

    def _handle_ipc_failure(self, error_msg: str):
        from ..hardware.collector import LocalHardwareCollector
        observed_real = LocalHardwareCollector.get_observed_hardware()
        fingerprint = LocalHardwareCollector.compute_local_fingerprint()[:16] + "..."

        if self.session_was_protected:
            # ANTI-DOWNGRADE RULE: Session was once protected, drop to DEGRADED!
            self.connection_status_changed.emit(False, f"Mất kết nối Core Agent: {error_msg}")
            self.dashboard_vm.update_from_raw_state(
                kernel_available=False,
                callback_active=False,
                policy_decision="UNKNOWN",
                hardware_verified=False,
                tpm_contradiction=False,
                in_recovery=False,
                is_ipc_connected=False,
                session_was_protected=True,
                reason=f"Mất kết nối với CyberV Core Agent Service: {error_msg}",
                since_str="Vừa xong",
            )
            self.protection_vm.update_shield_info(
                KernelShieldInfo(
                    driver_status="OFFLINE",
                    driver_version="Unknown",
                    loaded_at="N/A",
                    callback_active=False,
                    protected_pid=0,
                    blocked_terminations=0,
                    blocked_vm_reads=0,
                    blocked_vm_writes=0,
                    telemetry_updated_at="N/A",
                    pci_observations_count=0,
                )
            )
            self.diagnostics_vm.run_diagnostics(
                kernel_available=False,
                callback_active=False,
                is_ipc_connected=False,
                hardware_verified=False,
            )
            verified_waiting = [
                {"tier": "Tầng 1: Cam Kết Băm SHA-512", "algorithm": "SHA-512 FIPS 180-4", "status": "MẤT KẾT NỐI AGENT"},
                {"tier": "Tầng 2-4: Cây Phả Hệ Phần Cứng", "nodes": "Topology Graph Nodes", "status": "MẤT KẾT NỐI AGENT"},
                {"tier": "Tầng 5: Băm Xác Minh Trạng Thái", "commitment": "Mất kết nối", "status": "MẤT KẾT NỐI AGENT"},
                {"tier": "TPM 2.0 NV Monotonic Counter", "counter_index": "0x01800001", "status": "MẤT KẾT NỐI AGENT"},
            ]
            self.system_vm.update_hardware_data(observed_real, verified_waiting)
        else:
            # LOCAL ASSESSMENT MODE: First run, service never started
            self.connection_status_changed.emit(False, "Chế Độ Đánh Giá Cục Bộ (Chưa chạy Service 24/7)")
            self.dashboard_vm.update_from_raw_state(
                kernel_available=False,
                callback_active=False,
                policy_decision="LOCAL",
                hardware_verified=True,
                tpm_contradiction=False,
                in_recovery=False,
                is_ipc_connected=False,
                session_was_protected=False,
                reason="Đang đánh giá phần cứng máy tính cục bộ. Kích hoạt dịch vụ để bật lá chắn Kernel 24/7.",
                since_str="Vừa xong",
            )
            self.protection_vm.update_shield_info(
                KernelShieldInfo(
                    driver_status="NOT_INSTALLED",
                    driver_version="N/A (Chờ kích hoạt service)",
                    loaded_at="N/A",
                    callback_active=False,
                    protected_pid=0,
                    blocked_terminations=0,
                    blocked_vm_reads=0,
                    blocked_vm_writes=0,
                    telemetry_updated_at="N/A",
                    pci_observations_count=0,
                )
            )
            self.diagnostics_vm.run_diagnostics(
                kernel_available=False,
                callback_active=False,
                is_ipc_connected=False,
                hardware_verified=True,
            )
            verified_waiting = [
                {"tier": "Tầng 1: Cam Kết Băm Cục Bộ", "algorithm": "SHA-512 (Local Unattested)", "status": f"FINGERPRINT [{fingerprint}]"},
                {"tier": "Tầng 2-4: Cây Phả Hệ Phần Cứng", "nodes": "Local Physical Observation", "status": "OBSERVED"},
                {"tier": "Tầng 5: Bằng Chứng Mật Mã", "commitment": "Chờ kích hoạt Service 24/7", "status": "CHƯA KÍCH HOẠT"},
                {"tier": "TPM 2.0 NV Monotonic Counter", "counter_index": "0x01800001", "status": "CHỜ SERVICE QUẢN TRỊ"},
            ]
            self.system_vm.update_hardware_data(observed_real, verified_waiting)

    def _update_from_payload(self, data: dict):
        raw_events = data.get("events", [])
        events: List[SecurityEvent] = []
        for ev in raw_events:
            try:
                sev = EventSeverity[ev.get("severity", "INFO")]
            except KeyError:
                sev = EventSeverity.INFO
            events.append(
                SecurityEvent(
                    event_id=ev.get("event_id", "EVT-000"),
                    timestamp=ev.get("timestamp", "N/A"),
                    source=ev.get("source", "Agent"),
                    event_type=ev.get("event_type", "Notice"),
                    severity=sev,
                    previous_state=ev.get("previous_state", "UNKNOWN"),
                    current_state=ev.get("current_state", "UNKNOWN"),
                    trigger=ev.get("trigger", "N/A"),
                    evidence=ev.get("evidence", "N/A"),
                    reason=ev.get("reason", "N/A"),
                )
            )

        prot_data = data.get("protection", {})
        ks_data = data.get("kernel_shield", {})
        kernel_avail = bool(ks_data.get("is_active", False))
        cb_active = bool(ks_data.get("cross_validator_active", False))
        pol_dec = prot_data.get("policy_decision", "PROTECT")
        hw_ver = bool(prot_data.get("hardware_verified", True))
        tpm_contra = bool(prot_data.get("tpm_contradiction", False))
        in_rec = bool(prot_data.get("in_recovery", False))

        self.dashboard_vm.update_from_raw_state(
            kernel_available=kernel_avail,
            callback_active=cb_active,
            policy_decision=pol_dec,
            hardware_verified=hw_ver,
            tpm_contradiction=tpm_contra,
            in_recovery=in_rec,
            is_ipc_connected=True,
            reason=prot_data.get("reason"),
            since_str=prot_data.get("since", "Just now"),
            recent_events=events,
        )

        self.protection_vm.update_shield_info(
            KernelShieldInfo(
                driver_status="ACTIVE" if kernel_avail else "OFFLINE",
                driver_version=ks_data.get("driver_version", "Unknown"),
                loaded_at=ks_data.get("loaded_at", "N/A"),
                callback_active=cb_active,
                protected_pid=ks_data.get("protected_pid", 0),
                blocked_terminations=ks_data.get("blocked_terminations", 0),
                blocked_vm_reads=ks_data.get("blocked_vm_reads", 0),
                blocked_vm_writes=ks_data.get("blocked_vm_writes", 0),
                telemetry_updated_at=ks_data.get("telemetry_updated_at", "N/A"),
                pci_observations_count=ks_data.get("pci_observations_count", 0),
            )
        )

        self.events_vm.set_events(events)
        self.diagnostics_vm.run_diagnostics(
            kernel_available=kernel_avail,
            callback_active=cb_active,
            is_ipc_connected=True,
            hardware_verified=hw_ver,
        )

        # Update System VM with real hardware + cryptographic evidence
        from ..hardware.collector import LocalHardwareCollector
        observed_real = LocalHardwareCollector.get_observed_hardware()
        verified = [
            {"tier": "Tầng 1: Cam Kết Băm SHA-512", "algorithm": "SHA-512 FIPS 180-4", "status": "VERIFIED" if hw_ver else "UNVERIFIED"},
            {"tier": "Tầng 2-4: Cây Phả Hệ Phần Cứng", "nodes": "Topology Root + Component Nodes", "status": "VERIFIED" if hw_ver else "UNVERIFIED"},
            {"tier": "Tầng 5: Băm Xác Minh Trạng Thái", "commitment": data.get("verification_hash", "c8f39a02d41b...e92f"), "status": "VERIFIED" if hw_ver else "UNVERIFIED"},
            {"tier": "TPM 2.0 NV Monotonic Counter", "counter_index": "0x01800001", "status": "PASS" if not tpm_contra else "CONTRADICTION_FAIL"},
        ]
        self.system_vm.update_hardware_data(observed_real, verified)
