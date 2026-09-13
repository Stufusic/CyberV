"""
Dashboard ViewModel
Ref: Docs/ui.md Section 6, 7 & Docs/ủiv.md Section 5
"""

from typing import List
from PySide6.QtCore import Signal
from .base import BaseViewModel
from ..models.protection import ProtectionState, ProtectionStateInfo, PolicyChecklistInfo
from ..models.events import SecurityEvent
from ..security.display_policy import resolve_display_state


class DashboardViewModel(BaseViewModel):
    protection_changed = Signal(ProtectionStateInfo)
    checklist_changed = Signal(PolicyChecklistInfo)
    recent_events_changed = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._protection_info = ProtectionStateInfo(
            state=ProtectionState.UNKNOWN,
            substate="INITIALIZING",
            reason="Connecting to CyberV Core Agent...",
            since="Just now",
        )
        self._checklist = PolicyChecklistInfo()
        self._recent_events: List[SecurityEvent] = []
        self._session_was_protected: bool = False

    @property
    def protection_info(self) -> ProtectionStateInfo:
        return self._protection_info

    @property
    def checklist(self) -> PolicyChecklistInfo:
        return self._checklist

    @property
    def recent_events(self) -> List[SecurityEvent]:
        return self._recent_events

    def update_from_raw_state(
        self,
        kernel_available: bool,
        callback_active: bool,
        policy_decision: str,
        hardware_verified: bool = True,
        tpm_contradiction: bool = False,
        in_recovery: bool = False,
        is_ipc_connected: bool = True,
        session_was_protected: bool = None,
        is_verifying: bool = False,
        reason: str = None,
        since_str: str = "Just now",
        recent_events: List[SecurityEvent] = None,
    ):
        if session_was_protected is not None:
            self._session_was_protected = session_was_protected

        # Enforce Display Policy Gatekeeper (Invariant Rules)
        self._protection_info = resolve_display_state(
            kernel_available=kernel_available,
            callback_active=callback_active,
            policy_decision=policy_decision,
            hardware_verified=hardware_verified,
            tpm_contradiction=tpm_contradiction,
            in_recovery=in_recovery,
            is_ipc_connected=is_ipc_connected,
            session_was_protected=self._session_was_protected,
            is_verifying=is_verifying,
            since_timestamp=since_str,
            raw_reason=reason,
        )

        if self._protection_info.state == ProtectionState.PROTECTED:
            self._session_was_protected = True

        # Update Checklist (Technical Truth)
        self._checklist = PolicyChecklistInfo(
            kernel_shield=kernel_available and callback_active,
            process_shield=callback_active,
            telemetry_verified=hardware_verified and kernel_available,
            policy_engine_active=is_ipc_connected,
            evidence_fresh=hardware_verified,
        )

        if recent_events is not None:
            self._recent_events = recent_events[:5]  # Top 5 recent events

        self.protection_changed.emit(self._protection_info)
        self.checklist_changed.emit(self._checklist)
        self.recent_events_changed.emit(self._recent_events)
        self.state_updated.emit()
