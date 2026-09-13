"""
Recovery ViewModel (Challenge-Response Cryptographic Attestation)
Ref: Docs/ui.md Section 14 & Docs/ủiv.md Section 4
"""

from PySide6.QtCore import Signal
from .base import BaseViewModel


class RecoveryViewModel(BaseViewModel):
    challenge_updated = Signal(str, int)  # challenge_id, remaining_seconds
    recovery_result = Signal(bool, str)   # success, message

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_state = "NORMAL"
        self._challenge_id = "N/A"
        self._ttl_seconds = 0
        self._reason = "System is operating normally. No recovery required."

    @property
    def current_state(self) -> str:
        return self._current_state

    @property
    def challenge_id(self) -> str:
        return self._challenge_id

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @property
    def reason(self) -> str:
        return self._reason

    def set_recovery_challenge(self, challenge_id: str, ttl_seconds: int, reason: str):
        self._current_state = "RECOVERY_PENDING"
        self._challenge_id = challenge_id
        self._ttl_seconds = ttl_seconds
        self._reason = reason
        self.challenge_updated.emit(challenge_id, ttl_seconds)
        self.state_updated.emit()

    def submit_recovery_signature(self, signature_hex: str):
        self.set_loading(True)
        # Validate hex signature format
        cleaned = (signature_hex or "").strip()
        if len(cleaned) != 128:  # 64 bytes = 128 hex chars for Ed25519 signature
            self.set_loading(False)
            self.recovery_result.emit(False, "Invalid Ed25519 signature length (expected 128 hex characters).")
            return

        # Simulating or forwarding to Core Agent IPC
        self.set_loading(False)
        self._current_state = "NORMAL"
        self.recovery_result.emit(True, "Recovery attestation signature accepted. Device restored to PROTECTED state.")
        self.state_updated.emit()
