"""
Protection State & Telemetry Models
Ref: Docs/ui.md Section 7, 8, 21 & Docs/ủiv.md Section 4
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProtectionState(Enum):
    LOCAL = "LOCAL"               # Sapphire Blue - Local hardware assessment (Kernel shield inactive)
    VERIFYING = "VERIFYING"       # Amber Gold - Handshaking and authenticating with Core Agent
    UNKNOWN = "UNKNOWN"           # Gray - Disconnected or unverified
    STARTING = "STARTING"         # Blue - Bootstrapping agent
    PROTECTED = "PROTECTED"       # Green - Kernel callback active, driver verified, policy ok
    DEGRADED = "DEGRADED"         # Amber/Orange - Driver missing, callback lost, or telemetry stale
    ATTENTION = "ATTENTION"       # Orange - Hardware mutation pending review
    ISOLATED = "ISOLATED"         # Red - Emergency lockdown
    RECOVERY = "RECOVERY"         # Purple - Recovery signature required
    ERROR = "ERROR"               # Dark Red - Internal agent error

    @property
    def display_name(self) -> str:
        return self.value

    @property
    def is_safe(self) -> bool:
        return self == ProtectionState.PROTECTED


@dataclass
class ProtectionStateInfo:
    state: ProtectionState
    substate: str = "INITIALIZING"
    reason: str = "System is starting up"
    since: str = "Just now"
    confidence: str = "LOW"       # HIGH, MEDIUM, LOW
    device_id: str = "Unknown"
    details: Optional[str] = None


@dataclass
class KernelShieldInfo:
    driver_status: str = "OFFLINE"            # ACTIVE, OFFLINE, NOT_INSTALLED
    driver_version: str = "0.0.0"
    loaded_at: str = "N/A"
    callback_active: bool = False
    protected_pid: int = 0
    blocked_terminations: int = 0
    blocked_vm_reads: int = 0
    blocked_vm_writes: int = 0
    telemetry_updated_at: str = "N/A"
    pci_observations_count: int = 0
    raw_error: Optional[str] = None


@dataclass
class PolicyChecklistInfo:
    kernel_shield: bool = False
    process_shield: bool = False
    telemetry_verified: bool = False
    policy_engine_active: bool = False
    evidence_fresh: bool = False

    @property
    def all_active(self) -> bool:
        return (
            self.kernel_shield
            and self.process_shield
            and self.telemetry_verified
            and self.policy_engine_active
            and self.evidence_fresh
        )
