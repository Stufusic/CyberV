"""
Security Event Models
Ref: Docs/ui.md Section 11, 12
"""

from dataclasses import dataclass
from enum import Enum


class EventSeverity(Enum):
    INFO = "INFO"             # Normal operation (telemetry refreshed)
    NOTICE = "NOTICE"         # State transition (policy -> PROTECTED)
    WARNING = "WARNING"       # Hardware mutation, offline grace period
    CRITICAL = "CRITICAL"     # Driver missing, signature verification failed
    EMERGENCY = "EMERGENCY"   # Rollback detected, emergency ISOLATE

    @property
    def badge_type(self) -> str:
        mapping = {
            EventSeverity.INFO: "UNKNOWN",
            EventSeverity.NOTICE: "PROTECTED",
            EventSeverity.WARNING: "DEGRADED",
            EventSeverity.CRITICAL: "ATTENTION",
            EventSeverity.EMERGENCY: "ISOLATED",
        }
        return mapping.get(self, "UNKNOWN")


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: EventSeverity
    previous_state: str
    current_state: str
    trigger: str
    evidence: str
    reason: str

    @property
    def time_short(self) -> str:
        # Extract HH:MM:SS from timestamp if possible
        if " " in self.timestamp:
            return self.timestamp.split(" ")[1]
        if "T" in self.timestamp:
            return self.timestamp.split("T")[1][:8]
        return self.timestamp
