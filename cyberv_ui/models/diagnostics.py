"""
Diagnostics Models (4-Tier Diagnostics Engine)
Ref: Docs/ui.md Section 15 & Docs/ủiv.md Section 7
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class DiagnosticTier(Enum):
    DRIVER = "[1] DRIVER"
    CORE_AGENT = "[2] CORE AGENT"
    PROTOCOL = "[3] PROTOCOL"
    SECURITY = "[4] SECURITY"


@dataclass
class DiagnosticItem:
    name: str
    status: str             # "PASS", "FAIL", "WARN", "INFO"
    evidence: str
    tier: DiagnosticTier


@dataclass
class DiagnosticReport:
    generated_at: str
    overall_status: str     # "PASS", "WARN", "FAIL"
    items: List[DiagnosticItem] = field(default_factory=list)

    @property
    def total_checks(self) -> int:
        return len(self.items)

    @property
    def passed_count(self) -> int:
        return sum(1 for item in self.items if item.status == "PASS")

    @property
    def failed_count(self) -> int:
        return sum(1 for item in self.items if item.status == "FAIL")

    @property
    def warning_count(self) -> int:
        return sum(1 for item in self.items if item.status == "WARN")
