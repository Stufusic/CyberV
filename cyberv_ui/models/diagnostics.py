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
