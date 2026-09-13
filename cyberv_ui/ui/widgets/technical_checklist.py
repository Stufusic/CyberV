"""
Technical Truth Checklist Widget
Ref: Docs/ui.md Section 7 & Docs/ủiv.md Section 5

Renders the 5 verified security invariant pillars:
1. Kernel Shield
2. Process Protection
3. Kernel Telemetry
4. Policy Engine
5. Device Evidence
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel
from PySide6.QtCore import Qt
from ...styles.palette import ThemePalette
from ...models.protection import PolicyChecklistInfo


class ChecklistRow(QFrame):
    def __init__(self, title: str, active: bool = False, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent; border: none;")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self._icon_label = QLabel(self)
        self._icon_label.setFixedWidth(24)

        self._title_label = QLabel(title, self)
        self._title_label.setStyleSheet("font-size: 13px; color: #E6EDF3; font-weight: 500;")

        self._status_label = QLabel(self)
        self._status_label.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; font-weight: 700;")
        self._status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        layout.addWidget(self._icon_label)
        layout.addWidget(self._title_label)
        layout.addStretch()
        layout.addWidget(self._status_label)

        self.set_active(active)

    def set_active(self, active: bool):
        if active:
            self._icon_label.setText("✓")
            self._icon_label.setStyleSheet("color: #3FB950; font-weight: bold; font-size: 14px;")
            self._status_label.setText("ACTIVE")
            self._status_label.setStyleSheet("color: #3FB950; font-weight: bold;")
        else:
            self._icon_label.setText("✕")
            self._icon_label.setStyleSheet("color: #F85149; font-weight: bold; font-size: 14px;")
            self._status_label.setText("OFFLINE")
            self._status_label.setStyleSheet("color: #F85149; font-weight: bold;")


class TechnicalChecklistWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(16, 16, 16, 16)

        header = QLabel("CHỐT CHẶN BẢO VỆ CỐT LÕI (TECHNICAL TRUTH)", self)
        header.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        layout.addWidget(header)

        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("background-color: #30363D; max-height: 1px; margin-bottom: 6px;")
        layout.addWidget(divider)

        self.row_kernel = ChecklistRow("Kernel Ring-0 Shield (Altitude 385201)", False, self)
        self.row_process = ChecklistRow("Process Object Protection (Anti-Terminate/Read)", False, self)
        self.row_telemetry = ChecklistRow("Hardware Telemetry Verification (PCI Probe)", False, self)
        self.row_policy = ChecklistRow("Autonomous Fail-Closed Policy Engine", False, self)
        self.row_evidence = ChecklistRow("Device Topological Evidence Graph", False, self)

        layout.addWidget(self.row_kernel)
        layout.addWidget(self.row_process)
        layout.addWidget(self.row_telemetry)
        layout.addWidget(self.row_policy)
        layout.addWidget(self.row_evidence)

    def update_checklist(self, info: PolicyChecklistInfo):
        self.row_kernel.set_active(info.kernel_shield)
        self.row_process.set_active(info.process_shield)
        self.row_telemetry.set_active(info.telemetry_verified)
        self.row_policy.set_active(info.policy_engine_active)
        self.row_evidence.set_active(info.evidence_fresh)
