"""
Status Badge Widget
Ref: Docs/ui.md Section 4.2 & Docs/ủiv.md Section 4

Always renders both semantic color AND text label:
● PROTECTED - Kernel protection active
▲ DEGRADED - Kernel Probe Offline
✖ ISOLATED - Emergency Lockdown
"""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel
from PySide6.QtCore import Qt
from ...styles.palette import ThemePalette, StatusColorToken


class StatusBadgeWidget(QFrame):
    def __init__(
        self,
        parent=None,
        state_text: str = None,
        subtext: str = None,
        state: str = None,
        substate: str = None,
    ):
        super().__init__(parent)
        self.setObjectName("status_badge_frame")
        self._current_state = state or state_text or "UNKNOWN"
        self._current_substate = substate or subtext or ""

        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(10, 5, 12, 5)
        self._layout.setSpacing(8)

        self._dot_label = QLabel(self)
        self._dot_label.setFixedSize(10, 10)

        self._text_label = QLabel(self._current_state, self)
        self._text_label.setStyleSheet("font-weight: 700; font-size: 12px; letter-spacing: 0.5px;")

        self._subtext_label = QLabel(f"• {self._current_substate}" if self._current_substate else "", self)
        self._subtext_label.setStyleSheet("font-weight: 400; font-size: 11px; color: #8B949E;")

        self._layout.addWidget(self._dot_label)
        self._layout.addWidget(self._text_label)
        self._layout.addWidget(self._subtext_label)
        self._layout.addStretch()

        self.set_state(self._current_state, self._current_substate)

    @property
    def state_text(self) -> str:
        return self._current_state

    def set_state(self, state_text: str, subtext: str = None):
        self._current_state = (state_text or "UNKNOWN").upper().strip()
        self._current_substate = subtext or ""
        state_upper = self._current_state
        token: StatusColorToken = ThemePalette.get_status_token(state_upper)

        # Draw rounded indicator dot
        self._dot_label.setStyleSheet(f"""
            background-color: {token.bright};
            border-radius: 5px;
        """)

        # Style text and frame container
        icon_symbol = "●"
        display_label = state_upper
        if state_upper in ("DEGRADED", "WARN", "WARNING"):
            icon_symbol = "▲"
        elif state_upper in ("ISOLATED", "FAIL", "ERROR"):
            icon_symbol = "✖"
        elif state_upper in ("RECOVERY", "RECOVERYPENDING"):
            icon_symbol = "◆"
        elif state_upper in ("VERIFYING", "HANDSHAKING", "STARTING"):
            icon_symbol = "◆"
        elif state_upper in ("LOCAL", "LOCAL_ASSESSMENT"):
            icon_symbol = "●"
            display_label = "LOCAL ASSESSMENT"

        self._text_label.setText(f"{icon_symbol} {display_label}")
        self._text_label.setStyleSheet(f"font-weight: 700; font-size: 12px; color: {token.bright};")

        if subtext:
            self._subtext_label.setText(f"• {subtext}")
            self._subtext_label.setVisible(True)
        else:
            self._subtext_label.setVisible(False)

        self.setStyleSheet(f"""
            QFrame#status_badge_frame {{
                background-color: {token.bg_subtle};
                border: 1px solid {token.border};
                border-radius: 6px;
            }}
        """)
