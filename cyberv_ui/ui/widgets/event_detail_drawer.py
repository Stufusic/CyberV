"""
Event Detail Drawer Widget
Ref: Docs/ui.md Section 12

Slide-out or side panel showing technical breakdown of a selected event.
Excludes secrets, credentials, and private keys.
"""

from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QWidget
from PySide6.QtCore import Qt, Signal
from ...models.events import SecurityEvent
from ...styles.palette import ThemePalette


class EventDetailDrawerWidget(QFrame):
    closed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setFixedWidth(360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header_layout = QHBoxLayout()
        self._title = QLabel("CHI TIẾT SỰ KIỆN", self)
        self._title.setStyleSheet("font-size: 13px; font-weight: 700; color: #E6EDF3; letter-spacing: 0.5px;")

        self._close_btn = QPushButton("✕", self)
        self._close_btn.setFixedSize(24, 24)
        self._close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #8B949E;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                color: #F85149;
            }
        """)
        self._close_btn.clicked.connect(self.closed.emit)

        header_layout.addWidget(self._title)
        header_layout.addStretch()
        header_layout.addWidget(self._close_btn)
        layout.addLayout(header_layout)

        # Divider
        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("background-color: #30363D; max-height: 1px;")
        layout.addWidget(divider)

        # Scrollable content area
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        self.c_layout = QVBoxLayout(container)
        self.c_layout.setContentsMargins(0, 0, 0, 0)
        self.c_layout.setSpacing(10)

        self._id_val = self._add_field("Mã Sự Kiện (Event ID):", "N/A", is_mono=True)
        self._type_val = self._add_field("Phân Loại:", "N/A")
        self._sev_val = self._add_field("Mức Độ (Severity):", "N/A")
        self._time_val = self._add_field("Thời Gian:", "N/A", is_mono=True)
        self._source_val = self._add_field("Nguồn Phát Sinh:", "N/A")
        self._state_trans_val = self._add_field("Chuyển Dịch Trạng Thái:", "N/A")
        self._trigger_val = self._add_field("Cơ Chế Kích Hoạt (Trigger):", "N/A")
        self._evidence_val = self._add_field("Bằng Chứng Kỹ Thuật (Evidence):", "N/A", is_mono=True)
        self._reason_val = self._add_field("Lý Do Phán Quyết (Reason):", "N/A")

        self.c_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll)

    def _add_field(self, label_text: str, default_val: str, is_mono: bool = False) -> QLabel:
        lbl = QLabel(label_text, self)
        lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #8B949E; margin-top: 4px;")
        self.c_layout.addWidget(lbl)

        val = QLabel(default_val, self)
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if is_mono:
            val.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; color: #58A6FF; background: #0A0D12; padding: 4px 6px; border-radius: 4px;")
        else:
            val.setStyleSheet("font-size: 12px; color: #E6EDF3; padding: 2px 0px;")
        self.c_layout.addWidget(val)
        return val

    def display_event(self, event: SecurityEvent):
        if not event:
            return
        self._id_val.setText(event.event_id)
        self._type_val.setText(event.event_type)
        self._sev_val.setText(event.severity.value)
        self._time_val.setText(event.timestamp)
        self._source_val.setText(event.source)
        self._state_trans_val.setText(f"{event.previous_state}  →  {event.current_state}")
        self._trigger_val.setText(event.trigger)
        self._evidence_val.setText(event.evidence)
        self._reason_val.setText(event.reason)
        self.setVisible(True)
