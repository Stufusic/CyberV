"""
Event Timeline Widget
Ref: Docs/ui.md Section 11
"""

from typing import List
from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QWidget
from PySide6.QtCore import Qt, Signal
from ...models.events import SecurityEvent
from ...styles.palette import ThemePalette


class EventTimelineItem(QFrame):
    clicked = Signal(str)  # event_id

    def __init__(self, event: SecurityEvent, parent=None):
        super().__init__(parent)
        self.event_id = event.event_id
        self.setStyleSheet("""
            QFrame {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QFrame:hover {
                background-color: #21262D;
                border: 1px solid #58A6FF;
            }
        """)
        self.setCursor(Qt.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(12)

        # Time
        time_label = QLabel(event.time_short, self)
        time_label.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; color: #8B949E; font-weight: bold;")
        time_label.setFixedWidth(65)

        # Indicator dot
        dot = QLabel("●", self)
        token = ThemePalette.get_status_token(event.severity.badge_type)
        dot.setStyleSheet(f"color: {token.bright}; font-size: 12px;")

        # Content layout
        content_layout = QVBoxLayout()
        content_layout.setSpacing(2)

        source_label = QLabel(event.source, self)
        source_label.setStyleSheet("font-size: 11px; color: #8B949E; font-weight: 600; text-transform: uppercase;")

        type_label = QLabel(event.event_type, self)
        type_label.setStyleSheet("font-size: 13px; color: #E6EDF3; font-weight: 600;")

        content_layout.addWidget(source_label)
        content_layout.addWidget(type_label)

        layout.addWidget(time_label)
        layout.addWidget(dot)
        layout.addLayout(content_layout)
        layout.addStretch()

        # Severity Badge
        sev_label = QLabel(event.severity.value, self)
        sev_label.setStyleSheet(f"""
            background-color: {token.bg_subtle};
            color: {token.bright};
            border: 1px solid {token.border};
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 10px;
            font-weight: bold;
        """)
        layout.addWidget(sev_label)

    def mousePressEvent(self, event):
        self.clicked.emit(self.event_id)
        super().mousePressEvent(event)


class EventTimelineWidget(QWidget):
    event_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(True)

        self._container = QWidget()
        self._container_layout = QVBoxLayout(self._container)
        self._container_layout.setContentsMargins(0, 0, 0, 0)
        self._container_layout.setSpacing(6)
        self._container_layout.addStretch()

        self._scroll.setWidget(self._container)
        main_layout.addWidget(self._scroll)

    def set_events(self, events: List[SecurityEvent]):
        # Clear existing items
        while self._container_layout.count() > 1:
            item = self._container_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not events:
            no_events = QLabel("Không có sự kiện an ninh nào được ghi nhận.", self._container)
            no_events.setStyleSheet("color: #8B949E; font-style: italic; padding: 20px;")
            no_events.setAlignment(Qt.AlignCenter)
            self._container_layout.insertWidget(0, no_events)
            return

        for ev in events:
            item_widget = EventTimelineItem(ev, self._container)
            item_widget.clicked.connect(self.event_selected.emit)
            self._container_layout.insertWidget(self._container_layout.count() - 1, item_widget)
