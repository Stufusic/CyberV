"""
Events Page
Ref: Docs/ui.md Section 11, 12
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame
from ..widgets.event_timeline import EventTimelineWidget
from ..widgets.event_detail_drawer import EventDetailDrawerWidget
from ...viewmodels.events_viewmodel import EventsViewModel


class EventsPage(QWidget):
    def __init__(self, viewmodel: EventsViewModel, parent=None):
        super().__init__(parent)
        self.vm = viewmodel

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # Left: Main events view
        left_widget = QWidget(self)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(14)

        title_box = QVBoxLayout()
        title = QLabel("NHẬT KÝ SỰ KIỆN AN NINH (TIMELINE)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Theo dõi các chu kỳ chứng thực, thay đổi trạng thái và sự kiện phòng vệ", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        left_layout.addLayout(title_box)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)

        self._filter_btns = {}
        for cat in ("ALL", "KERNEL", "PROTECTION", "RECOVERY", "ERRORS"):
            btn = QPushButton(cat, self)
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.setChecked(cat == "ALL")
            btn.clicked.connect(lambda checked, c=cat: self.vm.set_filter(c))
            filter_bar.addWidget(btn)
            self._filter_btns[cat] = btn

        filter_bar.addStretch()
        left_layout.addLayout(filter_bar)

        # Timeline
        self.timeline = EventTimelineWidget(self)
        self.timeline.event_selected.connect(self.vm.select_event)
        left_layout.addWidget(self.timeline)

        main_layout.addWidget(left_widget, stretch=1)

        # Right: Detail drawer
        self.drawer = EventDetailDrawerWidget(self)
        self.drawer.setVisible(False)
        self.drawer.closed.connect(lambda: self.drawer.setVisible(False))
        main_layout.addWidget(self.drawer)

        # Connect VM signals
        self.vm.events_filtered_changed.connect(self.timeline.set_events)
        self.vm.selected_event_changed.connect(self._on_selected_event_changed)

    def _on_selected_event_changed(self, event):
        if event:
            self.drawer.display_event(event)
        else:
            self.drawer.setVisible(False)
