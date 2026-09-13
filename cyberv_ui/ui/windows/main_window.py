"""
Main Window for CyberV Desktop
Ref: Docs/ui.md Section 5, 6 & Docs/ủiv.md Section 2
"""

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QFrame,
)
from PySide6.QtCore import Qt, Signal
from ..widgets.status_badge import StatusBadgeWidget
from ..pages import (
    DashboardPage,
    ProtectionPage,
    EventsPage,
    SystemPage,
    RecoveryPage,
    DiagnosticsPage,
    SettingsPage,
    AboutPage,
)


class MainWindow(QMainWindow):
    refresh_requested = Signal()

    def __init__(
        self,
        dashboard_vm,
        protection_vm,
        events_vm,
        system_vm,
        recovery_vm,
        diagnostics_vm,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("CyberV Endpoint Security Platform")
        self.setMinimumSize(1050, 700)
        self.resize(1150, 760)

        # Central Widget
        self.central_widget = QWidget(self)
        self.central_widget.setObjectName("central_widget")
        self.setCentralWidget(self.central_widget)

        root_layout = QHBoxLayout(self.central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ----------------------------------------------------------------------
        # 1. Sidebar Navigation
        # ----------------------------------------------------------------------
        self.sidebar = QFrame(self.central_widget)
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)

        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(14, 18, 14, 18)
        sb_layout.setSpacing(6)

        # Brand header
        brand_layout = QHBoxLayout()
        brand_icon = QLabel("🛡️", self.sidebar)
        brand_icon.setStyleSheet("font-size: 20px;")
        brand_title = QLabel("CYBERV", self.sidebar)
        brand_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #58A6FF; letter-spacing: 1px;")
        brand_layout.addWidget(brand_icon)
        brand_layout.addWidget(brand_title)
        brand_layout.addStretch()
        sb_layout.addLayout(brand_layout)

        sb_subtitle = QLabel("Hardware-Anchored Trust", self.sidebar)
        sb_subtitle.setStyleSheet("font-size: 10px; color: #8B949E; margin-bottom: 14px; margin-left: 2px;")
        sb_layout.addWidget(sb_subtitle)

        # Navigation Buttons
        self.nav_buttons = []
        nav_items = [
            ("📊 Dashboard", 0),
            ("🛡️ Protection", 1),
            ("📜 Events", 2),
            ("💻 System", 3),
            ("🔑 Recovery", 4),
            ("🔬 Diagnostics", 5),
            ("⚙️ Settings", 6),
            ("ℹ️ About", 7),
        ]

        for label, page_idx in nav_items:
            btn = QPushButton(label, self.sidebar)
            btn.setObjectName("nav_btn")
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.clicked.connect(lambda checked, idx=page_idx: self._switch_page(idx))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sb_layout.addStretch()

        # Engine Version footer
        ver_lbl = QLabel("Engine: v0.1.0 (KMDF 1.15)", self.sidebar)
        ver_lbl.setStyleSheet("font-size: 10px; color: #484F58; text-align: center;")
        ver_lbl.setAlignment(Qt.AlignCenter)
        sb_layout.addWidget(ver_lbl)

        root_layout.addWidget(self.sidebar)

        # ----------------------------------------------------------------------
        # 2. Right Content Area (Top Bar + QStackedWidget)
        # ----------------------------------------------------------------------
        content_area = QWidget(self.central_widget)
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Top Bar
        self.top_bar = QFrame(content_area)
        self.top_bar.setObjectName("top_bar")
        self.top_bar.setFixedHeight(54)

        tb_layout = QHBoxLayout(self.top_bar)
        tb_layout.setContentsMargins(20, 0, 20, 0)

        self.global_status_badge = StatusBadgeWidget(self.top_bar, "UNKNOWN", "Checking")
        tb_layout.addWidget(self.global_status_badge)
        tb_layout.addStretch()

        self.refresh_btn = QPushButton("🔄 Làm Mới Dữ Liệu", self.top_bar)
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        tb_layout.addWidget(self.refresh_btn)

        content_layout.addWidget(self.top_bar)

        # Stacked Pages
        self.stack = QStackedWidget(content_area)
        self.page_dashboard = DashboardPage(dashboard_vm, self.stack)
        self.page_protection = ProtectionPage(protection_vm, self.stack)
        self.page_events = EventsPage(events_vm, self.stack)
        self.page_system = SystemPage(system_vm, self.stack)
        self.page_recovery = RecoveryPage(recovery_vm, self.stack)
        self.page_diagnostics = DiagnosticsPage(diagnostics_vm, self.stack)
        self.page_settings = SettingsPage(self.stack)
        self.page_about = AboutPage(self.stack)

        self.stack.addWidget(self.page_dashboard)    # 0
        self.stack.addWidget(self.page_protection)   # 1
        self.stack.addWidget(self.page_events)       # 2
        self.stack.addWidget(self.page_system)       # 3
        self.stack.addWidget(self.page_recovery)     # 4
        self.stack.addWidget(self.page_diagnostics)  # 5
        self.stack.addWidget(self.page_settings)     # 6
        self.stack.addWidget(self.page_about)        # 7

        content_layout.addWidget(self.stack)
        root_layout.addWidget(content_area, stretch=1)

        # Select first page by default
        self._switch_page(0)

        # Hook status update to top bar badge
        dashboard_vm.protection_changed.connect(self._on_protection_changed)

    def _switch_page(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

    def _on_protection_changed(self, info):
        self.global_status_badge.set_state(info.state.value, info.substate)
