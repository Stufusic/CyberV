"""
CyberV Application Lifecycle & System Tray Manager
Ref: Docs/ui.md Section 17 & Docs/ủiv.md Section 2
"""

import sys
from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtCore import Qt
from ..styles.stylesheet import get_application_stylesheet
from ..styles.palette import ThemePalette
from ..ui.windows.main_window import MainWindow
from ..viewmodels import (
    DashboardViewModel,
    ProtectionViewModel,
    EventsViewModel,
    SystemViewModel,
    RecoveryViewModel,
    DiagnosticsViewModel,
)
from ..services.agent_service import AgentServiceProvider
from ..services.mock_service import MockServiceProvider


class CyberVApplication:
    def __init__(self, sys_argv=None, mock_profile: str = None, live_mode: bool = False):
        self.app = QApplication.instance() or QApplication(sys_argv or sys.argv)
        self.app.setApplicationName("CyberV Endpoint Security")
        self.app.setQuitOnLastWindowClosed(False)  # Keep running in system tray
        self.app.setStyleSheet(get_application_stylesheet())

        # Initialize ViewModels
        self.dashboard_vm = DashboardViewModel()
        self.protection_vm = ProtectionViewModel()
        self.events_vm = EventsViewModel()
        self.system_vm = SystemViewModel()
        self.recovery_vm = RecoveryViewModel()
        self.diagnostics_vm = DiagnosticsViewModel()

        # Initialize Main Window
        self.window = MainWindow(
            self.dashboard_vm,
            self.protection_vm,
            self.events_vm,
            self.system_vm,
            self.recovery_vm,
            self.diagnostics_vm,
        )

        # Initialize System Tray
        self._setup_tray()

        # Wire refresh
        self.window.refresh_requested.connect(self._refresh_telemetry)

        # Service configuration
        self.mock_profile_name = mock_profile
        self.live_mode = live_mode or (mock_profile is None)
        self.agent_service: Optional[AgentServiceProvider] = None

        if self.live_mode and self.mock_profile_name is None:
            self.agent_service = AgentServiceProvider(
                self.dashboard_vm,
                self.protection_vm,
                self.events_vm,
                self.system_vm,
                self.recovery_vm,
                self.diagnostics_vm,
            )
            self.agent_service.start()
        else:
            self._refresh_telemetry()

    def _create_tray_icon_pixmap(self, color_hex: str) -> QPixmap:
        """Draws a clean, sharp 32x32 rounded security shield tray icon with status dot."""
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Outer dark ring
        painter.setBrush(QColor("#161B22"))
        painter.setPen(QColor("#30363D"))
        painter.drawRoundedRect(2, 2, 28, 28, 8, 8)

        # Status glowing dot in center
        painter.setBrush(QColor(color_hex))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(8, 8, 16, 16)
        painter.end()
        return pixmap

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self.window)
        initial_pixmap = self._create_tray_icon_pixmap("#8B949E")
        self.tray.setIcon(QIcon(initial_pixmap))
        self.tray.setToolTip("CyberV Endpoint Security - Monitoring")

        # Tray Menu
        self.tray_menu = QMenu()
        self.status_action = self.tray_menu.addAction("CyberV: Checking...")
        self.status_action.setEnabled(False)
        self.tray_menu.addSeparator()

        open_action = self.tray_menu.addAction("📊 Mở Bảng Điều Khiển (Dashboard)")
        open_action.triggered.connect(self._show_window)

        prot_action = self.tray_menu.addAction("🛡️ Trạng Thái Lá Chắn Kernel")
        prot_action.triggered.connect(lambda: (self._show_window(), self.window._switch_page(1)))

        events_action = self.tray_menu.addAction("📜 Nhật Ký Sự Kiện An Ninh")
        events_action.triggered.connect(lambda: (self._show_window(), self.window._switch_page(2)))

        self.tray_menu.addSeparator()
        quit_action = self.tray_menu.addAction("Thoát Hoàn Toàn")
        quit_action.triggered.connect(self.quit)

        self.tray.setContextMenu(self.tray_menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

        # Connect status updates to tray icon and toasts
        self.dashboard_vm.protection_changed.connect(self._on_tray_status_update)

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._show_window()

    def _show_window(self):
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def _on_tray_status_update(self, info):
        token = ThemePalette.get_status_token(info.state.value)
        self.tray.setIcon(QIcon(self._create_tray_icon_pixmap(token.bright)))
        self.status_action.setText(f"CyberV: ● {info.state.value} ({info.substate})")
        self.tray.setToolTip(f"CyberV: {info.state.value} - {info.reason}")

        # Toast notification on Degraded or Isolated states
        if info.state.value in ("DEGRADED", "ISOLATED", "ERROR"):
            self.tray.showMessage(
                f"CẢNH BÁO AN NINH: {info.state.value}",
                f"{info.reason}\nNhấn để kiểm tra lá chắn phòng vệ.",
                QSystemTrayIcon.Warning if info.state.value == "DEGRADED" else QSystemTrayIcon.Critical,
                5000,
            )

    def _refresh_telemetry(self):
        if self.live_mode and self.mock_profile_name is None:
            if self.agent_service:
                self.agent_service.poll_agent()
        else:
            profile = self.mock_profile_name or "protected"
            provider = MockServiceProvider(profile)
            provider.populate_viewmodels(
                self.dashboard_vm,
                self.protection_vm,
                self.events_vm,
                self.system_vm,
                self.recovery_vm,
                self.diagnostics_vm,
            )

    def run(self) -> int:
        self.window.show()
        return self.app.exec()

    def quit(self):
        self.tray.hide()
        self.app.quit()
