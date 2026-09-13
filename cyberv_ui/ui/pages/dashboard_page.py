"""
Dashboard Page
Ref: Docs/ui.md Section 6, 7, Docs/ủiv.md Section 5, & Docs/rvnew.md Section 4, 6
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QScrollArea, QGridLayout
)
from PySide6.QtCore import Qt
from ..widgets.status_badge import StatusBadgeWidget
from ..widgets.technical_checklist import TechnicalChecklistWidget
from ..widgets.event_timeline import EventTimelineWidget
from ...viewmodels.dashboard_viewmodel import DashboardViewModel
from ...models.protection import ProtectionState
from ...styles.palette import ThemePalette
from ...services.activation import ServiceActivationController
from ...hardware.collector import LocalHardwareCollector


class DashboardPage(QWidget):
    def __init__(self, viewmodel: DashboardViewModel, parent=None):
        super().__init__(parent)
        self.vm = viewmodel
        self.activation_controller = ServiceActivationController(self)
        self.activation_controller.activation_status_changed.connect(self._on_activation_status)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Page Header
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("TỔNG QUAN HỆ THỐNG AN NINH", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Bảo vệ thiết bị điểm cuối neo giữ phần cứng & lá chắn tầng nhân Ring-0", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # 1. Primary Status Card (Technical Truth, NO fake meters)
        self.status_card = QFrame(self)
        self.status_card.setObjectName("card")
        sc_layout = QVBoxLayout(self.status_card)
        sc_layout.setContentsMargins(20, 20, 20, 20)
        sc_layout.setSpacing(12)

        sc_header = QHBoxLayout()
        sc_label = QLabel("TRẠNG THÁI PHÒNG VỆ HIỆN HỮU (PROTECTION STATE)", self)
        sc_label.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        sc_header.addWidget(sc_label)
        sc_header.addStretch()
        sc_layout.addLayout(sc_header)

        self.badge = StatusBadgeWidget(self, "UNKNOWN", "Initial check")
        sc_layout.addWidget(self.badge)

        self.reason_label = QLabel("Đang kết nối tới dịch vụ an ninh CyberV...", self)
        self.reason_label.setStyleSheet("font-size: 14px; color: #E6EDF3; font-weight: 500;")
        self.reason_label.setWordWrap(True)
        sc_layout.addWidget(self.reason_label)

        self.since_label = QLabel("Thời điểm ghi nhận: Vừa xong", self)
        self.since_label.setStyleSheet("font-size: 12px; color: #8B949E;")
        sc_layout.addWidget(self.since_label)

        # Action Button & UAC Status
        action_box = QVBoxLayout()
        action_box.setSpacing(6)
        
        self.action_btn = QPushButton("🚀 Kích Hoạt Bảo Vệ Ngầm 24/7 (Windows Service)", self)
        self.action_btn.setObjectName("action_btn")
        self.action_btn.setCursor(Qt.PointingHandCursor)
        self.action_btn.setStyleSheet("""
            QPushButton#action_btn {
                background-color: #238636;
                color: #FFFFFF;
                font-weight: 600;
                font-size: 13px;
                padding: 10px 18px;
                border-radius: 6px;
                border: 1px solid rgba(240, 246, 252, 0.1);
                text-align: center;
            }
            QPushButton#action_btn:hover {
                background-color: #2EA043;
            }
            QPushButton#action_btn:pressed {
                background-color: #1F7F34;
            }
            QPushButton#action_btn:disabled {
                background-color: #21262D;
                color: #8B949E;
                border: 1px solid #30363D;
            }
        """)
        self.action_btn.clicked.connect(self._on_activate_clicked)
        action_box.addWidget(self.action_btn)

        self.action_status_label = QLabel("", self)
        self.action_status_label.setStyleSheet("font-size: 12px; color: #58A6FF;")
        self.action_status_label.setWordWrap(True)
        self.action_status_label.setVisible(False)
        action_box.addWidget(self.action_status_label)

        sc_layout.addLayout(action_box)
        layout.addWidget(self.status_card)

        # 2. Two-Block Breakdown Card (Docs/rvnew.md Section 4 & 6)
        breakdown_card = QFrame(self)
        breakdown_card.setObjectName("card")
        bc_layout = QVBoxLayout(breakdown_card)
        bc_layout.setContentsMargins(20, 20, 20, 20)
        bc_layout.setSpacing(14)

        bc_title = QLabel("PHÂN RÃ BẰNG CHỨNG AN NINH (SECURITY BREAKDOWN)", self)
        bc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        bc_layout.addWidget(bc_title)

        blocks_layout = QHBoxLayout()
        blocks_layout.setSpacing(16)

        # Block 1: Local Hardware Telemetry (User-Mode Probed)
        self.block1_frame = QFrame(self)
        self.block1_frame.setStyleSheet("""
            QFrame {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 14px;
            }
        """)
        b1_layout = QVBoxLayout(self.block1_frame)
        b1_layout.setSpacing(8)

        b1_header = QHBoxLayout()
        b1_title = QLabel("ĐÁNH GIÁ CẤU HÌNH CỤC BỘ", self)
        b1_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #58A6FF;")
        self.b1_badge = QLabel("OBSERVED", self)
        self.b1_badge.setStyleSheet("""
            background-color: rgba(56, 139, 253, 0.15);
            color: #58A6FF;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid rgba(56, 139, 253, 0.4);
        """)
        b1_header.addWidget(b1_title)
        b1_header.addStretch()
        b1_header.addWidget(self.b1_badge)
        b1_layout.addLayout(b1_header)

        self.b1_cpu = QLabel("CPU: Đang đọc...", self)
        self.b1_cpu.setStyleSheet("font-size: 12px; color: #C9D1D9;")
        self.b1_ram = QLabel("RAM: Đang đọc...", self)
        self.b1_ram.setStyleSheet("font-size: 12px; color: #C9D1D9;")
        self.b1_board = QLabel("Mainboard: Đang đọc...", self)
        self.b1_board.setStyleSheet("font-size: 12px; color: #C9D1D9;")
        self.b1_tpm = QLabel("TPM 2.0: Đang kiểm tra...", self)
        self.b1_tpm.setStyleSheet("font-size: 12px; color: #C9D1D9;")

        b1_layout.addWidget(self.b1_cpu)
        b1_layout.addWidget(self.b1_ram)
        b1_layout.addWidget(self.b1_board)
        b1_layout.addWidget(self.b1_tpm)

        b1_note = QLabel(
            "ℹ Thu thập từ Windows WMI tầng User-Mode. Chưa qua chữ ký mật mã SHA-512 hoặc TPM Quote từ Kernel.",
            self
        )
        b1_note.setWordWrap(True)
        b1_note.setStyleSheet("font-size: 11px; color: #8B949E; margin-top: 6px; font-style: italic;")
        b1_layout.addWidget(b1_note)

        blocks_layout.addWidget(self.block1_frame)

        # Block 2: Kernel Shield Ring-0 (Driver & Service Protection)
        self.block2_frame = QFrame(self)
        self.block2_frame.setStyleSheet("""
            QFrame {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 14px;
            }
        """)
        b2_layout = QVBoxLayout(self.block2_frame)
        b2_layout.setSpacing(8)

        b2_header = QHBoxLayout()
        b2_title = QLabel("LÁ CHẮN TẦNG NHÂN RING-0", self)
        b2_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #8B949E;")
        self.b2_badge = QLabel("INACTIVE", self)
        self.b2_badge.setStyleSheet("""
            background-color: rgba(139, 148, 158, 0.15);
            color: #8B949E;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid rgba(139, 148, 158, 0.4);
        """)
        b2_header.addWidget(b2_title)
        b2_header.addStretch()
        b2_header.addWidget(self.b2_badge)
        b2_layout.addLayout(b2_header)

        self.b2_driver = QLabel("KMDF Filter Driver: ○ Chưa kích hoạt (Altitude 385201)", self)
        self.b2_driver.setStyleSheet("font-size: 12px; color: #8B949E;")
        self.b2_callbacks = QLabel("Process Protection: ○ Chưa kích hoạt (ObRegisterCallbacks)", self)
        self.b2_callbacks.setStyleSheet("font-size: 12px; color: #8B949E;")
        self.b2_telemetry = QLabel("Hardware Telemetry: ○ Chưa kết nối PCI Probe trực tiếp", self)
        self.b2_telemetry.setStyleSheet("font-size: 12px; color: #8B949E;")

        b2_layout.addWidget(self.b2_driver)
        b2_layout.addWidget(self.b2_callbacks)
        b2_layout.addWidget(self.b2_telemetry)

        self.b2_note = QLabel(
            "🔒 Yêu cầu Dịch Vụ chạy ngầm với quyền SYSTEM để nạp Driver tầng nhân chống Terminate & Read/Write VM.",
            self
        )
        self.b2_note.setWordWrap(True)
        self.b2_note.setStyleSheet("font-size: 11px; color: #8B949E; margin-top: 6px; font-style: italic;")
        b2_layout.addWidget(self.b2_note)

        blocks_layout.addWidget(self.block2_frame)
        bc_layout.addLayout(blocks_layout)
        layout.addWidget(breakdown_card)

        # 3. Technical Checklist Widget
        self.checklist_widget = TechnicalChecklistWidget(self)
        layout.addWidget(self.checklist_widget)

        # 4. Recent Security Events
        events_box = QFrame(self)
        events_box.setObjectName("card")
        eb_layout = QVBoxLayout(events_box)
        eb_layout.setContentsMargins(20, 20, 20, 20)
        eb_layout.setSpacing(10)

        eb_header = QHBoxLayout()
        eb_title = QLabel("NHẬT KÝ SỰ KIỆN GẦN ĐÂY", self)
        eb_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        eb_header.addWidget(eb_title)
        eb_header.addStretch()
        eb_layout.addLayout(eb_header)

        self.recent_timeline = EventTimelineWidget(self)
        self.recent_timeline.setFixedHeight(220)
        eb_layout.addWidget(self.recent_timeline)

        layout.addWidget(events_box)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        # Populate local hardware specs immediately
        self._populate_local_hardware()

        # Connect ViewModel Signals
        self.vm.protection_changed.connect(self._on_protection_changed)
        self.vm.checklist_changed.connect(self.checklist_widget.update_checklist)
        self.vm.recent_events_changed.connect(self.recent_timeline.set_events)

    def _populate_local_hardware(self):
        """Populates the local hardware breakdown immediately without network or IPC delays."""
        cpu = LocalHardwareCollector.get_cpu_info()
        ram = LocalHardwareCollector.get_ram_info()
        board = LocalHardwareCollector.get_motherboard_info()
        tpm = LocalHardwareCollector.get_tpm_evidence()

        self.b1_cpu.setText(f"CPU: {cpu}")
        self.b1_ram.setText(f"RAM: {ram}")
        self.b1_board.setText(f"Mainboard: {board}")
        tpm_status = tpm.get("status", "NOT_DETECTED")
        tpm_det = tpm.get("details", "")
        self.b1_tpm.setText(f"TPM 2.0: [{tpm_status}] {tpm_det}")

    def _on_activate_clicked(self):
        """Triggers Windows UAC elevation to install/start the CyberVAgent service."""
        self.action_btn.setEnabled(False)
        self.action_status_label.setVisible(True)
        self.action_status_label.setText("Đang yêu cầu cấp quyền Administrator từ Windows UAC...")
        success, msg = self.activation_controller.request_enable_protection()
        self.action_status_label.setText(msg)
        if not success:
            self.action_btn.setEnabled(True)

    def _on_activation_status(self, status_key: str, message: str):
        self.action_status_label.setVisible(True)
        self.action_status_label.setText(message)
        if status_key == "UAC_ACCEPTED":
            self.action_status_label.setStyleSheet("font-size: 12px; color: #3FB950;")
        elif status_key == "UAC_DENIED":
            self.action_status_label.setStyleSheet("font-size: 12px; color: #F85149;")
            self.action_btn.setEnabled(True)

    def _on_protection_changed(self, info):
        self.badge.set_state(info.state.value, info.substate)
        self.reason_label.setText(info.reason)
        self.since_label.setText(f"Ghi nhận từ: {info.since}  •  Độ tin cậy: {info.confidence}")

        # Update Block 2 (Kernel Shield) and Action Button based on state
        if info.state == ProtectionState.PROTECTED:
            self.b2_badge.setText("ACTIVE")
            self.b2_badge.setStyleSheet("""
                background-color: rgba(46, 160, 67, 0.15);
                color: #3FB950;
                font-size: 10px;
                font-weight: 700;
                padding: 2px 8px;
                border-radius: 4px;
                border: 1px solid rgba(46, 160, 67, 0.4);
            """)
            self.b2_driver.setText("KMDF Filter Driver: ✓ ĐÃ NẠP (Altitude 385201)")
            self.b2_driver.setStyleSheet("font-size: 12px; color: #3FB950;")
            self.b2_callbacks.setText("Process Protection: ✓ BẢO VỆ ĐỘC QUYỀN (ObRegisterCallbacks)")
            self.b2_callbacks.setStyleSheet("font-size: 12px; color: #3FB950;")
            self.b2_telemetry.setText("Hardware Telemetry: ✓ XÁC MINH TRỰC TIẾP PCI BUS")
            self.b2_telemetry.setStyleSheet("font-size: 12px; color: #3FB950;")
            self.b2_note.setText("🛡️ Hệ thống phòng vệ nhân đang bảo vệ tiến trình Core Agent và Driver 24/7.")

            self.action_btn.setText("✓ Dịch Vụ Bảo Vệ Đang Hoạt Động (SYSTEM)")
            self.action_btn.setEnabled(False)
            self.action_status_label.setVisible(False)

        elif info.state == ProtectionState.LOCAL:
            self.b2_badge.setText("INACTIVE")
            self.b2_badge.setStyleSheet("""
                background-color: rgba(139, 148, 158, 0.15);
                color: #8B949E;
                font-size: 10px;
                font-weight: 700;
                padding: 2px 8px;
                border-radius: 4px;
                border: 1px solid rgba(139, 148, 158, 0.4);
            """)
            self.b2_driver.setText("KMDF Filter Driver: ○ Chưa nạp (Chờ kích hoạt service)")
            self.b2_driver.setStyleSheet("font-size: 12px; color: #8B949E;")
            self.b2_callbacks.setText("Process Protection: ○ Chưa kích hoạt (Yêu cầu quyền SYSTEM)")
            self.b2_callbacks.setStyleSheet("font-size: 12px; color: #8B949E;")
            self.b2_telemetry.setText("Hardware Telemetry: ○ Chưa kết nối PCI Probe trực tiếp")
            self.b2_telemetry.setStyleSheet("font-size: 12px; color: #8B949E;")

            self.action_btn.setText("🚀 Kích Hoạt Bảo Vệ Ngầm 24/7 (Windows Service)")
            self.action_btn.setEnabled(True)

        elif info.state in (ProtectionState.DEGRADED, ProtectionState.ISOLATED):
            self.b2_badge.setText("OFFLINE")
            self.b2_badge.setStyleSheet("""
                background-color: rgba(248, 81, 73, 0.15);
                color: #F85149;
                font-size: 10px;
                font-weight: 700;
                padding: 2px 8px;
                border-radius: 4px;
                border: 1px solid rgba(248, 81, 73, 0.4);
            """)
            self.b2_driver.setText("KMDF Filter Driver: ✕ Mất kết nối hoặc bị gỡ bỏ")
            self.b2_driver.setStyleSheet("font-size: 12px; color: #F85149;")
            self.b2_callbacks.setText("Process Protection: ✕ Cảnh báo nguy cơ can thiệp tiến trình")
            self.b2_callbacks.setStyleSheet("font-size: 12px; color: #F85149;")
            self.b2_telemetry.setText("Hardware Telemetry: ✕ Mất kết nối Kernel Telemetry")
            self.b2_telemetry.setStyleSheet("font-size: 12px; color: #F85149;")

            self.action_btn.setText("⚠️ Khởi Động Lại Dịch Vụ Bảo Vệ (Windows Service)")
            self.action_btn.setEnabled(True)

