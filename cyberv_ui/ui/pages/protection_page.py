"""
Protection Page (Kernel Technical Truth)
Ref: Docs/ui.md Section 8 & Docs/ủiv.md Section 6
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea, QGridLayout
from PySide6.QtCore import Qt
from ..widgets.status_badge import StatusBadgeWidget
from ...viewmodels.protection_viewmodel import ProtectionViewModel


class ProtectionPage(QWidget):
    def __init__(self, viewmodel: ProtectionViewModel, parent=None):
        super().__init__(parent)
        self.vm = viewmodel

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Page Title
        title_box = QVBoxLayout()
        title = QLabel("LÁ CHẮN TẦNG NHÂN (KERNEL RING-0 PROTECTION)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Giám sát trạng thái trình điều khiển CyberVProbe.sys và bảo vệ tiến trình bằng ObRegisterCallbacks", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Warning Banner (visible when callback or driver offline)
        self.warning_banner = QFrame(self)
        self.warning_banner.setStyleSheet("""
            QFrame {
                background-color: #2B0E10;
                border: 1px solid #7A181C;
                border-radius: 6px;
                padding: 12px 16px;
            }
        """)
        wb_layout = QHBoxLayout(self.warning_banner)
        wb_icon = QLabel("✕", self)
        wb_icon.setStyleSheet("color: #F85149; font-weight: bold; font-size: 16px;")
        self.wb_text = QLabel("CALLBACK NOT ACTIVE: CyberV cannot verify kernel object protection.", self)
        self.wb_text.setStyleSheet("color: #F85149; font-weight: 600; font-size: 13px;")
        wb_layout.addWidget(wb_icon)
        wb_layout.addWidget(self.wb_text)
        wb_layout.addStretch()
        layout.addWidget(self.warning_banner)

        # Grid of Cards
        grid = QGridLayout()
        grid.setSpacing(16)

        # Card 1: Driver State
        self.c1 = QFrame(self)
        self.c1.setObjectName("card")
        c1_layout = QVBoxLayout(self.c1)
        c1_layout.setContentsMargins(16, 16, 16, 16)
        c1_title = QLabel("TRÌNH ĐIỀU KHIỂN (DRIVER STATUS)", self)
        c1_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c1_layout.addWidget(c1_title)

        self.driver_status_lbl = self._create_row(c1_layout, "Trạng Thái:")
        self.driver_ver_lbl = self._create_row(c1_layout, "Phiên Bản:", is_mono=True)
        self.driver_loaded_lbl = self._create_row(c1_layout, "Thời Điểm Nạp:")
        grid.addWidget(self.c1, 0, 0)

        # Card 2: Object Callbacks
        self.c2 = QFrame(self)
        self.c2.setObjectName("card")
        c2_layout = QVBoxLayout(self.c2)
        c2_layout.setContentsMargins(16, 16, 16, 16)
        c2_title = QLabel("BẢO VỆ TIẾN TRÌNH (OBJECT PROTECTION)", self)
        c2_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c2_layout.addWidget(c2_title)

        self.cb_status_lbl = self._create_row(c2_layout, "Đăng Ký Callbacks:")
        self.pid_lbl = self._create_row(c2_layout, "PID Được Bảo Vệ:", is_mono=True)
        self.altitude_lbl = self._create_row(c2_layout, "Security Altitude:", is_mono=True)
        self.altitude_lbl.setText("385201 (PsProcessType)")
        grid.addWidget(self.c2, 0, 1)

        # Card 3: Restricted Access Rights
        self.c3 = QFrame(self)
        self.c3.setObjectName("card")
        c3_layout = QVBoxLayout(self.c3)
        c3_layout.setContentsMargins(16, 16, 16, 16)
        c3_title = QLabel("QUYỀN HẠN BỊ TƯỚC ĐOẠT (STRIPPED ACCESS)", self)
        c3_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c3_layout.addWidget(c3_title)

        self.perm_term_lbl = self._create_row(c3_layout, "PROCESS_TERMINATE:")
        self.perm_vmread_lbl = self._create_row(c3_layout, "PROCESS_VM_READ:")
        self.perm_vmwrite_lbl = self._create_row(c3_layout, "PROCESS_VM_WRITE:")
        grid.addWidget(self.c3, 1, 0)

        # Card 4: Telemetry Stats
        self.c4 = QFrame(self)
        self.c4.setObjectName("card")
        c4_layout = QVBoxLayout(self.c4)
        c4_layout.setContentsMargins(16, 16, 16, 16)
        c4_title = QLabel("DỮ LIỆU ĐO LƯỜNG (KERNEL TELEMETRY)", self)
        c4_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c4_layout.addWidget(c4_title)

        self.telem_time_lbl = self._create_row(c4_layout, "Cập Nhật Lần Cuối:")
        self.telem_pci_lbl = self._create_row(c4_layout, "Linh Kiện PCI Đã Quét:", is_mono=True)
        self.telem_blocked_lbl = self._create_row(c4_layout, "Số Tấn Công Đã Chặn:", is_mono=True)
        grid.addWidget(self.c4, 1, 1)

        layout.addLayout(grid)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        self.vm.shield_info_changed.connect(self._on_shield_info_changed)

    def _create_row(self, parent_layout, label_text: str, is_mono: bool = False) -> QLabel:
        row = QHBoxLayout()
        lbl = QLabel(label_text, self)
        lbl.setStyleSheet("color: #8B949E; font-size: 12px; font-weight: 500;")
        val = QLabel("N/A", self)
        if is_mono:
            val.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #58A6FF; font-weight: bold;")
        else:
            val.setStyleSheet("color: #E6EDF3; font-size: 12px; font-weight: 600;")
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(val)
        parent_layout.addLayout(row)
        return val

    def _on_shield_info_changed(self, info):
        # Driver
        self.driver_status_lbl.setText(info.driver_status)
        self.driver_status_lbl.setStyleSheet(
            "color: #3FB950; font-weight: bold;" if info.driver_status == "ACTIVE" else "color: #F85149; font-weight: bold;"
        )
        self.driver_ver_lbl.setText(info.driver_version)
        self.driver_loaded_lbl.setText(info.loaded_at)

        # Callbacks
        if info.callback_active:
            self.cb_status_lbl.setText("ACTIVE (Registered)")
            self.cb_status_lbl.setStyleSheet("color: #3FB950; font-weight: bold;")
            self.warning_banner.setVisible(False)
            self.perm_term_lbl.setText("BLOCKED (Access Denied)")
            self.perm_term_lbl.setStyleSheet("color: #3FB950; font-weight: bold;")
            self.perm_vmread_lbl.setText("BLOCKED (Access Denied)")
            self.perm_vmread_lbl.setStyleSheet("color: #3FB950; font-weight: bold;")
            self.perm_vmwrite_lbl.setText("BLOCKED (Access Denied)")
            self.perm_vmwrite_lbl.setStyleSheet("color: #3FB950; font-weight: bold;")
        else:
            self.cb_status_lbl.setText("NOT ACTIVE")
            self.cb_status_lbl.setStyleSheet("color: #F85149; font-weight: bold;")
            self.warning_banner.setVisible(True)
            self.wb_text.setText("CALLBACK NOT ACTIVE: Kernel object protection is unavailable.")
            self.perm_term_lbl.setText("UNPROTECTED")
            self.perm_term_lbl.setStyleSheet("color: #F85149; font-weight: bold;")
            self.perm_vmread_lbl.setText("UNPROTECTED")
            self.perm_vmread_lbl.setStyleSheet("color: #F85149; font-weight: bold;")
            self.perm_vmwrite_lbl.setText("UNPROTECTED")
            self.perm_vmwrite_lbl.setStyleSheet("color: #F85149; font-weight: bold;")

        self.pid_lbl.setText(f"PID {info.protected_pid}" if info.protected_pid else "Not Bound")

        # Telemetry
        self.telem_time_lbl.setText(info.telemetry_updated_at)
        self.telem_pci_lbl.setText(f"{info.pci_observations_count} devices")
        self.telem_blocked_lbl.setText(
            f"{info.blocked_terminations} Terminate, {info.blocked_vm_reads} Read, {info.blocked_vm_writes} Write"
        )
