"""
System Page (Observed vs Verified Separation)
Ref: Docs/ui.md Section 13
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import Qt
from ...viewmodels.system_viewmodel import SystemViewModel
from ...styles.palette import ThemePalette


class SystemPage(QWidget):
    def __init__(self, viewmodel: SystemViewModel, parent=None):
        super().__init__(parent)
        self.vm = viewmodel

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Title
        title_box = QVBoxLayout()
        title = QLabel("CẤU TRÚC THIẾT BỊ (SYSTEM & EVIDENCE MAPPING)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Phân định minh bạch giữa Thông Số Quan Sát Thô (Observed) và Bằng Chứng Đã Xác Minh (Verified)", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(16)

        # Left Column: OBSERVED RAW
        self.obs_card = QFrame(self)
        self.obs_card.setObjectName("card")
        obs_layout = QVBoxLayout(self.obs_card)
        obs_layout.setContentsMargins(16, 16, 16, 16)

        obs_title = QLabel("1. THÔNG SỐ QUAN SÁT THÔ (OBSERVED HARDWARE)", self)
        obs_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        obs_layout.addWidget(obs_title)

        obs_desc = QLabel("Dữ liệu thô thu thập từ tầng User-mode (WMI / OS Registry). Chưa qua thẩm định bảo mật.", self)
        obs_desc.setStyleSheet("font-size: 11px; color: #6E7681; margin-bottom: 8px;")
        obs_desc.setWordWrap(True)
        obs_layout.addWidget(obs_desc)

        self.obs_table = QTableWidget(self)
        self.obs_table.setColumnCount(2)
        self.obs_table.setHorizontalHeaderLabels(["Linh Kiện", "Mô Tả Quan Sát"])
        self.obs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.obs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        obs_layout.addWidget(self.obs_table)

        columns_layout.addWidget(self.obs_card)

        # Right Column: VERIFIED EVIDENCE
        self.ver_card = QFrame(self)
        self.ver_card.setObjectName("card")
        ver_layout = QVBoxLayout(self.ver_card)
        ver_layout.setContentsMargins(16, 16, 16, 16)

        ver_title = QLabel("2. BẰNG CHỨNG MẬT MÃ (VERIFIED EVIDENCE)", self)
        ver_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #3FB950; letter-spacing: 0.8px;")
        ver_layout.addWidget(ver_title)

        ver_desc = QLabel("Cam kết băm SHA-512 và counter phần cứng TPM 2.0 đã được xác minh toàn vẹn.", self)
        ver_desc.setStyleSheet("font-size: 11px; color: #6E7681; margin-bottom: 8px;")
        ver_desc.setWordWrap(True)
        ver_layout.addWidget(ver_desc)

        self.ver_table = QTableWidget(self)
        self.ver_table.setColumnCount(2)
        self.ver_table.setHorizontalHeaderLabels(["Tầng Chứng Thực", "Trạng Thái"])
        self.ver_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.ver_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        ver_layout.addWidget(self.ver_table)

        columns_layout.addWidget(self.ver_card)

        layout.addLayout(columns_layout)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        self.vm.system_data_changed.connect(self._on_system_data_changed)

    def _on_system_data_changed(self, data):
        # Observed
        obs = data.get("observed", [])
        self.obs_table.setRowCount(len(obs))
        for row, item in enumerate(obs):
            self.obs_table.setItem(row, 0, QTableWidgetItem(item.get("component", "")))
            self.obs_table.setItem(row, 1, QTableWidgetItem(item.get("model", "")))

        # Verified
        ver = data.get("verified", [])
        self.ver_table.setRowCount(len(ver))
        for row, item in enumerate(ver):
            self.ver_table.setItem(row, 0, QTableWidgetItem(item.get("tier", "")))
            status = item.get("status", "UNVERIFIED")
            it = QTableWidgetItem(status)
            token = ThemePalette.get_status_token(status)
            it.setForeground(ThemePalette.qcolor(token.bright))
            it.setTextAlignment(Qt.AlignCenter)
            self.ver_table.setItem(row, 1, it)
