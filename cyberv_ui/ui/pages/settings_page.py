"""
Settings Page
Ref: Docs/ui.md Section 16
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QCheckBox, QPushButton, QScrollArea


class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Title
        title_box = QVBoxLayout()
        title = QLabel("CẤU HÌNH & TÙY CHỌN (SETTINGS)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Quản lý thông báo, chế độ khởi động và chính sách bảo vệ hệ thống", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Card 1: Notifications
        c1 = QFrame(self)
        c1.setObjectName("card")
        c1_layout = QVBoxLayout(c1)
        c1_layout.setContentsMargins(16, 16, 16, 16)
        c1_title = QLabel("1. THÔNG BÁO HỆ THỐNG (NOTIFICATIONS)", self)
        c1_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c1_layout.addWidget(c1_title)

        self.cb_toast = QCheckBox("Hiển thị thông báo Windows Native Toast khi trạng thái bảo vệ bị suy giảm", self)
        self.cb_toast.setChecked(True)
        c1_layout.addWidget(self.cb_toast)

        self.cb_tray = QCheckBox("Thu nhỏ vào Khay Hệ thống (System Tray) khi đóng cửa sổ thay vì tắt ứng dụng", self)
        self.cb_tray.setChecked(True)
        c1_layout.addWidget(self.cb_tray)
        layout.addWidget(c1)

        # Card 2: Protection
        c2 = QFrame(self)
        c2.setObjectName("card")
        c2_layout = QVBoxLayout(c2)
        c2_layout.setContentsMargins(16, 16, 16, 16)
        c2_title = QLabel("2. CHẾ ĐỘ PHÒNG VỆ (PROTECTION ENFORCEMENT)", self)
        c2_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c2_layout.addWidget(c2_title)

        self.cb_autostart = QCheckBox("Tự khởi động cùng hệ điều hành Windows (Windows Service Auto-Start)", self)
        self.cb_autostart.setChecked(True)
        c2_layout.addWidget(self.cb_autostart)

        self.cb_failclosed = QCheckBox("Chính sách Fail-Closed nghiêm ngặt (Tự cô lập khi driver bị can thiệp)", self)
        self.cb_failclosed.setChecked(True)
        self.cb_failclosed.setEnabled(False)  # Security invariant, cannot be unchecked
        c2_layout.addWidget(self.cb_failclosed)
        layout.addWidget(c2)

        # Card 3: Advanced
        c3 = QFrame(self)
        c3.setObjectName("card")
        c3_layout = QVBoxLayout(c3)
        c3_layout.setContentsMargins(16, 16, 16, 16)
        c3_title = QLabel("3. TÙY CHỌN NÂNG CAO (ADVANCED)", self)
        c3_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #DB6D28; letter-spacing: 0.8px;")
        c3_layout.addWidget(c3_title)

        warn_box = QLabel("⚠️ CẢNH BÁO: Không can thiệp vào các tham số an ninh cốt lõi nếu không có hướng dẫn từ Quản trị viên An ninh. Việc thay đổi có thể làm suy yếu khả năng bảo vệ của thiết bị.", self)
        warn_box.setStyleSheet("color: #F0B72F; font-size: 11px; font-style: italic;")
        warn_box.setWordWrap(True)
        c3_layout.addWidget(warn_box)

        layout.addWidget(c3)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)
