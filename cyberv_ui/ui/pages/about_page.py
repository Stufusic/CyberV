"""
About Page (Open-Source Information & Vulnerability Reporting)
Ref: Docs/ui.md Section 20
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QScrollArea
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices


class AboutPage(QWidget):
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
        title = QLabel("THÔNG TIN DỰ ÁN (ABOUT CYBERV)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Nền tảng xác thực định danh thiết bị và phòng vệ điểm cuối mã nguồn mở", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Info Card
        card = QFrame(self)
        card.setObjectName("card")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(10)

        app_name = QLabel("CyberV Security Desktop Platform", self)
        app_name.setStyleSheet("font-size: 16px; font-weight: 700; color: #58A6FF;")
        c_layout.addWidget(app_name)

        desc = QLabel(
            "Hệ thống bảo vệ gắn chặt phần cứng vật lý (Hardware-Anchored Zero Trust) kết hợp lá chắn tầng nhân Ring-0 KMDF, "
            "chip bảo mật TPM 2.0 NV Monotonic Counter và kho khóa mật mã bảo vệ bởi Windows DPAPI.",
            self,
        )
        desc.setStyleSheet("color: #8B949E; font-size: 12px; line-height: 1.4;")
        desc.setWordWrap(True)
        c_layout.addWidget(desc)

        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("background-color: #30363D; max-height: 1px; margin: 8px 0px;")
        c_layout.addWidget(divider)

        self._add_row(c_layout, "Phiên Bản Ứng Dụng (UI Version):", "v0.1.0-alpha")
        self._add_row(c_layout, "Phiên Bản Core Agent (Rust):", "v0.1.0 (Session 0 SCM)")
        self._add_row(c_layout, "Phiên Bản Driver Kernel (KMDF):", "v1.0.2 (Altitude 385201)")
        self._add_row(c_layout, "Giao Thức Mật Mã (Crypto):", "FIPS 180-4 SHA-512 & RFC 8032 Ed25519")
        self._add_row(c_layout, "Giấy Phép Mã Nguồn Mở (License):", "Apache License 2.0")
        self._add_row(c_layout, "Bản Quyền (Copyright):", "Copyright (c) 2026 Stufusic and CyberV Contributors")

        layout.addWidget(card)

        # Links Box
        links_card = QFrame(self)
        links_card.setObjectName("card")
        lc_layout = QVBoxLayout(links_card)
        lc_layout.setContentsMargins(20, 20, 20, 20)
        lc_layout.setSpacing(12)

        lc_title = QLabel("TÀI NGUYÊN & CHÍNH SÁCH BẢO MẬT", self)
        lc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        lc_layout.addWidget(lc_title)

        sec_text = QLabel("Nếu bạn phát hiện lỗ hổng bảo mật, vui lòng tuân thủ chính sách tại SECURITY.md và liên hệ qua email bảo mật riêng tư: stufusiclab@gmail.com", self)
        sec_text.setStyleSheet("color: #E6EDF3; font-size: 12px;")
        sec_text.setWordWrap(True)
        lc_layout.addWidget(sec_text)

        layout.addWidget(links_card)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

    def _add_row(self, layout, label_str: str, val_str: str):
        row = QHBoxLayout()
        lbl = QLabel(label_str, self)
        lbl.setStyleSheet("color: #8B949E; font-size: 12px;")
        val = QLabel(val_str, self)
        val.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #E6EDF3; font-weight: 600;")
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(val)
        layout.addLayout(row)
