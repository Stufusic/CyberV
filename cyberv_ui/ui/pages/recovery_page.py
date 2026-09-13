"""
Recovery Page (Cryptographic Attestation & Unlocking)
Ref: Docs/ui.md Section 14
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QLineEdit, QTextEdit, QScrollArea
from PySide6.QtCore import Qt
from ...viewmodels.recovery_viewmodel import RecoveryViewModel


class RecoveryPage(QWidget):
    def __init__(self, viewmodel: RecoveryViewModel, parent=None):
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
        title = QLabel("KHÔI PHỤC VÀ TÁI CẤP QUYỀN (RECOVERY ATTESTATION)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Quy trình xác thực chữ ký bất đối xứng Ed25519 từ Master Authority khi thiết bị bị khóa hoặc biến động phần cứng", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Card: Current Recovery State
        card = QFrame(self)
        card.setObjectName("card")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(12)

        c_header = QLabel("THỬ THÁCH MẬT MÃ HIỆN HÀNH (CHALLENGE NONCE)", self)
        c_header.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E; letter-spacing: 0.8px;")
        c_layout.addWidget(c_header)

        self.status_banner = QLabel("Hệ thống đang ở trạng thái bình thường. Không yêu cầu phục hồi khẩn cấp.", self)
        self.status_banner.setStyleSheet("color: #3FB950; font-weight: bold; font-size: 13px;")
        c_layout.addWidget(self.status_banner)

        self.chal_row = QHBoxLayout()
        chal_lbl = QLabel("Mã Thử Thách (Challenge ID):", self)
        chal_lbl.setStyleSheet("color: #8B949E; font-size: 12px;")
        self.chal_val = QLabel("N/A", self)
        self.chal_val.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #58A6FF; font-weight: bold;")
        self.chal_row.addWidget(chal_lbl)
        self.chal_row.addWidget(self.chal_val)
        self.chal_row.addStretch()
        c_layout.addLayout(self.chal_row)

        self.ttl_row = QHBoxLayout()
        ttl_lbl = QLabel("Thời Gian Hiệu Lực (TTL):", self)
        ttl_lbl.setStyleSheet("color: #8B949E; font-size: 12px;")
        self.ttl_val = QLabel("0 giây (Chống Replay Attack)", self)
        self.ttl_val.setStyleSheet("color: #F0B72F; font-size: 12px; font-weight: bold;")
        self.ttl_row.addWidget(ttl_lbl)
        self.ttl_row.addWidget(self.ttl_val)
        self.ttl_row.addStretch()
        c_layout.addLayout(self.ttl_row)

        c_layout.addSpacing(10)
        sig_header = QLabel("CHỮ KÝ XÁC THỰC QUẢN TRỊ VIÊN (ED25519 ASYMMETRIC SIGNATURE):", self)
        sig_header.setStyleSheet("font-size: 11px; font-weight: 700; color: #8B949E;")
        c_layout.addWidget(sig_header)

        self.sig_input = QLineEdit(self)
        self.sig_input.setPlaceholderText("Dán chuỗi 128 ký tự Hex chữ ký số Ed25519 của Master Authority Key...")
        self.sig_input.setStyleSheet("font-family: Consolas, monospace;")
        c_layout.addWidget(self.sig_input)

        btn_row = QHBoxLayout()
        self.submit_btn = QPushButton("Xác Thực & Khôi Phục Hệ Thống", self)
        self.submit_btn.setObjectName("primary_btn")
        self.submit_btn.clicked.connect(self._on_submit_clicked)
        btn_row.addWidget(self.submit_btn)
        btn_row.addStretch()
        c_layout.addLayout(btn_row)

        self.result_lbl = QLabel("", self)
        self.result_lbl.setStyleSheet("font-size: 12px; font-weight: bold; margin-top: 6px;")
        self.result_lbl.setVisible(False)
        c_layout.addWidget(self.result_lbl)

        layout.addWidget(card)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        self.vm.challenge_updated.connect(self._on_challenge_updated)
        self.vm.recovery_result.connect(self._on_recovery_result)

    def _on_challenge_updated(self, chal_id: str, ttl: int):
        self.status_banner.setText("⚠️ YÊU CẦU PHỤC HỒI: Thiết bị cần được xác thực chữ ký bởi Master Authority.")
        self.status_banner.setStyleSheet("color: #F0B72F; font-weight: bold; font-size: 13px;")
        self.chal_val.setText(chal_id)
        self.ttl_val.setText(f"{ttl} giây")

    def _on_submit_clicked(self):
        sig = self.sig_input.text()
        self.vm.submit_recovery_signature(sig)

    def _on_recovery_result(self, success: bool, msg: str):
        self.result_lbl.setVisible(True)
        self.result_lbl.setText(msg)
        if success:
            self.result_lbl.setStyleSheet("color: #3FB950; font-weight: bold;")
            self.status_banner.setText("Hệ thống đã phục hồi và đang ở trạng thái an toàn.")
            self.status_banner.setStyleSheet("color: #3FB950; font-weight: bold; font-size: 13px;")
        else:
            self.result_lbl.setStyleSheet("color: #F85149; font-weight: bold;")
