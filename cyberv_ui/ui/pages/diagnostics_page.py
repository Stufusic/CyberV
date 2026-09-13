"""
Diagnostics Page (4-Tier Diagnostics Runner & Report Exporter)
Ref: Docs/ui.md Section 15, 19 & Docs/ủiv.md Section 7
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QFileDialog
from PySide6.QtCore import Qt
from ..widgets.diagnostic_tree import DiagnosticTreeWidget
from ...viewmodels.diagnostics_viewmodel import DiagnosticsViewModel


class DiagnosticsPage(QWidget):
    def __init__(self, viewmodel: DiagnosticsViewModel, parent=None):
        super().__init__(parent)
        self.vm = viewmodel

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Title
        title_box = QVBoxLayout()
        title = QLabel("CHẨN ĐOÁN KỸ THUẬT 4 TẦNG (4-TIER DIAGNOSTICS)", self)
        title.setObjectName("page_title")
        subtitle = QLabel("Tự động kiểm tra tính toàn vẹn của Driver, Core Agent, Giao thức IOCTL và Bất biến Bảo mật", self)
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Action Bar & Summary
        action_bar = QHBoxLayout()
        self.run_btn = QPushButton("Chạy Chẩn Đoán Toàn Bộ", self)
        self.run_btn.setObjectName("primary_btn")
        self.run_btn.clicked.connect(self._on_run_clicked)

        self.export_btn = QPushButton("Xuất Báo Cáo Chẩn Đoán (ZIP)", self)
        self.export_btn.clicked.connect(self._on_export_clicked)

        self.summary_lbl = QLabel("Tổng kiểm tra: 0  |  Thành công: 0  |  Cảnh báo: 0  |  Lỗi: 0", self)
        self.summary_lbl.setStyleSheet("color: #8B949E; font-size: 12px; margin-left: 12px;")

        action_bar.addWidget(self.run_btn)
        action_bar.addWidget(self.export_btn)
        action_bar.addWidget(self.summary_lbl)
        action_bar.addStretch()
        layout.addLayout(action_bar)

        # Tree Widget
        self.tree = DiagnosticTreeWidget(self)
        layout.addWidget(self.tree)

        self.export_path_lbl = QLabel("", self)
        self.export_path_lbl.setStyleSheet("color: #3FB950; font-size: 11px; font-weight: bold;")
        self.export_path_lbl.setVisible(False)
        layout.addWidget(self.export_path_lbl)

        # Connect signals
        self.vm.diagnostics_completed.connect(self._on_diagnostics_completed)
        self.vm.export_finished.connect(self._on_export_finished)

    def _on_run_clicked(self):
        # Trigger diagnostics
        self.vm.run_diagnostics(
            kernel_available=True,
            callback_active=True,
            is_ipc_connected=True,
            hardware_verified=True,
        )

    def _on_export_clicked(self):
        dest_dir = QFileDialog.getExistingDirectory(self, "Chọn Thư Mục Xuất Báo Cáo")
        if dest_dir:
            self.vm.export_report_zip(dest_dir)

    def _on_diagnostics_completed(self, report):
        self.tree.set_report(report)
        self.summary_lbl.setText(
            f"Tổng kiểm tra: {report.total_checks}  |  "
            f"Thành công: {report.passed_count}  |  "
            f"Cảnh báo: {report.warning_count}  |  "
            f"Lỗi: {report.failed_count}"
        )

    def _on_export_finished(self, zip_path: str):
        self.export_path_lbl.setText(f"✓ Đã xuất tệp báo cáo chẩn đoán sạch: {zip_path}")
        self.export_path_lbl.setVisible(True)
