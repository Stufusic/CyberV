"""
Diagnostic Tree Widget (4-Tier Diagnostics View)
Ref: Docs/ui.md Section 15 & Docs/ủiv.md Section 7
"""

from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from ...models.diagnostics import DiagnosticReport, DiagnosticTier
from ...styles.palette import ThemePalette


class DiagnosticTreeWidget(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Thành Phần Kiểm Tra", "Trạng Thái", "Bằng Chứng Kỹ Thuật (Evidence)"])
        self.setColumnWidth(0, 260)
        self.setColumnWidth(1, 110)
        self.setAlternatingRowColors(True)
        self.setStyleSheet("""
            QTreeWidget {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 6px;
            }
            QTreeWidget::item {
                padding: 6px 4px;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                font-weight: 600;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #30363D;
            }
        """)

    def set_report(self, report: DiagnosticReport):
        self.clear()
        if not report or not report.items:
            return

        # Group by Tier
        tier_nodes = {}
        for tier in DiagnosticTier:
            node = QTreeWidgetItem(self, [tier.value, "", ""])
            node.setExpanded(True)
            font = QFont()
            font.setBold(True)
            node.setFont(0, font)
            node.setForeground(0, ThemePalette.qcolor("#58A6FF"))
            tier_nodes[tier] = node

        for item in report.items:
            parent_node = tier_nodes.get(item.tier)
            if not parent_node:
                continue

            icon = "✓ " if item.status == "PASS" else ("▲ " if item.status == "WARN" else "✕ ")
            token = ThemePalette.get_status_token(item.status)

            child = QTreeWidgetItem(parent_node, [
                f"  {item.name}",
                f"{icon}{item.status}",
                item.evidence,
            ])
            child.setForeground(1, ThemePalette.qcolor(token.bright))
            child.setFont(1, QFont("Segoe UI", 9, QFont.Bold))
            child.setFont(2, QFont("Consolas", 9))
            child.setForeground(2, ThemePalette.qcolor("#8B949E"))
