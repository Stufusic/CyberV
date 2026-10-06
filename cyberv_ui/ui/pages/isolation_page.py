# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 CyberV - Stufusic. All rights reserved.
#
# PROPRIETARY & SOURCE CODE LICENSE NOTICE
# This software is protected by international copyright laws and treaties.
# Unauthorized reproduction, reverse engineering, or distribution of this code,
# or any portion of it, is strictly prohibited without explicit written consent.
#
# DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
# OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
# ============================================================================
"""
Isolation Inbox Page (M-PLAN I-2) — human-in-the-loop cách ly node mesh.

Ref: Docs/M_PLAN_MULTI_TRANSPORT_ISOLATION.md §6.1 (bậc I-2 operator-approved),
§6.4 (đường UI console). Quyết định cuối là NGƯỜI — không phá freeze gate;
auto-pilot (I-3) vẫn bị chặn độc lập.

Hiển thị trung thực (INV-007):
- enforcement "LOGIC_ONLY"/"NOT_EXECUTED" → banner cảnh báo hành động chưa
  verified (không chặn mạng thật);
- IPC mất kết nối → danh sách rỗng + banner OFFLINE, không hiện đề nghị cũ.
"""

from typing import Any, Dict, List

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...services.isolation_service import IsolationInputError, IsolationService

REFRESH_MS = 5000


class IsolationPage(QWidget):
    def __init__(self, service: IsolationService = None, parent=None):
        super().__init__(parent)
        # Service tự dựng khi caller không cung cấp (main.py không cần wiring VM).
        self.service = service or IsolationService()

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Title
        title_box = QVBoxLayout()
        title = QLabel("HỒ SƠ CÁCH LY NODE MESH (ISOLATION INBOX)", self)
        title.setObjectName("page_title")
        subtitle = QLabel(
            "Đề nghị cách ly từ quorum của mesh — chỉ THỰC THI khi bạn duyệt. "
            "Auto-pilot bị chặn bởi freeze gate (I-3).",
            self,
        )
        subtitle.setObjectName("page_subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Banner chế độ enforcement — trung thực WFP vs logic-only
        self.enforcement_banner = QLabel("", self)
        self.enforcement_banner.setStyleSheet(
            "font-weight: bold; font-size: 12px; padding: 8px; border-radius: 4px;"
        )
        layout.addWidget(self.enforcement_banner)

        # Danh sách đề nghị
        self.proposals_layout = QVBoxLayout()
        self.proposals_layout.setSpacing(10)
        layout.addLayout(self.proposals_layout)
        layout.addStretch()

        scroll.setWidget(container)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._rows: List[Dict[str, Any]] = []
        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    # ------------------------------------------------------------------ data

    def refresh(self):
        inbox = self.service.fetch_inbox()
        if not inbox["online"]:
            self._set_banner(
                f"⚠ OFFLINE — không liên lạc được Core Agent ({inbox.get('error')})",
                "#F85149",
            )
            self._rebuild_rows([])
            return
        mode = inbox.get("enforcement", "UNKNOWN")
        if mode == "WFP":
            self._set_banner(
                "✓ Enforcement: WFP — cách ly chặn mạng THẬT (rule per-IP, TTL tuyệt đối)",
                "#3FB950",
            )
        else:
            self._set_banner(
                f"⚠ Enforcement: {mode} — hành động cách ly CHƯA verified "
                "(không chặn mạng thật; chỉ graph + ngừng gossip)",
                "#D29922",
            )
        self._rebuild_rows(inbox.get("proposals", []))

    def _set_banner(self, text: str, color: str):
        self.enforcement_banner.setText(text)
        self.enforcement_banner.setStyleSheet(
            f"font-weight: bold; font-size: 12px; padding: 8px; border-radius: 4px; "
            f"color: {color};"
        )

    def _rebuild_rows(self, proposals: List[Dict[str, Any]]):
        while self.proposals_layout.count():
            item = self.proposals_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not proposals:
            empty = QLabel("Không có đề nghị cách ly nào đang chờ.", self)
            empty.setStyleSheet("color: #8B949E; font-size: 12px;")
            self.proposals_layout.addWidget(empty)
            return
        for proposal in proposals:
            self.proposals_layout.addWidget(self._build_row(proposal))

    def _build_row(self, proposal: Dict[str, Any]) -> QFrame:
        card = QFrame(self)
        card.setObjectName("card")
        row = QVBoxLayout(card)
        row.setContentsMargins(16, 12, 16, 12)
        row.setSpacing(8)

        subject = str(proposal.get("subject_hex", ""))[:16]
        header = QLabel(f"NODE: {subject}…  ·  weight={proposal.get('total_weight')}", self)
        header.setStyleSheet("font-family: Consolas, monospace; font-weight: bold; color: #58A6FF;")
        row.addWidget(header)

        evidence = proposal.get("evidence_refs", [])
        detail = QLabel(
            f"Evidence: {len(evidence)} phiếu độc lập (truy vết qua MMR) · "
            f"TTL đề nghị: {proposal.get('ttl_ms')} ms"
        )
        detail.setStyleSheet("color: #8B949E; font-size: 11px;")
        row.addWidget(detail)

        # Lý do (input) + 3 nút quyết định — UAC của hành động nằm ở tiến
        # trình agent elevated phía dưới (plan §9 admin override).
        reason = QLineEdit(card)
        reason.setPlaceholderText("Lý do (ghi vào DecisionLog — audit)")
        reason.setMaxLength(200)
        row.addWidget(reason)

        buttons = QHBoxLayout()
        for action, label, color in (
            ("approve", "Duyệt cách ly", "#F85149"),
            ("lift", "Gỡ nghi", "#3FB950"),
            ("reject", "Từ chối đề nghị", "#8B949E"),
        ):
            btn = QPushButton(label, card)
            btn.setStyleSheet(f"color: {color}; font-weight: bold;")
            btn.clicked.connect(
                lambda checked=False, s=str(proposal.get("subject_hex", "")), a=action, r=reason: self._decide(s, a, r.text())
            )
            buttons.addWidget(btn)
        buttons.addStretch()
        row.addLayout(buttons)
        return card

    def _decide(self, subject_hex: str, action: str, reason: str):
        try:
            result = self.service.decide(subject_hex, action, reason)
        except IsolationInputError as e:
            self._set_banner(f"⚠ Input không hợp lệ: {e}", "#F85149")
            return
        if result.get("ok"):
            self._set_banner(f"✓ Đã ghi quyết định ({action}) — audit DecisionLog", "#3FB950")
        else:
            self._set_banner(
                f"⚠ Lệnh {action} bị từ chối: {result.get('error')}", "#F85149"
            )
        self.refresh()
