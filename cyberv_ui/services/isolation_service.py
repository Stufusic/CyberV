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
Isolation Inbox service (M-PLAN I-2) — cầu nối UI ↔ Core Agent qua IPC.

Bổ sung lệnh `IsolationInbox` / `IsolationDecision` vào mặt protocol Python,
đối xứng với `IpcCommand` phía Rust (defense/passive/ipc/protocol.rs).

Ranh giới trung thực (INV-007):
- enforcement trả về "LOGIC_ONLY" hoặc "NOT_EXECUTED" PHẢI được hiển thị
  là hành động chưa verified (không chặn mạng thật);
- mọi lỗi IPC → trạng thái fail-closed cho UI (không bao giờ hiển thị đề
  nghị "đã xử lý" khi thực chất chưa gửi được lệnh).
"""

import re
from typing import Any, Dict, List, Optional

from ..ipc.client import NamedPipeClient
from ..ipc.pipe_session import load_pinned_agent_key

MAX_REASON_LEN = 200  # đối xứng MAX_REASON_LEN phía Rust (DecisionLog)
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
VALID_ACTIONS = ("approve", "lift", "reject")


class IsolationInputError(ValueError):
    """Input của operator không đạt bounds — chặn trước khi gửi IPC."""


def create_isolation_inbox() -> Dict[str, Any]:
    """Lệnh truy vấn Isolation Inbox (đề nghị đang chờ + enforcement mode)."""
    return {"command": "IsolationInbox"}


def create_isolation_decision(subject_hex: str, action: str, reason: str) -> Dict[str, Any]:
    """Lệnh quyết định cách ly của operator — bounds kiểm tra cả phía UI."""
    if not HEX_64.match(subject_hex or ""):
        raise IsolationInputError("subject_hex phải là 64 ký tự hex")
    if action not in VALID_ACTIONS:
        raise IsolationInputError(f"action phải thuộc {VALID_ACTIONS}")
    if len(reason or "") > MAX_REASON_LEN:
        raise IsolationInputError(f"reason vượt {MAX_REASON_LEN} ký tự")
    return {
        "command": {
            "IsolationDecision": {
                "subject_hex": subject_hex.lower(),
                "action": action,
                "reason": reason or "",
            }
        }
    }


class IsolationService:
    """Gọi IPC cho trang Isolation Inbox — client riêng, fail-closed khi lỗi."""

    def __init__(self, client: Optional[NamedPipeClient] = None):
        # P1-1b: pin khóa agent — thiếu khóa → connect fail-closed (an toàn).
        self.client = client or NamedPipeClient(agent_public_key=load_pinned_agent_key())

    def fetch_inbox(self) -> Dict[str, Any]:
        """Trả {online, enforcement, proposals} — fail-closed khi IPC lỗi."""
        resp = self.client.send_command(create_isolation_inbox())
        if not resp.success or not resp.data:
            return {
                "online": False,
                "enforcement": "UNKNOWN",
                "proposals": [],
                "error": resp.error or "IPC unavailable",
            }
        data = resp.data
        return {
            "online": True,
            "enforcement": data.get("enforcement", "UNKNOWN"),
            "proposals": data.get("proposals", []),
            "error": None,
        }

    def decide(self, subject_hex: str, action: str, reason: str) -> Dict[str, Any]:
        """Gửi quyết định operator; trả dict {ok, enforcement|error}."""
        cmd = create_isolation_decision(subject_hex, action, reason)  # bounds ở đây
        resp = self.client.send_command(cmd)
        if not resp.success:
            return {"ok": False, "error": resp.error or "IPC unavailable"}
        return {"ok": True, "data": resp.data or {}}
