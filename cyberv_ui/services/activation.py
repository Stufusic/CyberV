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
Service Activation Controller for CyberV UI
Ref: Docs/rvnew.md Section 6 ("Enable 24/7 Protection" UX Flow)
Handles Windows UAC elevation and Windows Service lifecycle management.
"""

import os
import subprocess
import sys
from typing import Tuple

from PySide6.QtCore import QObject, Signal


class ServiceActivationController(QObject):
    activation_status_changed = Signal(str, str)  # status_key, message

    SERVICE_NAME = "CyberVAgent"

    def __init__(self, parent=None):
        super().__init__(parent)

    def is_service_installed(self) -> bool:
        """Checks whether CyberVAgent Windows Service is installed."""
        if sys.platform != "win32":
            return False
        try:
            res = subprocess.run(
                ["sc", "query", self.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return "FAILED 1060" not in res.stdout and res.returncode == 0
        except Exception:
            return False

    def is_service_running(self) -> bool:
        """Checks whether CyberVAgent Windows Service is currently RUNNING."""
        if sys.platform != "win32":
            return False
        try:
            res = subprocess.run(
                ["sc", "query", self.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return "RUNNING" in res.stdout
        except Exception:
            return False

    def request_enable_protection(self) -> Tuple[bool, str]:
        """
        Requests Windows UAC elevation to install and start the CyberVAgent service.
        Docs/rvnew.md Section 6: Explains privilege and invokes UAC cleanly.
        """
        if sys.platform != "win32":
            return False, "Chỉ hỗ trợ hệ điều hành Windows."

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        script_path = os.path.join(project_root, "scripts", "install-agent-service.ps1")

        if not os.path.exists(script_path):
            return False, f"Không tìm thấy kịch bản cài đặt: {script_path}"

        self.activation_status_changed.emit("UAC_PROMPT", "Đang yêu cầu quyền Administrator từ Windows UAC...")

        try:
            # Trigger UAC elevation via PowerShell Start-Process -Verb RunAs
            ps_command = (
                f"Start-Process powershell -Verb RunAs "
                f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{script_path}\"'"
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if proc.returncode == 0:
                self.activation_status_changed.emit(
                    "UAC_ACCEPTED",
                    "Đang cài đặt và khởi động dịch vụ CyberV Agent ngầm..."
                )
                return True, "Yêu cầu cài đặt dịch vụ đã được gửi tới Windows UAC."
            else:
                return False, f"Người dùng từ chối cấp quyền UAC hoặc lỗi: {proc.stderr}"
        except Exception as e:
            return False, f"Lỗi khởi chạy UAC: {e}"
