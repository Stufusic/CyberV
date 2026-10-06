# ============================================================================
# CyberV - Stufusic
# Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
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
Protection Page ViewModel (Kernel Technical Truth)
Ref: Docs/ui.md Section 8 & Docs/ủiv.md Section 6
"""

from PySide6.QtCore import Signal
from .base import BaseViewModel
from ..models.protection import KernelShieldInfo


class ProtectionViewModel(BaseViewModel):
    shield_info_changed = Signal(KernelShieldInfo)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._shield_info = KernelShieldInfo()

    @property
    def shield_info(self) -> KernelShieldInfo:
        return self._shield_info

    def update_shield_info(self, info: KernelShieldInfo):
        self._shield_info = info
        self.shield_info_changed.emit(self._shield_info)
        self.state_updated.emit()
