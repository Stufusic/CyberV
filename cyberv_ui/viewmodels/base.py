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
Base ViewModel for PySide6 MVVM Pattern
Ref: Docs/ủiv.md Section 2
"""

from PySide6.QtCore import QObject, Signal


class BaseViewModel(QObject):
    """
    Base ViewModel providing unified reactive signals for all feature view models.
    """
    is_loading_changed = Signal(bool)
    error_message_emitted = Signal(str)
    state_updated = Signal()

    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self._is_loading: bool = False

    @property
    def is_loading(self) -> bool:
        return self._is_loading

    def set_loading(self, loading: bool) -> None:
        if self._is_loading != loading:
            self._is_loading = loading
            self.is_loading_changed.emit(loading)

    def emit_error(self, message: str) -> None:
        self.error_message_emitted.emit(message)
