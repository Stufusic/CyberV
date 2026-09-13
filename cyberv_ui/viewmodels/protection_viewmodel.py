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
