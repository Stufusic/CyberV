"""
System ViewModel (Observed vs Verified Separation)
Ref: Docs/ui.md Section 13
"""

from typing import List, Dict
from PySide6.QtCore import Signal
from .base import BaseViewModel


class SystemViewModel(BaseViewModel):
    system_data_changed = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._observed_components: List[Dict[str, str]] = []
        self._verified_evidence: List[Dict[str, str]] = []

    @property
    def observed_components(self) -> List[Dict[str, str]]:
        return self._observed_components

    @property
    def verified_evidence(self) -> List[Dict[str, str]]:
        return self._verified_evidence

    def update_hardware_data(self, observed: List[Dict[str, str]], verified: List[Dict[str, str]]):
        self._observed_components = observed
        self._verified_evidence = verified
        self.system_data_changed.emit({
            "observed": self._observed_components,
            "verified": self._verified_evidence,
        })
        self.state_updated.emit()
