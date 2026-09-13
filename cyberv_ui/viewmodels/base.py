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
