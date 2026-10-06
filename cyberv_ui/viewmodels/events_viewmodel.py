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
Events ViewModel
Ref: Docs/ui.md Section 11, 12
"""

from typing import List, Optional
from PySide6.QtCore import Signal
from .base import BaseViewModel
from ..models.events import SecurityEvent, EventSeverity


class EventsViewModel(BaseViewModel):
    events_filtered_changed = Signal(list)
    selected_event_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_events: List[SecurityEvent] = []
        self._filtered_events: List[SecurityEvent] = []
        self._current_filter: str = "ALL"
        self._selected_event: Optional[SecurityEvent] = None

    @property
    def filtered_events(self) -> List[SecurityEvent]:
        return self._filtered_events

    @property
    def selected_event(self) -> Optional[SecurityEvent]:
        return self._selected_event

    def set_events(self, events: List[SecurityEvent]):
        self._all_events = events
        self._apply_filter()

    def set_filter(self, filter_category: str):
        self._current_filter = (filter_category or "ALL").upper().strip()
        self._apply_filter()

    def select_event(self, event_id: str):
        for ev in self._all_events:
            if ev.event_id == event_id:
                self._selected_event = ev
                self.selected_event_changed.emit(ev)
                return
        self._selected_event = None
        self.selected_event_changed.emit(None)

    def _apply_filter(self):
        if self._current_filter in ("ALL", ""):
            self._filtered_events = list(self._all_events)
        elif self._current_filter == "KERNEL":
            self._filtered_events = [e for e in self._all_events if "KERNEL" in e.source.upper()]
        elif self._current_filter == "PROTECTION":
            self._filtered_events = [e for e in self._all_events if "PROTECTION" in e.source.upper() or "SHIELD" in e.source.upper()]
        elif self._current_filter == "RECOVERY":
            self._filtered_events = [e for e in self._all_events if "RECOVERY" in e.source.upper()]
        elif self._current_filter == "ERRORS":
            self._filtered_events = [e for e in self._all_events if e.severity in (EventSeverity.CRITICAL, EventSeverity.EMERGENCY, EventSeverity.WARNING)]
        else:
            self._filtered_events = [e for e in self._all_events if self._current_filter in e.source.upper()]

        self.events_filtered_changed.emit(self._filtered_events)
        self.state_updated.emit()
