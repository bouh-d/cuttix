"""CaptureWorker — runs LiveCapture on a QThread.

LiveCapture already has its own internal thread for the pcap loop;
this worker just provides start/stop lifecycle + Qt signals so the
GUI can drive it cleanly.
"""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal


class CaptureWorker(QObject):
    started_ok = pyqtSignal()
    stopped_ok = pyqtSignal(dict)       # final stats snapshot
    failed = pyqtSignal(str)

    def __init__(self, capture: Any, iface: str, bpf_filter: str = "",
                 count: int = 0) -> None:
        super().__init__()
        self._cap = capture
        self._iface = iface
        self._filter = bpf_filter
        self._count = count

    def start(self) -> None:
        try:
            self._cap.start(
                interface=self._iface,
                bpf_filter=self._filter,
                count=self._count or None,
            )
            self.started_ok.emit()
        except Exception as exc:
            self.failed.emit(str(exc))

    def stop(self) -> None:
        try:
            self._cap.stop()
            stats = self._cap.stats.snapshot() if hasattr(self._cap, "stats") else {}
            self.stopped_ok.emit(stats)
        except Exception as exc:
            self.failed.emit(str(exc))
