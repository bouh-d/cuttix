"""ScanWorker — runs NetworkScanner on a QThread.

Emits scan_done on completion, scan_failed on error. The scanner
publishes HOST_DISCOVERED on the bus, which the StateStore picks up.
"""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QObject, QThread, pyqtSignal


class ScanWorker(QObject):
    scan_done = pyqtSignal(int)        # host_count
    scan_failed = pyqtSignal(str)      # error message
    progress = pyqtSignal(str)         # status text

    def __init__(self, scanner: Any, network: str | None = None,
                 timeout: float = 2.0, retries: int = 2) -> None:
        super().__init__()
        self._scanner = scanner
        self._network = network
        self._timeout = timeout
        self._retries = retries

    def run(self) -> None:
        try:
            self.progress.emit("Scanning…")
            hosts = self._scanner.scan(
                network=self._network,
                timeout=self._timeout,
                retries=self._retries,
            )
            self.scan_done.emit(len(hosts))
        except Exception as exc:
            self.scan_failed.emit(str(exc))


def launch_scan(scanner: Any, network: str | None = None,
                timeout: float = 2.0, retries: int = 2) -> tuple[QThread, ScanWorker]:
    """Convenience: create thread + worker, connect lifecycle, start.

    Caller is responsible for keeping references to both returned objects
    and connecting to worker signals before calling thread.start().
    """
    thread = QThread()
    worker = ScanWorker(scanner, network, timeout, retries)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.scan_done.connect(thread.quit)
    worker.scan_failed.connect(thread.quit)
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    return thread, worker
