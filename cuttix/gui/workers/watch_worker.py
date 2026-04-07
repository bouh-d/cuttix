"""WatchWorker — periodic scan loop, feeds the IDS via the bus.

Runs scanner.scan() on a timer. The StateStore picks up
HOST_DISCOVERED events and the IDS raises alerts. This worker
just owns the loop + stop flag.
"""
from __future__ import annotations

import time
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal


class WatchWorker(QObject):
    cycle_done = pyqtSignal(int)       # host count for this cycle
    cycle_failed = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(self, scanner: Any, interval: int = 30,
                 network: str | None = None) -> None:
        super().__init__()
        self._scanner = scanner
        self._interval = max(1, interval)
        self._network = network
        self._stop = False

    def run(self) -> None:
        while not self._stop:
            try:
                hosts = self._scanner.scan(network=self._network)
                self.cycle_done.emit(len(hosts))
            except Exception as exc:
                self.cycle_failed.emit(str(exc))

            # sleep in small slices so stop() reacts quickly
            for _ in range(self._interval * 10):
                if self._stop:
                    break
                time.sleep(0.1)

        self.stopped.emit()

    def stop(self) -> None:
        self._stop = True
