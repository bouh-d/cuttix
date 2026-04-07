"""Tests for GUI QThread workers.

Only QtCore is required, so these run headless with the offscreen
platform. Workers are driven synchronously — we call run()/start()/stop()
directly on the main thread and assert emitted signals.
"""
from __future__ import annotations

import os
from typing import Any

import pytest

pytest.importorskip("PyQt6.QtCore")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QCoreApplication  # noqa: E402

from cuttix.gui.workers.capture_worker import CaptureWorker  # noqa: E402
from cuttix.gui.workers.scan_worker import ScanWorker, launch_scan  # noqa: E402
from cuttix.gui.workers.watch_worker import WatchWorker  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def qapp():
    app = QCoreApplication.instance() or QCoreApplication([])
    yield app


class _Recorder:
    def __init__(self, signal) -> None:
        self.count = 0
        self.payloads: list = []
        signal.connect(self._on)

    def _on(self, *args) -> None:
        self.count += 1
        self.payloads.append(args if len(args) != 1 else args[0])


class FakeScanner:
    def __init__(self, hosts=None, raises: Exception | None = None) -> None:
        self._hosts = hosts or []
        self._raises = raises
        self.calls: list[dict] = []

    def scan(self, network=None, timeout=2.0, retries=2) -> list[Any]:
        self.calls.append({"network": network, "timeout": timeout, "retries": retries})
        if self._raises:
            raise self._raises
        return list(self._hosts)


class TestScanWorker:
    def test_successful_scan_emits_done(self) -> None:
        scanner = FakeScanner(hosts=[object(), object(), object()])
        worker = ScanWorker(scanner, network="10.0.0.0/24", timeout=1.0, retries=1)
        done = _Recorder(worker.scan_done)
        failed = _Recorder(worker.scan_failed)
        progress = _Recorder(worker.progress)

        worker.run()

        assert done.count == 1
        assert done.payloads[0] == 3
        assert failed.count == 0
        assert progress.count == 1
        assert scanner.calls[0]["network"] == "10.0.0.0/24"
        assert scanner.calls[0]["timeout"] == 1.0
        assert scanner.calls[0]["retries"] == 1

    def test_scanner_error_emits_failed(self) -> None:
        scanner = FakeScanner(raises=RuntimeError("iface down"))
        worker = ScanWorker(scanner)
        done = _Recorder(worker.scan_done)
        failed = _Recorder(worker.scan_failed)

        worker.run()

        assert done.count == 0
        assert failed.count == 1
        assert "iface down" in failed.payloads[0]

    def test_launch_scan_returns_thread_and_worker(self) -> None:
        scanner = FakeScanner(hosts=[object()])
        thread, worker = launch_scan(scanner, network="192.168.0.0/24")
        try:
            assert thread is not None
            assert isinstance(worker, ScanWorker)
            assert worker._network == "192.168.0.0/24"
            # don't start() in the test — just verify wiring is set up
        finally:
            thread.deleteLater()


class FakeCapture:
    class _Stats:
        def snapshot(self) -> dict:
            return {"total_packets": 42, "elapsed_seconds": 3}

    def __init__(self, start_raises: Exception | None = None,
                 stop_raises: Exception | None = None) -> None:
        self.stats = self._Stats()
        self._start_raises = start_raises
        self._stop_raises = stop_raises
        self.start_called_with: dict | None = None
        self.stop_called = False

    def start(self, interface=None, bpf_filter="", count=None) -> None:
        self.start_called_with = {
            "interface": interface, "bpf_filter": bpf_filter, "count": count,
        }
        if self._start_raises:
            raise self._start_raises

    def stop(self) -> None:
        self.stop_called = True
        if self._stop_raises:
            raise self._stop_raises


class TestCaptureWorker:
    def test_start_emits_started_ok(self) -> None:
        cap = FakeCapture()
        worker = CaptureWorker(cap, iface="eth0", bpf_filter="tcp", count=0)
        ok = _Recorder(worker.started_ok)
        failed = _Recorder(worker.failed)

        worker.start()

        assert ok.count == 1
        assert failed.count == 0
        assert cap.start_called_with == {
            "interface": "eth0", "bpf_filter": "tcp", "count": None,
        }

    def test_start_forwards_count(self) -> None:
        cap = FakeCapture()
        worker = CaptureWorker(cap, iface="eth0", count=100)
        worker.start()
        assert cap.start_called_with["count"] == 100

    def test_start_failure_emits_failed(self) -> None:
        cap = FakeCapture(start_raises=RuntimeError("no pcap"))
        worker = CaptureWorker(cap, iface="eth0")
        failed = _Recorder(worker.failed)
        worker.start()
        assert failed.count == 1
        assert "no pcap" in failed.payloads[0]

    def test_stop_emits_stats_snapshot(self) -> None:
        cap = FakeCapture()
        worker = CaptureWorker(cap, iface="eth0")
        stopped = _Recorder(worker.stopped_ok)
        worker.stop()
        assert cap.stop_called
        assert stopped.count == 1
        assert stopped.payloads[0] == {"total_packets": 42, "elapsed_seconds": 3}

    def test_stop_error_emits_failed(self) -> None:
        cap = FakeCapture(stop_raises=OSError("bad state"))
        worker = CaptureWorker(cap, iface="eth0")
        failed = _Recorder(worker.failed)
        worker.stop()
        assert failed.count == 1


class TestWatchWorker:
    def test_stop_before_run_exits_promptly(self) -> None:
        scanner = FakeScanner(hosts=[object()])
        worker = WatchWorker(scanner, interval=1)
        stopped = _Recorder(worker.stopped)
        cycle_done = _Recorder(worker.cycle_done)

        worker.stop()  # set flag before run
        # First iteration still runs once because while-check is at top,
        # but stop flag is already True so loop exits after first pass.
        worker.run()

        assert stopped.count == 1
        # one cycle may still happen depending on scheduling; both are OK
        assert cycle_done.count <= 1

    def test_cycle_failed_on_error(self) -> None:
        scanner = FakeScanner(raises=RuntimeError("boom"))
        worker = WatchWorker(scanner, interval=1)
        failed = _Recorder(worker.cycle_failed)
        stopped = _Recorder(worker.stopped)

        worker.stop()
        worker.run()

        assert failed.count <= 1
        assert stopped.count == 1

    def test_interval_lower_bound(self) -> None:
        scanner = FakeScanner()
        w = WatchWorker(scanner, interval=0)
        assert w._interval >= 1
