"""Tests for the GUI StateStore bridge.

Runs only when PyQt6.QtCore is importable (no display required).
We drive the bus directly and assert store state + emitted signals.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("PyQt6.QtCore")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QCoreApplication  # noqa: E402

from cuttix.core.event_bus import Event, EventBus, EventType  # noqa: E402
from cuttix.gui.state import StateStore  # noqa: E402
from cuttix.models.alert import Alert, AlertSeverity, AlertType  # noqa: E402
from cuttix.models.host import Host  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def qapp():
    app = QCoreApplication.instance() or QCoreApplication([])
    yield app


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def store(bus: EventBus) -> StateStore:
    s = StateStore(bus)
    s.connect_bus()
    yield s
    s.disconnect_bus()


class SignalRecorder:
    """Minimal helper to count Qt signal emissions."""

    def __init__(self, signal) -> None:
        self.count = 0
        self.payloads: list = []
        signal.connect(self._on)

    def _on(self, *args) -> None:
        self.count += 1
        self.payloads.append(args if len(args) != 1 else args[0])


def _host(ip: str, mac: str, vendor: str = "Acme") -> Host:
    return Host(ip=ip, mac=mac, vendor=vendor)


def _publish_host(bus: EventBus, host: Host) -> None:
    bus.publish(Event(type=EventType.HOST_DISCOVERED, data=host, source="scanner"))


class TestHostTracking:
    def test_new_host_added(self, store: StateStore, bus: EventBus) -> None:
        rec = SignalRecorder(store.host_added)
        _publish_host(bus, _host("192.168.1.10", "aa:bb:cc:00:00:01"))
        assert rec.count == 1
        assert len(store.get_hosts()) == 1

    def test_duplicate_host_updates(self, store: StateStore, bus: EventBus) -> None:
        added = SignalRecorder(store.host_added)
        updated = SignalRecorder(store.host_updated)
        h = _host("192.168.1.20", "aa:bb:cc:00:00:02")
        _publish_host(bus, h)
        _publish_host(bus, h)
        assert added.count == 1
        assert updated.count == 1
        assert len(store.get_hosts()) == 1

    def test_host_lost_removes_host(self, store: StateStore, bus: EventBus) -> None:
        h = _host("192.168.1.30", "aa:bb:cc:00:00:03")
        _publish_host(bus, h)
        removed = SignalRecorder(store.host_removed)
        bus.publish(Event(type=EventType.HOST_LOST, data=h, source="scanner"))
        assert removed.count == 1
        assert store.get_hosts() == []

    def test_get_host_by_mac(self, store: StateStore, bus: EventBus) -> None:
        h = _host("192.168.1.40", "AA:BB:CC:00:00:04")
        _publish_host(bus, h)
        # lookup is case-insensitive
        found = store.get_host("aa:bb:cc:00:00:04")
        assert found is not None
        assert found.ip == "192.168.1.40"


class TestStatsUpdates:
    def test_stats_incremented_on_host(self, store: StateStore, bus: EventBus) -> None:
        rec = SignalRecorder(store.stats_changed)
        _publish_host(bus, _host("10.0.0.1", "aa:bb:cc:01:00:01"))
        _publish_host(bus, _host("10.0.0.2", "aa:bb:cc:01:00:02"))
        stats = store.get_stats()
        assert stats.host_count == 2
        assert rec.count >= 2

    def test_scan_status_lifecycle(self, store: StateStore) -> None:
        assert store.get_stats().scan_in_progress is False
        started = SignalRecorder(store.scan_started)
        finished = SignalRecorder(store.scan_finished)
        store.mark_scan_started()
        assert store.get_stats().scan_in_progress is True
        assert started.count == 1
        store.mark_scan_finished(5)
        assert store.get_stats().scan_in_progress is False
        assert finished.count == 1
        assert finished.payloads[0] == 5


class TestAlerts:
    def _alert(self, sev: AlertSeverity = AlertSeverity.HIGH) -> Alert:
        return Alert(
            alert_type=AlertType.ARP_SPOOF,
            severity=sev,
            description="test alert",
            source_ip="1.2.3.4",
        )

    def test_alert_event_updates_store(self, store: StateStore, bus: EventBus) -> None:
        rec = SignalRecorder(store.alert_raised)
        bus.publish(Event(
            type=EventType.ARP_SPOOF_DETECTED,
            data=self._alert(),
            source="ids",
        ))
        assert rec.count == 1
        assert len(store.get_alerts()) == 1
        assert store.get_stats().alert_count == 1

    def test_critical_alert_counted(self, store: StateStore, bus: EventBus) -> None:
        bus.publish(Event(
            type=EventType.ARP_SPOOF_DETECTED,
            data=self._alert(AlertSeverity.CRITICAL),
            source="ids",
        ))
        assert store.get_stats().critical_alerts == 1

    def test_clear_alerts_resets_counters(self, store: StateStore, bus: EventBus) -> None:
        bus.publish(Event(
            type=EventType.NEW_DEVICE,
            data=self._alert(AlertSeverity.LOW),
            source="ids",
        ))
        store.clear_alerts()
        assert store.get_alerts() == []
        assert store.get_stats().alert_count == 0

    def test_alerts_ring_buffer_caps(self, store: StateStore, bus: EventBus) -> None:
        for i in range(StateStore.MAX_ALERTS + 50):
            bus.publish(Event(
                type=EventType.NEW_DEVICE,
                data=self._alert(AlertSeverity.LOW),
                source="ids",
            ))
        assert len(store.get_alerts()) == StateStore.MAX_ALERTS


class TestSpoofTracking:
    def test_host_cut_emits_and_counts(self, store: StateStore, bus: EventBus) -> None:
        rec = SignalRecorder(store.host_cut)
        bus.publish(Event(
            type=EventType.HOST_CUT,
            data={"ip": "192.168.1.50"},
            source="arp",
        ))
        assert rec.count == 1
        assert store.is_spoofed("192.168.1.50")
        assert store.get_stats().spoofed_count == 1

    def test_host_restored_clears_tracking(self, store: StateStore, bus: EventBus) -> None:
        bus.publish(Event(type=EventType.HOST_CUT,
                          data={"ip": "10.0.0.9"}, source="arp"))
        bus.publish(Event(type=EventType.HOST_RESTORED,
                          data={"ip": "10.0.0.9"}, source="arp"))
        assert not store.is_spoofed("10.0.0.9")
        assert store.get_stats().spoofed_count == 0


class TestLifecycle:
    def test_connect_disconnect_idempotent(self, bus: EventBus) -> None:
        s = StateStore(bus)
        s.connect_bus()
        s.connect_bus()
        s.disconnect_bus()
        s.disconnect_bus()

    def test_disconnected_store_ignores_events(self, bus: EventBus) -> None:
        s = StateStore(bus)
        s.connect_bus()
        s.disconnect_bus()
        _publish_host(bus, _host("1.1.1.1", "aa:bb:cc:99:99:99"))
        assert s.get_hosts() == []

    def test_packet_counter(self, store: StateStore, bus: EventBus) -> None:
        from cuttix.models.packet import PacketInfo
        from datetime import datetime
        for _ in range(5):
            bus.publish(Event(
                type=EventType.PACKET_CAPTURED,
                data=PacketInfo(timestamp=datetime.now()),
                source="capture",
            ))
        assert store.get_stats().packets_total == 5
