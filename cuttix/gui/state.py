"""StateStore — source of truth for the GUI.

Bridges the EventBus (background threads) to Qt signals (main thread).
All mutations happen in Python/Qt land; handlers are registered on the
bus and forward into thread-safe Qt signals so widgets can connect
without worrying about thread affinity.

The store holds host inventory, alerts, packet counters, and active
spoof targets. Widgets connect to signals and pull snapshots as needed.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.gui.bandwidth import BandwidthAggregator
from cuttix.models.alert import Alert
from cuttix.models.host import Host
from cuttix.models.packet import PacketInfo


@dataclass
class Stats:
    host_count: int = 0
    alert_count: int = 0
    spoofed_count: int = 0
    packets_total: int = 0
    critical_alerts: int = 0
    scan_in_progress: bool = False


class StateStore(QObject):
    """Observable store fed by the EventBus."""

    # host table updates
    host_added = pyqtSignal(object)      # Host
    host_updated = pyqtSignal(object)    # Host
    host_removed = pyqtSignal(str)       # mac

    # alert feed
    alert_raised = pyqtSignal(object)    # Alert

    # ARP control status
    host_cut = pyqtSignal(str)           # ip
    host_restored = pyqtSignal(str)      # ip

    # packets (high-volume — widgets should throttle)
    packet_captured = pyqtSignal(object)

    # dashboard stats (emitted whenever they change)
    stats_changed = pyqtSignal(object)   # Stats

    # scanner lifecycle
    scan_started = pyqtSignal()
    scan_finished = pyqtSignal(int)      # host count

    # generic errors / notifications
    error_raised = pyqtSignal(str, str)  # (title, message)

    MAX_ALERTS = 500
    MAX_PACKETS = 2000

    def __init__(self, bus: EventBus, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._bus = bus
        self._lock = threading.RLock()

        # in-memory state
        self._hosts: dict[str, Host] = {}      # mac → Host
        self._alerts: deque[Alert] = deque(maxlen=self.MAX_ALERTS)
        self._packets: deque[PacketInfo] = deque(maxlen=self.MAX_PACKETS)
        self._spoofed: set[str] = set()        # set of IPs
        self._stats = Stats()
        self._bandwidth = BandwidthAggregator()

        self._subscribed = False

    # -- lifecycle --

    def connect_bus(self) -> None:
        """Subscribe the store to all relevant bus events. Idempotent."""
        if self._subscribed:
            return
        subs = [
            (EventType.HOST_DISCOVERED, self._on_host_discovered),
            (EventType.HOST_UPDATED, self._on_host_updated),
            (EventType.HOST_LOST, self._on_host_lost),
            (EventType.HOST_CUT, self._on_host_cut),
            (EventType.HOST_RESTORED, self._on_host_restored),
            (EventType.PACKET_CAPTURED, self._on_packet_captured),
            (EventType.SCAN_CYCLE_COMPLETE, self._on_scan_complete),
            (EventType.ARP_SPOOF_DETECTED, self._on_alert),
            (EventType.NEW_DEVICE, self._on_alert),
            (EventType.ROGUE_DHCP, self._on_alert),
            (EventType.PORT_SCAN_DETECTED, self._on_alert),
            (EventType.MAC_FLOODING, self._on_alert),
            (EventType.MODULE_ERROR, self._on_module_error),
        ]
        for evt_type, handler in subs:
            self._bus.subscribe(evt_type, handler, "gui.state")
        self._subscribed = True

    def disconnect_bus(self) -> None:
        if not self._subscribed:
            return
        self._bus.unsubscribe_all("gui.state")
        self._subscribed = False

    # -- public read API (thread-safe snapshots) --

    def get_hosts(self) -> list[Host]:
        with self._lock:
            return list(self._hosts.values())

    def get_host(self, mac: str) -> Host | None:
        with self._lock:
            return self._hosts.get(mac.lower())

    def get_alerts(self, limit: int | None = None) -> list[Alert]:
        with self._lock:
            lst = list(self._alerts)
        if limit is None:
            return lst
        return lst[-limit:]

    def get_stats(self) -> Stats:
        with self._lock:
            return Stats(
                host_count=self._stats.host_count,
                alert_count=self._stats.alert_count,
                spoofed_count=self._stats.spoofed_count,
                packets_total=self._stats.packets_total,
                critical_alerts=self._stats.critical_alerts,
                scan_in_progress=self._stats.scan_in_progress,
            )

    def is_spoofed(self, ip: str) -> bool:
        with self._lock:
            return ip in self._spoofed

    def get_recent_packets(self, limit: int | None = None) -> list[PacketInfo]:
        with self._lock:
            lst = list(self._packets)
        if limit is None:
            return lst
        return lst[-limit:]

    @property
    def bandwidth(self) -> BandwidthAggregator:
        return self._bandwidth

    # -- direct mutations (used by widgets or workers) --

    def mark_scan_started(self) -> None:
        with self._lock:
            self._stats.scan_in_progress = True
        self.scan_started.emit()
        self.stats_changed.emit(self.get_stats())

    def mark_scan_finished(self, count: int) -> None:
        with self._lock:
            self._stats.scan_in_progress = False
        self.scan_finished.emit(count)
        self.stats_changed.emit(self.get_stats())

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()
            self._stats.alert_count = 0
            self._stats.critical_alerts = 0
        self.stats_changed.emit(self.get_stats())

    # -- event bus handlers --

    def _on_host_discovered(self, evt: Event) -> None:
        host = evt.data
        if not isinstance(host, Host):
            return
        is_new = False
        with self._lock:
            mac = host.mac.lower()
            if mac not in self._hosts:
                is_new = True
            self._hosts[mac] = host
            self._stats.host_count = len(self._hosts)
        if is_new:
            self.host_added.emit(host)
        else:
            self.host_updated.emit(host)
        self.stats_changed.emit(self.get_stats())

    def _on_host_updated(self, evt: Event) -> None:
        host = evt.data
        if not isinstance(host, Host):
            return
        with self._lock:
            self._hosts[host.mac.lower()] = host
        self.host_updated.emit(host)

    def _on_host_lost(self, evt: Event) -> None:
        data = evt.data
        if isinstance(data, Host):
            mac = data.mac.lower()
        elif isinstance(data, dict):
            mac = str(data.get("mac", "")).lower()
        else:
            return
        with self._lock:
            self._hosts.pop(mac, None)
            self._stats.host_count = len(self._hosts)
        self.host_removed.emit(mac)
        self.stats_changed.emit(self.get_stats())

    def _on_host_cut(self, evt: Event) -> None:
        ip = self._extract_ip(evt.data)
        if not ip:
            return
        with self._lock:
            self._spoofed.add(ip)
            self._stats.spoofed_count = len(self._spoofed)
        self.host_cut.emit(ip)
        self.stats_changed.emit(self.get_stats())

    def _on_host_restored(self, evt: Event) -> None:
        ip = self._extract_ip(evt.data)
        if not ip:
            return
        with self._lock:
            self._spoofed.discard(ip)
            self._stats.spoofed_count = len(self._spoofed)
        self.host_restored.emit(ip)
        self.stats_changed.emit(self.get_stats())

    def _on_packet_captured(self, evt: Event) -> None:
        pkt = evt.data
        with self._lock:
            self._stats.packets_total += 1
            if isinstance(pkt, PacketInfo):
                self._packets.append(pkt)
                self._bandwidth.add_packet(pkt)
        self.packet_captured.emit(pkt)

    def _on_scan_complete(self, evt: Event) -> None:
        data = evt.data if isinstance(evt.data, dict) else {}
        count = int(data.get("host_count", self._stats.host_count))
        self.mark_scan_finished(count)

    def _on_alert(self, evt: Event) -> None:
        alert = evt.data
        if not isinstance(alert, Alert):
            return
        with self._lock:
            self._alerts.append(alert)
            self._stats.alert_count = len(self._alerts)
            if alert.severity.value == "critical":
                self._stats.critical_alerts += 1
        self.alert_raised.emit(alert)
        self.stats_changed.emit(self.get_stats())

    def _on_module_error(self, evt: Event) -> None:
        data = evt.data if isinstance(evt.data, dict) else {}
        title = str(data.get("module", "Module"))
        msg = str(data.get("error", "Unknown error"))
        self.error_raised.emit(title, msg)

    # -- helpers --

    @staticmethod
    def _extract_ip(data: Any) -> str | None:
        if isinstance(data, dict):
            return data.get("ip") or data.get("target_ip")
        return getattr(data, "ip", None) or getattr(data, "target_ip", None)
