"""Lightweight IDS — event-driven threat detection.

Subscribes to the EventBus and watches for:
  - ARP spoof (MAC change for known IP, gratuitous ARP)
  - New device (unknown MAC)
  - Rogue DHCP server
  - Inbound port scan (threshold-based)
  - MAC flooding (many new MACs in short window)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from cuttix.config import IDSConfig
from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.models.alert import Alert, AlertSeverity, AlertType

logger = logging.getLogger(__name__)


def _default_whitelist_path() -> Path:
    import os
    import sys

    if sys.platform == "linux":
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".local" / "share"
    d = base / "cuttix"
    d.mkdir(parents=True, exist_ok=True)
    return d / "whitelist.json"


class NetworkIDS:
    """Event-driven intrusion detection.

    Hooks into EventBus to consume HOST_DISCOVERED, PACKET_CAPTURED,
    ARP_CONFLICT events and emit alert events (ARP_SPOOF_DETECTED,
    NEW_DEVICE, ROGUE_DHCP, PORT_SCAN_DETECTED, MAC_FLOODING).
    """

    def __init__(
        self,
        event_bus: EventBus,
        config: IDSConfig | None = None,
        db: Any = None,
        whitelist_path: Path | str | None = None,
    ) -> None:
        self._bus = event_bus
        self._cfg = config or IDSConfig()
        self._db = db  # optional Database instance for alert persistence
        self._running = False
        self._lock = threading.Lock()

        # known state
        self._ip_to_mac: dict[str, str] = {}  # IP → last known MAC
        self._known_macs: set[str] = set()
        self._alerts: list[Alert] = []

        # port scan tracking: src_ip → list of (port, timestamp)
        self._port_hits: dict[str, list[tuple[int, float]]] = defaultdict(list)

        # MAC flood tracking: deque of (mac, timestamp) in the last window
        self._recent_macs: list[tuple[str, float]] = []
        self._mac_flood_window = 60  # seconds
        self._mac_flood_threshold = 100

        # DHCP server tracking
        self._authorized_dhcp: set[str] = set()  # set of known-good DHCP servers

        # whitelist
        if whitelist_path is None:
            self._wl_path = _default_whitelist_path()
        else:
            self._wl_path = Path(whitelist_path)
        self._whitelist: set[str] = set()
        self._load_whitelist()

        if self._cfg.whitelist:
            for mac in self._cfg.whitelist:
                self._whitelist.add(mac.lower())

    # -- Protocol: IDS --

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._subscribe()
        logger.info("IDS started (%d detection rules active)", self._active_rules())

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        self._bus.unsubscribe_all("ids")
        logger.info("IDS stopped — %d alerts raised this session", len(self._alerts))

    def get_alerts(self, since: float | None = None) -> list[Alert]:
        with self._lock:
            if since is None:
                return list(self._alerts)
            return [a for a in self._alerts if a.created_at.timestamp() >= since]

    def get_whitelist(self) -> set[str]:
        return set(self._whitelist)

    def add_to_whitelist(self, mac: str) -> None:
        mac = mac.lower()
        self._whitelist.add(mac)
        self._save_whitelist()
        logger.info("Added %s to IDS whitelist", mac)

    def remove_from_whitelist(self, mac: str) -> None:
        mac = mac.lower()
        self._whitelist.discard(mac)
        self._save_whitelist()

    # -- internal: event subscriptions --

    def _subscribe(self) -> None:
        subs = []
        if self._cfg.detect_arp_spoof:
            subs.append((EventType.HOST_DISCOVERED, self._check_arp_spoof))
            subs.append((EventType.ARP_CONFLICT, self._on_arp_conflict))
        if self._cfg.detect_new_device:
            subs.append((EventType.HOST_DISCOVERED, self._check_new_device))
        if self._cfg.detect_rogue_dhcp:
            subs.append((EventType.PACKET_CAPTURED, self._check_rogue_dhcp))
        if self._cfg.detect_port_scan:
            subs.append((EventType.PACKET_CAPTURED, self._check_port_scan))
        if self._cfg.detect_mac_flooding:
            subs.append((EventType.HOST_DISCOVERED, self._check_mac_flooding))

        for evt_type, handler in subs:
            self._bus.subscribe(evt_type, handler, "ids")

    def _active_rules(self) -> int:
        count = 0
        for attr in (
            "detect_arp_spoof",
            "detect_new_device",
            "detect_rogue_dhcp",
            "detect_port_scan",
            "detect_mac_flooding",
        ):
            if getattr(self._cfg, attr):
                count += 1
        return count

    # -- detection: ARP spoof --

    def _check_arp_spoof(self, event: Event) -> None:
        host = event.data
        if not hasattr(host, "ip") or not hasattr(host, "mac"):
            return

        ip = host.ip
        mac = host.mac.lower()

        if mac in self._whitelist:
            return

        with self._lock:
            prev_mac = self._ip_to_mac.get(ip)
            self._ip_to_mac[ip] = mac

        if prev_mac and prev_mac != mac:
            alert = Alert(
                alert_type=AlertType.ARP_SPOOF,
                severity=AlertSeverity.HIGH,
                description=f"MAC changed for {ip}: {prev_mac} → {mac}",
                source_ip=ip,
                source_mac=mac,
                target_mac=prev_mac,
                raw_data={"previous_mac": prev_mac, "new_mac": mac},
            )
            self._raise_alert(alert, EventType.ARP_SPOOF_DETECTED)

    def _on_arp_conflict(self, event: Event) -> None:
        """Handle ARP conflict events from the scanner."""
        data = event.data if isinstance(event.data, dict) else {}
        ip = data.get("ip", "?")
        macs = data.get("macs", [])

        alert = Alert(
            alert_type=AlertType.ARP_SPOOF,
            severity=AlertSeverity.CRITICAL,
            description=f"ARP conflict on {ip}: multiple MACs {macs}",
            source_ip=ip,
            raw_data=data,
        )
        self._raise_alert(alert, EventType.ARP_SPOOF_DETECTED)

    # -- detection: new device --

    def _check_new_device(self, event: Event) -> None:
        host = event.data
        if not hasattr(host, "mac"):
            return

        mac = host.mac.lower()
        if mac in self._whitelist:
            return

        with self._lock:
            if mac in self._known_macs:
                return
            self._known_macs.add(mac)

        ip = getattr(host, "ip", "?")
        vendor = getattr(host, "vendor", None) or "unknown"

        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.LOW,
            description=f"New device: {ip} [{mac}] vendor={vendor}",
            source_ip=ip,
            source_mac=mac,
            raw_data={"vendor": vendor},
        )
        self._raise_alert(alert, EventType.NEW_DEVICE)

    # -- detection: rogue DHCP --

    def _check_rogue_dhcp(self, event: Event) -> None:
        """Look for DHCP offer/ACK packets from unauthorized servers."""
        pkt = event.data
        if not hasattr(pkt, "protocol"):
            return

        # DHCP runs on UDP 67 (server) / 68 (client)
        if getattr(pkt, "src_port", None) != 67:
            return
        if getattr(pkt, "dst_port", None) != 68:
            return

        src_ip = getattr(pkt, "src_ip", None)
        if not src_ip:
            return

        src_mac = getattr(pkt, "src_mac", None) or "?"

        if src_mac.lower() in self._whitelist:
            return
        if src_ip in self._authorized_dhcp:
            return

        alert = Alert(
            alert_type=AlertType.ROGUE_DHCP,
            severity=AlertSeverity.HIGH,
            description=f"Rogue DHCP server detected: {src_ip} [{src_mac}]",
            source_ip=src_ip,
            source_mac=src_mac,
            raw_data={"server_ip": src_ip, "server_mac": src_mac},
        )
        self._raise_alert(alert, EventType.ROGUE_DHCP)

    # -- detection: port scan --

    def _check_port_scan(self, event: Event) -> None:
        pkt = event.data
        if not hasattr(pkt, "dst_port") or not hasattr(pkt, "src_ip"):
            return

        dst_port = getattr(pkt, "dst_port", None)
        src_ip = getattr(pkt, "src_ip", None)
        if dst_port is None or src_ip is None:
            return

        now = time.time()
        threshold_ports = self._cfg.port_scan_threshold_ports
        threshold_secs = self._cfg.port_scan_threshold_seconds

        with self._lock:
            hits = self._port_hits[src_ip]
            # prune old entries
            cutoff = now - threshold_secs
            hits[:] = [(p, t) for p, t in hits if t > cutoff]
            hits.append((dst_port, now))

            # count unique ports in window
            unique_ports = {p for p, _ in hits}
            if len(unique_ports) >= threshold_ports:
                # only alert once per window
                self._port_hits[src_ip] = []

        if len(unique_ports) >= threshold_ports:
            alert = Alert(
                alert_type=AlertType.PORT_SCAN,
                severity=AlertSeverity.MEDIUM,
                description=(
                    f"Port scan from {src_ip}: {len(unique_ports)} ports in {threshold_secs}s"
                ),
                source_ip=src_ip,
                raw_data={
                    "unique_ports": len(unique_ports),
                    "window_seconds": threshold_secs,
                    "ports": sorted(unique_ports),
                },
            )
            self._raise_alert(alert, EventType.PORT_SCAN_DETECTED)

    # -- detection: MAC flooding --

    def _check_mac_flooding(self, event: Event) -> None:
        host = event.data
        if not hasattr(host, "mac"):
            return

        mac = host.mac.lower()
        now = time.time()

        with self._lock:
            cutoff = now - self._mac_flood_window
            self._recent_macs = [(m, t) for m, t in self._recent_macs if t > cutoff]
            self._recent_macs.append((mac, now))

            unique_new = {m for m, _ in self._recent_macs}
            if len(unique_new) < self._mac_flood_threshold:
                return

            # reset to avoid repeated alerts
            self._recent_macs = []

        alert = Alert(
            alert_type=AlertType.MAC_FLOODING,
            severity=AlertSeverity.CRITICAL,
            description=(f"MAC flooding: {len(unique_new)} new MACs in {self._mac_flood_window}s"),
            raw_data={
                "unique_macs": len(unique_new),
                "window_seconds": self._mac_flood_window,
            },
        )
        self._raise_alert(alert, EventType.MAC_FLOODING)

    # -- alert management --

    def _raise_alert(self, alert: Alert, event_type: EventType) -> None:
        with self._lock:
            self._alerts.append(alert)

        # persist if we have a DB
        if self._db is not None:
            try:
                self._db.insert_alert(alert)
            except Exception:
                logger.debug("Failed to persist alert", exc_info=True)

        # publish to event bus
        self._bus.publish(
            Event(
                type=event_type,
                data=alert,
                source="ids",
            )
        )

        logger.warning(
            "IDS ALERT [%s/%s]: %s",
            alert.alert_type.name,
            alert.severity.value,
            alert.description,
        )

    # -- whitelist persistence --

    def _load_whitelist(self) -> None:
        if not self._wl_path.exists():
            return
        try:
            data = json.loads(self._wl_path.read_text())
            self._whitelist = {m.lower() for m in data.get("macs", [])}
        except Exception:
            logger.debug("Could not load whitelist from %s", self._wl_path)

    def _save_whitelist(self) -> None:
        try:
            self._wl_path.parent.mkdir(parents=True, exist_ok=True)
            self._wl_path.write_text(json.dumps({"macs": sorted(self._whitelist)}, indent=2) + "\n")
        except Exception:
            logger.debug("Could not save whitelist to %s", self._wl_path)

    # -- seeding known state --

    def seed_known_hosts(self, hosts: dict[str, Any]) -> None:
        """Pre-populate known MACs/IPs from a prior scan.
        Avoids false NEW_DEVICE alerts for hosts seen before IDS started.
        """
        with self._lock:
            for ip, host in hosts.items():
                if isinstance(host, dict):
                    mac = host.get("mac", "")
                else:
                    mac = getattr(host, "mac", "") or ""
                if not mac:
                    continue
                mac = mac.lower()
                self._ip_to_mac[ip] = mac
                self._known_macs.add(mac)

    def set_authorized_dhcp(self, servers: list[str]) -> None:
        self._authorized_dhcp = set(servers)
