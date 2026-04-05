"""ARP scanner — host discovery on the local network."""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr, conf  # type: ignore[import]

from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.core.exceptions import (
    InterfaceError,
    InvalidNetworkError,
    PrivilegeError,
    SecurityError,
)
from cuttix.models.host import Host, HostStatus
from cuttix.utils import mac_vendor
from cuttix.utils.network import get_default_interface, get_gateway_ip

logger = logging.getLogger(__name__)


class NetworkScanner:
    """ARP scanner with retry, deduplication, and periodic diff.

    Designed to be the first module wired up in the pipeline.
    Publishes HOST_DISCOVERED / HOST_LOST / HOST_UPDATED on the event bus
    so other modules can react.
    """

    def __init__(
        self,
        interface: str | None = None,
        event_bus: EventBus | None = None,
        arp_control: Any = None,
        db: Any = None,
    ) -> None:
        self._iface = interface or get_default_interface() or conf.iface
        self._bus = event_bus
        self._arp_ctl = arp_control  # for spoofed-host exclusion
        self._db = db
        self._hosts: dict[str, Host] = {}  # keyed by MAC
        self._lock = threading.Lock()
        self._periodic_stop: threading.Event | None = None
        self._periodic_thread: threading.Thread | None = None

        self._validate_interface()
        logger.debug("Scanner init on %s", self._iface)

    # -- public API matching the Scanner Protocol --

    def scan(
        self,
        network: str | None = None,
        timeout: float = 2.0,
        retries: int = 2,
    ) -> list[Host]:
        """Run an ARP scan. Returns discovered hosts."""
        cidr = network or self._guess_cidr()
        self._check_cidr(cidr)

        discovered: dict[str, Host] = {}
        gateway_ip = get_gateway_ip()

        for attempt in range(retries):
            results = self._send_arp(cidr, timeout)
            for ip, mac in results:
                if mac in discovered:
                    discovered[mac].last_seen = datetime.now()
                    # same MAC, different IP? update it
                    if discovered[mac].ip != ip:
                        discovered[mac].ip = ip
                    continue

                is_gw = (ip == gateway_ip) if gateway_ip else False
                vendor = mac_vendor.lookup(mac)
                host = Host(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    status=HostStatus.ACTIVE,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    is_gateway=is_gw,
                )
                discovered[mac] = host

        # hostname resolution (threaded, best-effort)
        self._resolve_hostnames(list(discovered.values()))

        # ARP conflict check: same IP, different MAC
        self._check_arp_conflicts(discovered)

        # diff against previous scan
        self._detect_changes(discovered)

        with self._lock:
            self._hosts = discovered

        # persist to DB if available
        if self._db:
            for h in discovered.values():
                try:
                    self._db.upsert_host(h)
                except Exception:
                    logger.debug("DB upsert failed for %s", h.mac, exc_info=True)

        if self._bus:
            self._bus.publish(Event(
                type=EventType.SCAN_CYCLE_COMPLETE,
                data={"count": len(discovered)},
                source="scanner",
            ))

        return list(discovered.values())

    def get_known_hosts(self) -> dict[str, Host]:
        with self._lock:
            return dict(self._hosts)

    @property
    def interface(self) -> str:
        return self._iface

    # -- periodic scanning --

    def start_periodic(self, interval: float = 30.0, **scan_kwargs: Any) -> None:
        """Run scans in a loop. Call stop_periodic() to stop."""
        if self._periodic_thread and self._periodic_thread.is_alive():
            logger.warning("Periodic scan already running")
            return

        self._periodic_stop = threading.Event()
        self._periodic_thread = threading.Thread(
            target=self._periodic_loop,
            args=(interval, scan_kwargs),
            name="scanner-periodic",
            daemon=True,
        )
        self._periodic_thread.start()
        logger.info("Started periodic scanning every %.0fs", interval)

    def stop_periodic(self) -> None:
        if self._periodic_stop:
            self._periodic_stop.set()
        if self._periodic_thread:
            self._periodic_thread.join(timeout=5)
            self._periodic_thread = None
            logger.info("Periodic scanning stopped")

    # -- internals --

    def _periodic_loop(self, interval: float, kwargs: dict[str, Any]) -> None:
        assert self._periodic_stop is not None
        while not self._periodic_stop.is_set():
            try:
                self.scan(**kwargs)
            except Exception:
                logger.exception("Periodic scan failed")
            self._periodic_stop.wait(interval)

    def _send_arp(self, cidr: str, timeout: float) -> list[tuple[str, str]]:
        """Send ARP who-has and return (ip, mac) pairs."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        try:
            ans, _ = srp(
                pkt,
                timeout=timeout,
                iface=self._iface,
                verbose=False,
                retry=0,
            )
        except PermissionError:
            raise PrivilegeError(
                "Root/admin required for ARP scan. Run with sudo."
            )
        except OSError as exc:
            raise InterfaceError(
                f"Interface {self._iface} not usable: {exc}"
            ) from exc

        results = []
        for _, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.lower()
            results.append((ip, mac))
        return results

    def _detect_changes(self, new: dict[str, Host]) -> None:
        """Publish HOST_DISCOVERED / HOST_LOST / HOST_UPDATED events."""
        if not self._bus:
            return

        with self._lock:
            old = self._hosts

        old_macs = set(old.keys())
        new_macs = set(new.keys())

        # get spoofed hosts so we don't emit false HOST_LOST
        spoofed_ips: set[str] = set()
        if self._arp_ctl:
            try:
                spoofed_ips = set(self._arp_ctl.get_spoofed().keys())
            except Exception:
                pass

        for mac in new_macs - old_macs:
            self._bus.publish(Event(
                type=EventType.HOST_DISCOVERED,
                data=new[mac],
                source="scanner",
            ))

        for mac in old_macs - new_macs:
            host = old[mac]
            if host.ip in spoofed_ips:
                continue  # we're spoofing it, don't cry about it
            self._bus.publish(Event(
                type=EventType.HOST_LOST,
                data=host,
                source="scanner",
            ))

        # IP or vendor changed for existing MAC
        for mac in old_macs & new_macs:
            o, n = old[mac], new[mac]
            if o.ip != n.ip or o.vendor != n.vendor:
                self._bus.publish(Event(
                    type=EventType.HOST_UPDATED,
                    data=n,
                    source="scanner",
                ))

    def _check_arp_conflicts(self, hosts: dict[str, Host]) -> None:
        """Detect multiple MACs claiming the same IP."""
        if not self._bus:
            return

        ip_to_macs: dict[str, list[str]] = {}
        for mac, host in hosts.items():
            ip_to_macs.setdefault(host.ip, []).append(mac)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                self._bus.publish(Event(
                    type=EventType.ARP_CONFLICT,
                    data={"ip": ip, "macs": macs},
                    source="scanner",
                ))

    def _resolve_hostnames(self, hosts: list[Host]) -> None:
        """Batch reverse DNS, best-effort."""

        def _rdns(host: Host) -> None:
            try:
                name, _, _ = socket.gethostbyaddr(host.ip)
                host.hostname = name
            except (socket.herror, socket.gaierror, OSError):
                pass

        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = [pool.submit(_rdns, h) for h in hosts]
            for f in as_completed(futs, timeout=5):
                try:
                    f.result()
                except Exception:
                    pass

    def _validate_interface(self) -> None:
        available = get_if_list()
        if self._iface not in available:
            raise InterfaceError(
                f"Interface '{self._iface}' not found. "
                f"Available: {', '.join(available)}"
            )

    def _guess_cidr(self) -> str:
        """Get the CIDR for the scanner's interface."""
        ip = get_if_addr(self._iface)
        if not ip or ip == "0.0.0.0":
            raise InterfaceError(
                f"No IP address on interface {self._iface}"
            )
        # assume /24 — covers 99% of home/office LANs
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(net)

    @staticmethod
    def _check_cidr(cidr: str) -> None:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as exc:
            raise InvalidNetworkError(f"Bad network: {cidr}") from exc

        if net.prefixlen < 16:
            raise SecurityError(
                f"Refusing to scan /{net.prefixlen} — too wide (max /16)"
            )
