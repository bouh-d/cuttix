"""TCP port scanner — Connect scan (no root) + SYN scan (root)."""

from __future__ import annotations

import contextlib
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.core.exceptions import PrivilegeError
from cuttix.models.scan_result import PortEntry, ScanResult

logger = logging.getLogger(__name__)

_top_ports_cache: dict[str, Any] | None = None


def _load_top_ports() -> dict[str, Any]:
    global _top_ports_cache
    if _top_ports_cache is not None:
        return _top_ports_cache

    path = Path(__file__).resolve().parent.parent.parent / "assets" / "top_ports.json"
    try:
        with open(path) as f:
            _top_ports_cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Can't load top_ports.json: %s — using fallback", exc)
        _top_ports_cache = {
            "top_100": [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                143,
                443,
                445,
                993,
                995,
                1433,
                3306,
                3389,
                5432,
                5900,
                8080,
                8443,
            ],
            "services": {},
            "profiles": {},
        }
    return _top_ports_cache


def _service_name(port: int) -> str | None:
    """Lookup service name from our asset database."""
    db = _load_top_ports()
    return db.get("services", {}).get(str(port))


def get_profile_ports(profile: str) -> list[int] | None:
    """Get port list for a named profile (web, database, iot, etc)."""
    db = _load_top_ports()
    return db.get("profiles", {}).get(profile)


class TCPPortScanner:
    """Port scanner with connect and SYN techniques.

    Connect scan uses stdlib sockets (no root needed).
    SYN scan uses scapy raw packets (root required).
    """

    def __init__(
        self,
        event_bus: EventBus | None = None,
        max_workers: int = 20,
        timeout: float = 2.0,
        rate_limit: int = 0,
    ) -> None:
        self._bus = event_bus
        self._max_workers = max_workers
        self._timeout = timeout
        self._rate_limit = rate_limit  # max ports/sec, 0 = unlimited
        self._rate_lock = threading.Lock()
        self._last_send: float = 0

    # -- Protocol methods --

    def scan_host(
        self,
        target_ip: str,
        ports: list[int] | None = None,
        technique: str = "connect",
    ) -> ScanResult:
        """Scan specific ports on a host."""
        if ports is None:
            ports = _load_top_ports()["top_100"]

        if technique == "syn":
            entries = self._syn_scan(target_ip, ports)
        else:
            entries = self._connect_scan(target_ip, ports)

        result = ScanResult(target_ip=target_ip, ports=entries)

        # grab banners for open ports
        self._banner_grab(target_ip, result.open_ports)

        if self._bus:
            self._bus.publish(
                Event(
                    type=EventType.PORTS_SCANNED,
                    data={
                        "target_ip": target_ip,
                        "open": len(result.open_ports),
                        "total": len(ports),
                        "technique": technique,
                    },
                    source="port_scanner",
                )
            )

            # emit SERVICE_FOUND for interesting services
            for p in result.open_ports:
                if p.service:
                    self._bus.publish(
                        Event(
                            type=EventType.SERVICE_FOUND,
                            data={
                                "target_ip": target_ip,
                                "port": p.port,
                                "service": p.service,
                                "banner": p.banner,
                            },
                            source="port_scanner",
                        )
                    )

        return result

    def scan_top_ports(self, target_ip: str, top_n: int = 100) -> ScanResult:
        """Scan the N most common ports."""
        all_top = _load_top_ports()["top_100"]
        ports = all_top[: min(top_n, len(all_top))]
        return self.scan_host(target_ip, ports=ports)

    # -- Connect scan --

    def _connect_scan(self, ip: str, ports: list[int]) -> list[PortEntry]:
        """Full TCP handshake per port — works without root."""
        results: list[PortEntry] = []
        lock = threading.Lock()

        def _probe(port: int) -> None:
            self._rate_wait()
            state = self._tcp_connect(ip, port)
            svc = _service_name(port) if state == "open" else None
            entry = PortEntry(port=port, protocol="tcp", state=state, service=svc)
            with lock:
                results.append(entry)

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futs = [pool.submit(_probe, p) for p in ports]
            for f in as_completed(futs, timeout=self._timeout * len(ports)):
                with contextlib.suppress(Exception):
                    f.result()

        results.sort(key=lambda e: e.port)
        return results

    def _tcp_connect(self, ip: str, port: int) -> str:
        """Try a full TCP connection. Returns 'open', 'closed', or 'filtered'."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect((ip, port))
            sock.close()
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except (TimeoutError, OSError):
            return "filtered"
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    # -- SYN scan --

    def _syn_scan(self, ip: str, ports: list[int]) -> list[PortEntry]:
        """Half-open SYN scan via scapy. Requires root."""
        try:
            from scapy.all import IP, TCP, conf, sr  # type: ignore[import]
        except ImportError:
            logger.warning("Scapy not available for SYN scan, falling back to connect")
            return self._connect_scan(ip, ports)
        conf.verb = 0  # silence scapy globally for this scan

        results: list[PortEntry] = []

        # batch into chunks to avoid flooding
        chunk_size = 50
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i : i + chunk_size]

            try:
                ans, unans = sr(
                    IP(dst=ip) / TCP(dport=chunk, flags="S"),
                    timeout=self._timeout,
                    verbose=False,
                )
            except PermissionError as exc:
                raise PrivilegeError("Root required for SYN scan") from exc
            except OSError as exc:
                logger.error("SYN scan error: %s", exc)
                break

            answered_ports = set()
            for sent, rcv in ans:
                port = sent[TCP].dport
                answered_ports.add(port)

                flags = rcv[TCP].flags
                if flags == 0x12:  # SYN-ACK
                    state = "open"
                elif flags & 0x04:  # RST
                    state = "closed"
                else:
                    state = "filtered"

                svc = _service_name(port) if state == "open" else None
                results.append(
                    PortEntry(
                        port=port,
                        protocol="tcp",
                        state=state,
                        service=svc,
                    )
                )

            # unanswered = filtered
            for port in chunk:
                if port not in answered_ports:
                    results.append(
                        PortEntry(
                            port=port,
                            protocol="tcp",
                            state="filtered",
                        )
                    )

        results.sort(key=lambda e: e.port)
        return results

    # -- Banner grabbing --

    def _banner_grab(self, ip: str, entries: list[PortEntry]) -> None:
        """Try to read banners from open ports."""

        def _grab(entry: PortEntry) -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            try:
                sock.connect((ip, entry.port))
                # some services send a banner immediately
                sock.sendall(b"\r\n")
                data = sock.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()
                    if banner:
                        entry.banner = banner[:256]  # cap length
                        # try to extract version from banner
                        entry.version = self._parse_version(banner)
            except (TimeoutError, OSError, ConnectionRefusedError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    sock.close()

        with ThreadPoolExecutor(max_workers=min(10, len(entries) or 1)) as pool:
            futs = [pool.submit(_grab, e) for e in entries]
            for f in as_completed(futs, timeout=self._timeout * 2):
                with contextlib.suppress(Exception):
                    f.result()

    @staticmethod
    def _parse_version(banner: str) -> str | None:
        """Best-effort version extraction from banner strings."""
        # SSH-2.0-OpenSSH_8.9p1 → OpenSSH 8.9p1
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 3:
                return parts[2].replace("_", " ")

        # 220 mail.example.com ESMTP Postfix → Postfix
        if banner.startswith("220 "):
            tokens = banner.split()
            if len(tokens) >= 4:
                return tokens[-1]

        # Apache/2.4.54 → Apache 2.4.54
        for sep in ("/", " "):
            if sep in banner:
                name, _, ver = banner.partition(sep)
                ver = ver.split()[0] if ver else ""
                if ver and any(c.isdigit() for c in ver):
                    return f"{name} {ver}"

        return None

    # -- Rate limiting --

    def _rate_wait(self) -> None:
        if self._rate_limit <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            min_interval = 1.0 / self._rate_limit
            elapsed = now - self._last_send
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_send = time.monotonic()
