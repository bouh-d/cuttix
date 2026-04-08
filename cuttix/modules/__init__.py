"""Module stubs for when real modules aren't available.

Each NullXxx class implements the matching Protocol interface
but does nothing. This lets the rest of the system run even
if a dependency is missing (e.g. no pypcap installed).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from cuttix.models.alert import Alert
from cuttix.models.host import Host
from cuttix.models.scan_result import PortEntry as PortEntry  # re-export
from cuttix.models.scan_result import ScanResult

logger = logging.getLogger(__name__)

_WARN_TEMPLATE = "%s is not available — install missing dependencies"


class NullScanner:
    """Placeholder when scapy isn't installed."""

    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "Scanner")

    def scan(
        self, network: str | None = None, timeout: float = 2.0, retries: int = 2
    ) -> list[Host]:
        return []

    def get_known_hosts(self) -> dict[str, Host]:
        return {}

    @property
    def interface(self) -> str:
        return "none"


class NullARPControl:
    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "ARP Control")

    def cut_access(self, target_ip: str, auto_restore_minutes: int = 0) -> None:
        raise RuntimeError("ARP Control not available")

    def restore_access(self, target_ip: str) -> None:
        pass

    def restore_all(self) -> None:
        pass

    def get_spoofed(self) -> dict[str, Any]:
        return {}

    def is_spoofed(self, target_ip: str) -> bool:
        return False


class NullPortScanner:
    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "Port Scanner")

    def scan_host(
        self, target_ip: str, ports: list[int] | None = None, technique: str = "connect"
    ) -> ScanResult:
        return ScanResult(target_ip=target_ip)

    def scan_top_ports(self, target_ip: str, top_n: int = 100) -> ScanResult:
        return ScanResult(target_ip=target_ip)


class NullPacketCapture:
    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "Packet Capture")

    def start(self, bpf_filter: str = "", callback: Callable | None = None) -> None:
        raise RuntimeError("Packet Capture not available — install pypcap or tshark")

    def stop(self) -> None:
        pass

    def is_running(self) -> bool:
        return False

    def get_stats(self) -> dict[str, int]:
        return {}


class NullIDS:
    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "IDS")

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def get_alerts(self, since: float | None = None) -> list[Alert]:
        return []

    def get_whitelist(self) -> set[str]:
        return set()

    def add_to_whitelist(self, mac: str) -> None:
        pass


class NullReportGenerator:
    def __init__(self) -> None:
        logger.warning(_WARN_TEMPLATE, "Report Generator")

    def generate(self, fmt: str = "json", output_path: str | None = None) -> str:
        return "{}"

    def get_supported_formats(self) -> list[str]:
        return []
