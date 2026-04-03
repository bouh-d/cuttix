from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PortEntry:
    port: int
    protocol: str = "tcp"  # tcp or udp
    state: str = "open"    # open, closed, filtered
    service: str | None = None
    banner: str | None = None
    version: str | None = None


@dataclass
class ScanResult:
    target_ip: str
    ports: list[PortEntry] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.now)

    @property
    def open_ports(self) -> list[PortEntry]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def open_port_numbers(self) -> list[int]:
        return [p.port for p in self.open_ports]
