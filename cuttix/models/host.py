from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto


class HostStatus(Enum):
    ACTIVE = auto()
    INACTIVE = auto()
    SPOOFED = auto()  # currently being ARP-spoofed by us


@dataclass
class Host:
    ip: str
    mac: str
    vendor: str | None = None
    hostname: str | None = None
    os_guess: str | None = None
    os_confidence: float = 0.0
    status: HostStatus = HostStatus.ACTIVE
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_gateway: bool = False
    notes: str | None = None

    def __post_init__(self) -> None:
        # lowercase for consistent lookup
        self.mac = self.mac.lower()

    @property
    def short_mac(self) -> str:
        """First 3 octets (OUI part)."""
        return ":".join(self.mac.split(":")[:3])

    def __str__(self) -> str:
        name = self.hostname or self.ip
        vendor_str = f" ({self.vendor})" if self.vendor else ""
        return f"{name} [{self.mac}]{vendor_str}"
