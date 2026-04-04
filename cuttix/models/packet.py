from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PacketInfo:
    """Simplified packet representation for display and storage.
    Not a replacement for raw scapy/dpkt packets — just metadata."""

    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "unknown"
    length: int = 0
    info: str = ""  # one-line summary, like wireshark's info column
    raw: bytes = field(default=b"", repr=False)
