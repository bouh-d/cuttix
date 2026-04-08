from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any


class AlertType(Enum):
    ARP_SPOOF = auto()
    ROGUE_DHCP = auto()
    NEW_DEVICE = auto()
    PORT_SCAN = auto()
    MAC_FLOODING = auto()
    DNS_SPOOFING = auto()
    ARP_CONFLICT = auto()
    CLEARTEXT_CREDS = auto()


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    alert_type: AlertType
    severity: AlertSeverity
    description: str
    source_ip: str | None = None
    source_mac: str | None = None
    target_ip: str | None = None
    target_mac: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False
    false_positive: bool = False
    correlation_id: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
