from __future__ import annotations

import ipaddress
import re


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


def is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def normalize_mac(mac: str) -> str:
    """aa:bb:cc:dd:ee:ff — lowercase, colon-separated."""
    return mac.lower().replace("-", ":")


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def parse_port_range(spec: str) -> list[int]:
    """Parse '80,443,8000-8100' into a list of port numbers."""
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if not (is_valid_port(lo_i) and is_valid_port(hi_i) and lo_i <= hi_i):
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(lo_i, hi_i + 1))
        else:
            p = int(part)
            if not is_valid_port(p):
                raise ValueError(f"Invalid port: {p}")
            ports.append(p)
    return ports
