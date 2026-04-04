"""Network utility functions — interface detection, CIDR, gateway."""
from __future__ import annotations

import logging
import socket
import struct
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def get_default_interface() -> str | None:
    """Best-effort detection of the active network interface."""
    if sys.platform == "linux":
        return _linux_default_interface()
    elif sys.platform == "darwin":
        return _macos_default_interface()
    elif sys.platform == "win32":
        return _windows_default_interface()
    return None


def _linux_default_interface() -> str | None:
    """Parse /proc/net/route for the default route."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except FileNotFoundError:
        pass

    # fallback: ip route
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        # "default via 192.168.1.1 dev eth0 ..."
        for part in out.split():
            idx = out.split().index("dev")
            return out.split()[idx + 1]
    except Exception:
        pass

    return None


def _macos_default_interface() -> str | None:
    try:
        out = subprocess.check_output(
            ["route", "-n", "get", "default"], text=True, timeout=5
        )
        for line in out.splitlines():
            if "interface:" in line:
                return line.split(":")[-1].strip()
    except Exception:
        pass
    return None


def _windows_default_interface() -> str | None:
    # on windows, scapy picks the right one usually
    # TODO: implement via `Get-NetRoute -DestinationPrefix 0.0.0.0/0` or WMI
    return None


def get_gateway_ip() -> str | None:
    """Get the default gateway IP."""
    if sys.platform == "linux":
        try:
            with open("/proc/net/route") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        # gateway is in parts[2], hex little-endian
                        gw_hex = parts[2]
                        gw_int = struct.unpack("<I", bytes.fromhex(gw_hex))[0]
                        return socket.inet_ntoa(struct.pack("!I", gw_int))
        except FileNotFoundError:
            pass

    # fallback: ip route parsing
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"] if sys.platform != "win32"
            else ["powershell", "-Command",
                  "(Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop"],
            text=True, timeout=5,
        )
        # linux/mac: "default via 192.168.1.1 dev eth0"
        for word in out.split():
            if _looks_like_ip(word):
                return word
    except Exception:
        pass

    return None


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
