"""Tests for NetworkScanner — scapy calls are mocked out."""
from __future__ import annotations

import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from cuttix.core.event_bus import EventBus, Event, EventType
from cuttix.core.exceptions import (
    InterfaceError,
    InvalidNetworkError,
    PrivilegeError,
    SecurityError,
)
from cuttix.models.host import Host, HostStatus


# We need to mock scapy imports before importing the scanner module.
# Patch at the module level where scapy symbols are used.

SCAPY_PATCH_BASE = "cuttix.modules.scanner"


def _fake_srp(pkt, timeout=2, iface="eth0", verbose=False, retry=0):
    """Return a fake answered list with 3 hosts."""

    class FakeReply:
        def __init__(self, ip, mac):
            self.psrc = ip
            self.hwsrc = mac

    ans = [
        (None, FakeReply("192.168.1.1", "aa:bb:cc:dd:ee:01")),
        (None, FakeReply("192.168.1.10", "aa:bb:cc:dd:ee:0a")),
        (None, FakeReply("192.168.1.20", "aa:bb:cc:dd:ee:14")),
    ]
    return ans, []


@pytest.fixture
def scanner_patches():
    """Patch all scapy/network calls so we can test logic without root."""
    with (
        patch(f"{SCAPY_PATCH_BASE}.srp", side_effect=_fake_srp),
        patch(f"{SCAPY_PATCH_BASE}.get_if_list", return_value=["eth0", "lo"]),
        patch(f"{SCAPY_PATCH_BASE}.get_if_addr", return_value="192.168.1.100"),
        patch(f"{SCAPY_PATCH_BASE}.get_default_interface", return_value="eth0"),
        patch(f"{SCAPY_PATCH_BASE}.get_gateway_ip", return_value="192.168.1.1"),
        patch(f"{SCAPY_PATCH_BASE}.mac_vendor") as mock_vendor,
        patch("socket.gethostbyaddr", side_effect=OSError("no rdns")),
    ):
        mock_vendor.lookup = MagicMock(return_value=None)
        yield mock_vendor


@pytest.fixture
def make_scanner(scanner_patches):
    """Factory that imports and creates a scanner with all patches active."""
    from cuttix.modules.scanner import NetworkScanner
    return NetworkScanner


class TestScanBasic:
    def test_scan_returns_hosts(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        hosts = scanner.scan(network="192.168.1.0/24")
        assert len(hosts) == 3

    def test_hosts_have_correct_ips(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        hosts = scanner.scan(network="192.168.1.0/24")
        ips = {h.ip for h in hosts}
        assert "192.168.1.1" in ips
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips

    def test_hosts_are_active(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        hosts = scanner.scan(network="192.168.1.0/24")
        for h in hosts:
            assert h.status == HostStatus.ACTIVE

    def test_gateway_flagged(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        hosts = scanner.scan(network="192.168.1.0/24")
        gateways = [h for h in hosts if h.is_gateway]
        assert len(gateways) == 1
        assert gateways[0].ip == "192.168.1.1"

    def test_macs_lowercased(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        hosts = scanner.scan(network="192.168.1.0/24")
        for h in hosts:
            assert h.mac == h.mac.lower()

    def test_vendor_lookup_called(self, make_scanner, scanner_patches, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")
        assert scanner_patches.lookup.call_count >= 3


class TestScanValidation:
    def test_bad_interface(self, scanner_patches):
        from cuttix.modules.scanner import NetworkScanner
        with pytest.raises(InterfaceError):
            NetworkScanner(interface="doesnt_exist")

    def test_bad_cidr(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        with pytest.raises(InvalidNetworkError):
            scanner.scan(network="not-a-cidr")

    def test_cidr_too_wide(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        with pytest.raises(SecurityError, match="too wide"):
            scanner.scan(network="10.0.0.0/8")


class TestScanEvents:
    def test_host_discovered_on_first_scan(self, make_scanner, event_bus):
        discovered = []
        event_bus.subscribe(
            EventType.HOST_DISCOVERED,
            lambda e: discovered.append(e),
            "test_sub",
        )

        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")

        assert len(discovered) == 3

    def test_no_duplicate_events_on_rescan(self, make_scanner, event_bus):
        discovered = []
        event_bus.subscribe(
            EventType.HOST_DISCOVERED,
            lambda e: discovered.append(e),
            "test_sub",
        )

        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")
        first_count = len(discovered)

        # second scan — same hosts, no new events
        scanner.scan(network="192.168.1.0/24")
        assert len(discovered) == first_count

    def test_host_lost_event(self, make_scanner, event_bus):
        lost = []
        event_bus.subscribe(
            EventType.HOST_LOST,
            lambda e: lost.append(e),
            "test_sub",
        )

        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")

        # now simulate an empty scan
        with patch(f"{SCAPY_PATCH_BASE}.srp", return_value=([], [])):
            scanner.scan(network="192.168.1.0/24")

        assert len(lost) == 3

    def test_spoofed_hosts_excluded_from_lost(self, make_scanner, event_bus):
        """Hosts we're spoofing shouldn't trigger HOST_LOST."""
        lost = []
        event_bus.subscribe(
            EventType.HOST_LOST,
            lambda e: lost.append(e),
            "test_sub",
        )

        mock_arp_ctl = MagicMock()
        mock_arp_ctl.get_spoofed.return_value = {"192.168.1.10": {}}

        scanner = make_scanner(
            interface="eth0", event_bus=event_bus, arp_control=mock_arp_ctl
        )
        scanner.scan(network="192.168.1.0/24")

        # empty scan — but 192.168.1.10 is spoofed so shouldn't appear in lost
        with patch(f"{SCAPY_PATCH_BASE}.srp", return_value=([], [])):
            scanner.scan(network="192.168.1.0/24")

        lost_ips = [e.data.ip for e in lost]
        assert "192.168.1.10" not in lost_ips
        assert len(lost) == 2  # .1 and .20 lost, .10 excluded

    def test_scan_cycle_complete_event(self, make_scanner, event_bus):
        cycles = []
        event_bus.subscribe(
            EventType.SCAN_CYCLE_COMPLETE,
            lambda e: cycles.append(e),
            "test_sub",
        )

        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")
        assert len(cycles) == 1
        assert cycles[0].data["count"] == 3


class TestKnownHosts:
    def test_get_known_hosts_empty_before_scan(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        assert scanner.get_known_hosts() == {}

    def test_get_known_hosts_after_scan(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        scanner.scan(network="192.168.1.0/24")
        hosts = scanner.get_known_hosts()
        assert len(hosts) == 3

    def test_interface_property(self, make_scanner, event_bus):
        scanner = make_scanner(interface="eth0", event_bus=event_bus)
        assert scanner.interface == "eth0"
