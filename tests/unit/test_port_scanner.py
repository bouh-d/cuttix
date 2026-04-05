"""Tests for TCPPortScanner — socket calls mocked."""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch, call

import pytest

from cuttix.core.event_bus import EventBus, Event, EventType
from cuttix.models.scan_result import PortEntry, ScanResult
from cuttix.modules.port_scanner import (
    TCPPortScanner,
    _load_top_ports,
    _service_name,
    get_profile_ports,
)


PORT_MOD = "cuttix.modules.port_scanner"


@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear module-level cache between tests."""
    import cuttix.modules.port_scanner as mod
    mod._top_ports_cache = None
    yield
    mod._top_ports_cache = None


# -- helper to mock socket.connect --

def _mock_connect(open_ports: set[int]):
    """Return a side_effect for socket.connect that opens specific ports."""
    def connect(addr):
        _, port = addr
        if port in open_ports:
            return  # success
        raise ConnectionRefusedError("refused")
    return connect


@pytest.fixture
def mock_socket():
    """Patch socket.socket for connect scan tests."""
    mock_sock = MagicMock()
    mock_sock.settimeout = MagicMock()
    mock_sock.close = MagicMock()

    with patch(f"{PORT_MOD}.socket.socket", return_value=mock_sock) as factory:
        yield mock_sock


class TestTopPortsAsset:
    def test_load_top_ports(self):
        data = _load_top_ports()
        assert "top_100" in data
        assert "services" in data
        assert "profiles" in data
        assert len(data["top_100"]) == 100

    def test_service_name_known(self):
        assert _service_name(80) == "http"
        assert _service_name(443) == "https"
        assert _service_name(22) == "ssh"

    def test_service_name_unknown(self):
        assert _service_name(99999) is None

    def test_profile_web(self):
        ports = get_profile_ports("web")
        assert ports is not None
        assert 80 in ports
        assert 443 in ports

    def test_profile_database(self):
        ports = get_profile_ports("database")
        assert ports is not None
        assert 3306 in ports
        assert 5432 in ports

    def test_profile_unknown(self):
        assert get_profile_ports("nonexistent") is None


class TestConnectScan:
    def test_scan_finds_open_ports(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({80, 443}))

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_host("192.168.1.10", ports=[22, 80, 443, 8080])

        open_ports = {p.port for p in result.open_ports}
        assert open_ports == {80, 443}

    def test_scan_closed_ports(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=ConnectionRefusedError)

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_host("192.168.1.10", ports=[80])

        assert len(result.open_ports) == 0
        assert result.ports[0].state == "closed"

    def test_scan_filtered_ports(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=socket.timeout("timed out"))

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_host("192.168.1.10", ports=[80])

        assert result.ports[0].state == "filtered"

    def test_scan_result_sorted(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({22, 80, 443}))

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_host("192.168.1.10", ports=[443, 22, 80])

        port_nums = [p.port for p in result.ports]
        assert port_nums == sorted(port_nums)

    def test_service_names_assigned(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({80, 22}))

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_host("192.168.1.10", ports=[22, 80])

        services = {p.port: p.service for p in result.open_ports}
        assert services[80] == "http"
        assert services[22] == "ssh"

    def test_scan_top_ports(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({80}))

        scanner = TCPPortScanner(timeout=0.1)
        result = scanner.scan_top_ports("192.168.1.10", top_n=10)

        # should have scanned 10 ports
        assert len(result.ports) == 10
        assert result.target_ip == "192.168.1.10"


class TestScanEvents:
    def test_ports_scanned_event(self, mock_socket, event_bus):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({80}))

        events = []
        event_bus.subscribe(EventType.PORTS_SCANNED, lambda e: events.append(e), "test")

        scanner = TCPPortScanner(event_bus=event_bus, timeout=0.1)
        scanner.scan_host("192.168.1.10", ports=[22, 80])

        assert len(events) == 1
        assert events[0].data["target_ip"] == "192.168.1.10"
        assert events[0].data["open"] == 1
        assert events[0].data["total"] == 2

    def test_service_found_event(self, mock_socket, event_bus):
        mock_socket.connect = MagicMock(side_effect=_mock_connect({80, 443}))

        svc_events = []
        event_bus.subscribe(EventType.SERVICE_FOUND, lambda e: svc_events.append(e), "test")

        scanner = TCPPortScanner(event_bus=event_bus, timeout=0.1)
        scanner.scan_host("192.168.1.10", ports=[80, 443])

        assert len(svc_events) == 2
        services = {e.data["service"] for e in svc_events}
        assert "http" in services
        assert "https" in services


class TestBannerParsing:
    def test_ssh_banner(self):
        scanner = TCPPortScanner()
        ver = scanner._parse_version("SSH-2.0-OpenSSH_8.9p1")
        assert ver == "OpenSSH 8.9p1"

    def test_smtp_banner(self):
        scanner = TCPPortScanner()
        ver = scanner._parse_version("220 mail.example.com ESMTP Postfix")
        assert ver == "Postfix"

    def test_apache_banner(self):
        scanner = TCPPortScanner()
        ver = scanner._parse_version("Apache/2.4.54")
        assert ver == "Apache 2.4.54"

    def test_unknown_banner(self):
        scanner = TCPPortScanner()
        ver = scanner._parse_version("hello")
        assert ver is None

    def test_empty_banner(self):
        scanner = TCPPortScanner()
        ver = scanner._parse_version("")
        assert ver is None


class TestRateLimiting:
    def test_rate_limit_zero_no_delay(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=ConnectionRefusedError)

        scanner = TCPPortScanner(timeout=0.1, rate_limit=0)
        # should not hang
        scanner.scan_host("192.168.1.10", ports=[80, 443])

    def test_rate_limit_nonzero(self, mock_socket):
        mock_socket.connect = MagicMock(side_effect=ConnectionRefusedError)

        import time
        scanner = TCPPortScanner(timeout=0.1, rate_limit=100)
        t0 = time.monotonic()
        scanner.scan_host("192.168.1.10", ports=[80, 443, 8080])
        elapsed = time.monotonic() - t0
        # should complete reasonably quickly even with rate limit
        assert elapsed < 5.0
