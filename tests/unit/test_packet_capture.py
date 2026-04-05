"""Tests for LiveCapture and CaptureStats — backends mocked."""
from __future__ import annotations

import json
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from cuttix.core.event_bus import EventBus, EventType
from cuttix.models.packet import PacketInfo
from cuttix.modules.packet_capture import (
    CaptureStats,
    LiveCapture,
    _tcp_flags,
    _dns_type,
    _cleartext_service,
    _mac_str,
    _ip_str,
)


CAP_MOD = "cuttix.modules.packet_capture"


class TestCaptureStats:
    def test_record_and_snapshot(self):
        stats = CaptureStats()
        stats.started_at = time.time() - 10

        stats.record("TCP", "192.168.1.10")
        stats.record("TCP", "192.168.1.10")
        stats.record("UDP", "192.168.1.20")
        stats.record("DNS", "192.168.1.10")

        snap = stats.snapshot()
        assert snap["total_packets"] == 4
        assert snap["by_protocol"]["TCP"] == 2
        assert snap["by_protocol"]["UDP"] == 1
        assert snap["by_protocol"]["DNS"] == 1
        assert "192.168.1.10" in snap["top_talkers"]
        assert snap["top_talkers"]["192.168.1.10"] == 3
        assert snap["elapsed_seconds"] >= 9
        assert snap["pps"] > 0

    def test_reset(self):
        stats = CaptureStats()
        stats.started_at = time.time()
        stats.record("TCP", "1.2.3.4")

        stats.reset()
        snap = stats.snapshot()
        assert snap["total_packets"] == 0
        assert snap["by_protocol"] == {}

    def test_empty_snapshot(self):
        stats = CaptureStats()
        snap = stats.snapshot()
        assert snap["total_packets"] == 0
        assert snap["pps"] == 0


class TestHelpers:
    def test_mac_str(self):
        raw = b"\xaa\xbb\xcc\xdd\xee\xff"
        assert _mac_str(raw) == "aa:bb:cc:dd:ee:ff"

    def test_ip_str(self):
        raw = b"\xc0\xa8\x01\x01"
        assert _ip_str(raw) == "192.168.1.1"

    def test_tcp_flags_syn(self):
        assert "SYN" in _tcp_flags(0x02)

    def test_tcp_flags_syn_ack(self):
        result = _tcp_flags(0x12)
        assert "SYN" in result
        assert "ACK" in result

    def test_tcp_flags_rst(self):
        assert "RST" in _tcp_flags(0x04)

    def test_tcp_flags_fin(self):
        assert "FIN" in _tcp_flags(0x01)

    def test_dns_type_a(self):
        assert _dns_type(1) == "A"

    def test_dns_type_aaaa(self):
        assert _dns_type(28) == "AAAA"

    def test_dns_type_unknown(self):
        assert _dns_type(999) == "999"

    def test_cleartext_service_ftp(self):
        assert _cleartext_service(21) == "FTP"

    def test_cleartext_service_http(self):
        assert _cleartext_service(80) == "HTTP"

    def test_cleartext_service_telnet(self):
        assert _cleartext_service(23) == "Telnet"


class TestLiveCaptureInit:
    def test_initial_state(self):
        cap = LiveCapture("eth0")
        assert not cap.is_running()
        assert cap.backend == "none"
        stats = cap.get_stats()
        assert stats["total_packets"] == 0

    def test_stop_when_not_running(self):
        cap = LiveCapture("eth0")
        cap.stop()  # should not raise


class TestLiveCaptureNoBackend:
    def test_raises_without_backend(self):
        """If neither pypcap nor tshark is available, start() should raise."""
        cap = LiveCapture("eth0")

        with (
            patch.object(cap, "_try_pypcap", return_value=False),
            patch.object(cap, "_try_tshark", return_value=False),
        ):
            with pytest.raises(RuntimeError, match="No capture backend"):
                cap.start()

        assert not cap.is_running()


class TestHandlePacket:
    def _make_pkt(self, **overrides) -> PacketInfo:
        defaults = dict(
            timestamp=datetime.now(),
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            src_mac="aa:bb:cc:00:00:0a",
            dst_mac="aa:bb:cc:00:00:01",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            length=100,
            info=":54321 → :80 [SYN]",
        )
        defaults.update(overrides)
        return PacketInfo(**defaults)

    def test_stats_updated(self):
        cap = LiveCapture("eth0")
        pkt = self._make_pkt()
        cap._handle_packet(pkt)

        snap = cap.stats.snapshot()
        assert snap["total_packets"] == 1
        assert snap["by_protocol"]["TCP"] == 1

    def test_callback_called(self):
        cap = LiveCapture("eth0")
        received = []
        cap._callback = lambda p: received.append(p)

        pkt = self._make_pkt()
        cap._handle_packet(pkt)
        assert len(received) == 1

    def test_callback_exception_doesnt_crash(self):
        cap = LiveCapture("eth0")
        cap._callback = lambda p: 1 / 0  # crash

        pkt = self._make_pkt()
        cap._handle_packet(pkt)  # should not raise
        assert cap.stats.snapshot()["total_packets"] == 1

    def test_cleartext_event(self, event_bus):
        cap = LiveCapture("eth0", event_bus=event_bus)
        events = []
        event_bus.subscribe(EventType.CLEARTEXT_DETECTED, lambda e: events.append(e), "test")

        pkt = self._make_pkt(dst_port=21, protocol="TCP")
        cap._handle_packet(pkt)

        assert len(events) == 1
        assert events[0].data["service"] == "FTP"
        assert events[0].data["port"] == 21

    def test_dns_event(self, event_bus):
        cap = LiveCapture("eth0", event_bus=event_bus)
        events = []
        event_bus.subscribe(EventType.DNS_QUERY, lambda e: events.append(e), "test")

        pkt = self._make_pkt(
            protocol="DNS",
            dst_port=53,
            info="DNS A example.com",
        )
        cap._handle_packet(pkt)

        assert len(events) == 1
        assert events[0].data["query"] == "DNS A example.com"

    def test_no_event_for_non_cleartext_tcp(self, event_bus):
        cap = LiveCapture("eth0", event_bus=event_bus)
        events = []
        event_bus.subscribe(EventType.CLEARTEXT_DETECTED, lambda e: events.append(e), "test")

        # port 443 is NOT cleartext
        pkt = self._make_pkt(dst_port=443, protocol="TCP")
        cap._handle_packet(pkt)
        assert len(events) == 0


class TestTsharkJsonParsing:
    def test_parse_tcp_packet(self):
        cap = LiveCapture("eth0")
        line = json.dumps({
            "layers": {
                "frame": {
                    "frame_frame_time_epoch": "1700000000.123",
                    "frame_frame_len": "100",
                    "frame_frame_protocols": "eth:ip:tcp",
                },
                "ip": {
                    "ip_ip_src": "10.0.0.1",
                    "ip_ip_dst": "10.0.0.2",
                },
                "tcp": {
                    "tcp_tcp_srcport": "54321",
                    "tcp_tcp_dstport": "80",
                },
            }
        })

        pkt = cap._parse_tshark_json(line)
        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "10.0.0.2"
        assert pkt.src_port == 54321
        assert pkt.dst_port == 80
        assert pkt.protocol == "TCP"

    def test_parse_dns_packet(self):
        cap = LiveCapture("eth0")
        line = json.dumps({
            "layers": {
                "frame": {
                    "frame_frame_time_epoch": "1700000000",
                    "frame_frame_len": "80",
                    "frame_frame_protocols": "eth:ip:udp:dns",
                },
                "ip": {"ip_ip_src": "10.0.0.1", "ip_ip_dst": "8.8.8.8"},
                "udp": {"udp_udp_srcport": "12345", "udp_udp_dstport": "53"},
                "dns": {},
            }
        })

        pkt = cap._parse_tshark_json(line)
        assert pkt is not None
        assert pkt.protocol == "DNS"

    def test_parse_empty_layers(self):
        cap = LiveCapture("eth0")
        pkt = cap._parse_tshark_json('{"layers": {}}')
        assert pkt is None

    def test_parse_invalid_json(self):
        cap = LiveCapture("eth0")
        pkt = cap._parse_tshark_json("not json at all")
        assert pkt is None

    def test_parse_no_layers_key(self):
        cap = LiveCapture("eth0")
        pkt = cap._parse_tshark_json('{"something": "else"}')
        assert pkt is None
