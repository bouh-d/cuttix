"""Tests for the BandwidthAggregator (pure Python, no Qt)."""

from __future__ import annotations

from datetime import datetime

import pytest

from cuttix.gui.bandwidth import BandwidthAggregator
from cuttix.models.packet import PacketInfo


def _pkt(
    length: int, src: str = "10.0.0.1", dst: str = "10.0.0.2", ts: datetime | None = None
) -> PacketInfo:
    return PacketInfo(
        timestamp=ts or datetime.now(),
        src_ip=src,
        dst_ip=dst,
        protocol="TCP",
        length=length,
    )


class TestBasicAggregation:
    def test_zero_length_packet_ignored(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(0), now=1000)
        assert agg.total_bytes() == 0
        assert agg.snapshot() == []

    def test_single_packet_records_in_global_and_endpoints(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(500, src="10.0.0.1", dst="10.0.0.2"), now=1000)

        assert agg.total_bytes() == 500
        assert agg.total_bytes("10.0.0.1") == 500  # outbound
        assert agg.total_bytes("10.0.0.2") == 500  # inbound

    def test_packets_in_same_second_aggregate(self) -> None:
        agg = BandwidthAggregator()
        for _ in range(3):
            agg.add_packet(_pkt(100), now=1000)
        snap = agg.snapshot()
        assert len(snap) == 1
        assert snap[0].total == 300

    def test_packets_across_seconds_create_buckets(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100), now=1000)
        agg.add_packet(_pkt(200), now=1001)
        agg.add_packet(_pkt(300), now=1002)
        snap = agg.snapshot()
        assert [p.total for p in snap] == [100, 200, 300]
        assert [p.timestamp for p in snap] == [1000, 1001, 1002]

    def test_gaps_are_zero_filled(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100), now=1000)
        agg.add_packet(_pkt(100), now=1003)
        snap = agg.snapshot()
        assert [p.timestamp for p in snap] == [1000, 1001, 1002, 1003]
        assert [p.total for p in snap] == [100, 0, 0, 100]

    def test_window_caps_history(self) -> None:
        agg = BandwidthAggregator(window_seconds=5)
        for sec in range(10):
            agg.add_packet(_pkt(100), now=1000 + sec)
        snap = agg.snapshot()
        assert len(snap) == 5
        # most recent 5 seconds: 1005..1009
        assert snap[0].timestamp == 1005
        assert snap[-1].timestamp == 1009


class TestPerHost:
    def test_per_host_separation(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100, src="10.0.0.1", dst="10.0.0.2"), now=1000)
        agg.add_packet(_pkt(200, src="10.0.0.1", dst="10.0.0.3"), now=1000)
        agg.add_packet(_pkt(50, src="10.0.0.4", dst="10.0.0.1"), now=1000)

        assert agg.total_bytes("10.0.0.1") == 100 + 200 + 50
        assert agg.total_bytes("10.0.0.2") == 100
        assert agg.total_bytes("10.0.0.3") == 200
        assert agg.total_bytes("10.0.0.4") == 50

    def test_known_hosts_lists_only_real_keys(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(10, src="10.0.0.1", dst="10.0.0.2"), now=1)
        hosts = set(agg.known_hosts())
        assert hosts == {"10.0.0.1", "10.0.0.2"}
        assert "" not in hosts


class TestRate:
    def test_current_rate_averages_recent_buckets(self) -> None:
        agg = BandwidthAggregator()
        for sec in range(5):
            agg.add_packet(_pkt(1000), now=1000 + sec)
        # current_rate looks at the 5 buckets *before* `now`
        rate = agg.current_rate(now=1005)
        assert rate == pytest.approx(1000.0)

    def test_no_recent_traffic_means_zero_rate(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100), now=1000)
        assert agg.current_rate(now=1100) == 0.0


class TestFormatRate:
    def test_bytes(self) -> None:
        assert BandwidthAggregator.format_rate(0) == "0 B/s"
        assert BandwidthAggregator.format_rate(512) == "512 B/s"

    def test_kilobytes(self) -> None:
        assert BandwidthAggregator.format_rate(2048).endswith("KB/s")

    def test_megabytes(self) -> None:
        assert BandwidthAggregator.format_rate(5 * 1024 * 1024).endswith("MB/s")


class TestReset:
    def test_reset_global_only(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100, src="10.0.0.1", dst="10.0.0.2"), now=1000)
        agg.reset()
        assert agg.snapshot() == []
        assert agg.snapshot("10.0.0.1") == []

    def test_reset_specific_host(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet(_pkt(100, src="10.0.0.1", dst="10.0.0.2"), now=1000)
        agg.reset("10.0.0.1")
        assert agg.snapshot("10.0.0.1") == []
        # global series remains
        assert agg.snapshot() != []


class TestValidation:
    def test_invalid_window(self) -> None:
        with pytest.raises(ValueError):
            BandwidthAggregator(window_seconds=0)

    def test_non_packet_input_ignored(self) -> None:
        agg = BandwidthAggregator()
        agg.add_packet("not a packet", now=1000)  # type: ignore[arg-type]
        assert agg.snapshot() == []
