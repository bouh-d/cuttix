"""Bandwidth aggregator — sliding-window byte counts from PacketInfo events.

Pure Python so it can be tested without Qt. Bins traffic into 1-second
buckets keyed by either ``"all"`` or by host IP, keeping a fixed-size
ring buffer per series. Widgets pull a snapshot of the recent buckets
and render them however they want.

The aggregator does not subscribe to anything itself; the StateStore
calls :meth:`add_packet` from its ``_on_packet_captured`` handler.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass

from cuttix.models.packet import PacketInfo

WINDOW_SECONDS_DEFAULT = 60


@dataclass
class BandwidthPoint:
    timestamp: int  # unix second
    bytes_in: int  # received by host (dst)
    bytes_out: int  # sent by host (src)

    @property
    def total(self) -> int:
        return self.bytes_in + self.bytes_out


class BandwidthAggregator:
    """Per-host and global bandwidth in 1-second buckets."""

    def __init__(self, window_seconds: int = WINDOW_SECONDS_DEFAULT) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._window = window_seconds
        self._lock = threading.RLock()
        # ip -> deque[BandwidthPoint]; the special key "" holds the global
        # series across all hosts.
        self._series: dict[str, deque[BandwidthPoint]] = defaultdict(
            lambda: deque(maxlen=self._window)
        )

    # -- ingestion --

    def add_packet(self, pkt: PacketInfo, now: float | None = None) -> None:
        """Account a single packet against src and dst IPs."""
        if not isinstance(pkt, PacketInfo):
            return
        size = max(int(pkt.length or 0), 0)
        if size == 0:
            return
        ts = int(now if now is not None else time.time())
        with self._lock:
            # Global series: count each packet once (not once per endpoint).
            # We park the byte count in bytes_out so .total still works.
            self._add_to_series("", ts, 0, size)
            if pkt.src_ip:
                self._add_to_series(pkt.src_ip, ts, 0, size)
            if pkt.dst_ip:
                self._add_to_series(pkt.dst_ip, ts, size, 0)

    def _add_to_series(self, key: str, ts: int, b_in: int, b_out: int) -> None:
        series = self._series[key]
        if series and series[-1].timestamp == ts:
            last = series[-1]
            last.bytes_in += b_in
            last.bytes_out += b_out
            return
        # backfill any missing seconds with zero buckets so the chart
        # has a continuous x-axis even when traffic is bursty.
        if series:
            base = series[-1].timestamp
            gap = ts - base
            for fill in range(1, min(gap, self._window)):
                series.append(BandwidthPoint(base + fill, 0, 0))
        series.append(BandwidthPoint(ts, b_in, b_out))

    # -- queries --

    def known_hosts(self) -> list[str]:
        with self._lock:
            return [k for k in self._series if k]

    def snapshot(self, ip: str | None = None) -> list[BandwidthPoint]:
        """Return a copy of the recent series for ``ip`` (or global)."""
        key = ip or ""
        with self._lock:
            series = self._series.get(key)
            if not series:
                return []
            return list(series)

    def total_bytes(self, ip: str | None = None) -> int:
        return sum(p.total for p in self.snapshot(ip))

    def current_rate(self, ip: str | None = None, now: float | None = None) -> float:
        """Bytes/sec averaged over the last 5 buckets up to ``now``."""
        ts = int(now if now is not None else time.time())
        with self._lock:
            series = list(self._series.get(ip or "", ()))
        if not series:
            return 0.0
        # only count buckets within the last 5 seconds (excluding the
        # current second so partial buckets don't tank the average).
        cutoff = ts - 5
        recent = [p for p in series if cutoff <= p.timestamp < ts]
        if not recent:
            return 0.0
        return sum(p.total for p in recent) / max(len(recent), 1)

    def reset(self, ip: str | None = None) -> None:
        with self._lock:
            if ip is None:
                self._series.clear()
            else:
                self._series.pop(ip, None)
                if not ip:
                    self._series.pop("", None)

    # -- helpers --

    @staticmethod
    def format_rate(bps: float) -> str:
        """Pretty-print a bytes/sec value (B/s, KB/s, MB/s)."""
        if bps < 1024:
            return f"{bps:.0f} B/s"
        if bps < 1024 * 1024:
            return f"{bps / 1024:.1f} KB/s"
        return f"{bps / (1024 * 1024):.2f} MB/s"

    def feed_many(self, packets: Iterable[PacketInfo], now: float | None = None) -> None:
        for p in packets:
            self.add_packet(p, now=now)
