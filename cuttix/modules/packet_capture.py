"""Packet capture — pypcap/dpkt primary, tshark fallback.

BPF filtering happens in kernel (pypcap) or in tshark, so we
only see packets that match the filter. Parsing is done with dpkt.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from typing import Any

from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.models.packet import PacketInfo

logger = logging.getLogger(__name__)


class CaptureStats:
    """Thread-safe packet counters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.by_proto: dict[str, int] = defaultdict(int)
        self.by_src: dict[str, int] = defaultdict(int)
        self.started_at: float = 0

    def record(self, proto: str, src: str) -> None:
        with self._lock:
            self.total += 1
            self.by_proto[proto] += 1
            self.by_src[src] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            elapsed = time.time() - self.started_at if self.started_at else 0
            return {
                "total_packets": self.total,
                "by_protocol": dict(self.by_proto),
                "top_talkers": dict(
                    sorted(self.by_src.items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "elapsed_seconds": round(elapsed, 1),
                "pps": round(self.total / elapsed, 1) if elapsed > 0 else 0,
            }

    def reset(self) -> None:
        with self._lock:
            self.total = 0
            self.by_proto.clear()
            self.by_src.clear()
            self.started_at = 0


class LiveCapture:
    """Packet capture with pypcap (primary) or tshark (fallback).

    Usage:
        cap = LiveCapture("eth0", event_bus=bus)
        cap.start(bpf_filter="tcp port 80")
        ...
        cap.stop()
        print(cap.get_stats())
    """

    def __init__(
        self,
        interface: str,
        event_bus: EventBus | None = None,
        max_buffer: int = 10000,
    ) -> None:
        self._iface = interface
        self._bus = event_bus
        self._max_buffer = max_buffer
        self._stats = CaptureStats()
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._callback: Callable[[PacketInfo], None] | None = None
        self._backend: str = "none"

    # -- Protocol methods --

    def start(self, bpf_filter: str = "", callback: Callable | None = None) -> None:
        if self._running:
            logger.warning("Capture already running")
            return

        self._callback = callback
        self._stop_evt.clear()
        self._stats.reset()
        self._stats.started_at = time.time()
        self._running = True

        # try pypcap first, fall back to tshark
        if self._try_pypcap(bpf_filter):
            return

        if self._try_tshark(bpf_filter):
            return

        self._running = False
        raise RuntimeError("No capture backend available — install pypcap or tshark")

    def stop(self) -> None:
        if not self._running:
            return

        self._stop_evt.set()
        self._running = False

        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        logger.info(
            "Capture stopped (%s): %d packets in %.1fs",
            self._backend,
            self._stats.total,
            time.time() - self._stats.started_at,
        )

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, int]:
        snap = self._stats.snapshot()
        return {
            "total_packets": snap["total_packets"],
            "elapsed_seconds": int(snap["elapsed_seconds"]),
            "pps": int(snap["pps"]),
        }

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    @property
    def backend(self) -> str:
        return self._backend

    # -- pypcap backend --

    def _try_pypcap(self, bpf_filter: str) -> bool:
        try:
            import dpkt  # type: ignore[import]  # noqa: F401
            import pcap  # type: ignore[import]  # noqa: F401
        except ImportError:
            logger.debug("pypcap/dpkt not available")
            return False

        self._backend = "pypcap"
        self._thread = threading.Thread(
            target=self._pcap_loop,
            args=(bpf_filter,),
            name="capture-pcap",
            daemon=True,
        )
        self._thread.start()
        logger.info("Capture started (pypcap) on %s filter='%s'", self._iface, bpf_filter)
        return True

    def _pcap_loop(self, bpf_filter: str) -> None:
        import dpkt  # type: ignore[import]
        import pcap  # type: ignore[import]

        sniffer = pcap.pcap(name=self._iface, promisc=True, immediate=True)
        if bpf_filter:
            sniffer.setfilter(bpf_filter)

        for ts, raw in sniffer:
            if self._stop_evt.is_set():
                break

            pkt = self._parse_dpkt(ts, raw, dpkt)
            if pkt:
                self._handle_packet(pkt)

    def _parse_dpkt(self, ts: float, raw: bytes, dpkt_mod: Any) -> PacketInfo | None:
        """Parse raw bytes with dpkt into our PacketInfo."""
        try:
            eth = dpkt_mod.ethernet.Ethernet(raw)
        except Exception:
            return None

        src_mac = _mac_str(eth.src)
        dst_mac = _mac_str(eth.dst)
        proto = "other"
        src_ip = dst_ip = None
        src_port = dst_port = None
        info = ""

        if isinstance(eth.data, dpkt_mod.ip.IP):
            ip = eth.data
            src_ip = _ip_str(ip.src)
            dst_ip = _ip_str(ip.dst)

            if isinstance(ip.data, dpkt_mod.tcp.TCP):
                proto = "TCP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                flags = ip.data.flags
                flag_str = _tcp_flags(flags)
                info = f":{src_port} → :{dst_port} [{flag_str}]"

            elif isinstance(ip.data, dpkt_mod.udp.UDP):
                proto = "UDP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                info = f":{src_port} → :{dst_port}"

                # check for DNS
                if src_port == 53 or dst_port == 53:
                    proto = "DNS"
                    dns_info = self._parse_dns(ip.data.data, dpkt_mod)
                    if dns_info:
                        info = dns_info

            elif isinstance(ip.data, dpkt_mod.icmp.ICMP):
                proto = "ICMP"
                info = f"type={ip.data.type} code={ip.data.code}"

        elif isinstance(eth.data, dpkt_mod.arp.ARP):
            proto = "ARP"
            arp = eth.data
            if arp.op == 1:
                info = f"who-has {_ip_str(arp.tpa)}"
            elif arp.op == 2:
                info = f"{_ip_str(arp.spa)} is-at {_mac_str(arp.sha)}"

        return PacketInfo(
            timestamp=datetime.fromtimestamp(ts),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=len(raw),
            info=info,
            raw=raw[:256],  # keep first 256 bytes
        )

    def _parse_dns(self, data: bytes, dpkt_mod: Any) -> str | None:
        """Extract DNS query domain."""
        try:
            dns = dpkt_mod.dns.DNS(data)
            if dns.qd:
                qname = dns.qd[0].name
                qtype = _dns_type(dns.qd[0].type)
                return f"DNS {qtype} {qname}"
        except Exception:  # noqa: S110 - malformed DNS is common; just skip
            pass
        return None

    # -- tshark backend --

    def _try_tshark(self, bpf_filter: str) -> bool:
        # check if tshark is installed
        try:
            subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("tshark not found")
            return False

        self._backend = "tshark"
        self._thread = threading.Thread(
            target=self._tshark_loop,
            args=(bpf_filter,),
            name="capture-tshark",
            daemon=True,
        )
        self._thread.start()
        logger.info("Capture started (tshark) on %s filter='%s'", self._iface, bpf_filter)
        return True

    def _tshark_loop(self, bpf_filter: str) -> None:
        cmd = [
            "tshark",
            "-i",
            self._iface,
            "-T",
            "ek",  # JSON output
            "-l",  # line-buffered
        ]
        if bpf_filter:
            cmd += ["-f", bpf_filter]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None

        try:
            for line in proc.stdout:
                if self._stop_evt.is_set():
                    break

                line = line.strip()
                if not line or not line.startswith("{"):
                    continue

                pkt = self._parse_tshark_json(line)
                if pkt:
                    self._handle_packet(pkt)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _parse_tshark_json(self, line: str) -> PacketInfo | None:
        """Parse a single tshark EK-JSON line."""
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None

        layers = obj.get("layers", {})
        if not layers:
            return None

        # frame info
        frame = layers.get("frame", {})
        ts_str = frame.get("frame_frame_time_epoch", "0")
        try:
            ts = float(ts_str)
        except (TypeError, ValueError):
            ts = time.time()

        length = int(frame.get("frame_frame_len", 0))

        # IP layer
        ip_layer = layers.get("ip", {})
        src_ip = ip_layer.get("ip_ip_src")
        dst_ip = ip_layer.get("ip_ip_dst")
        proto = frame.get("frame_frame_protocols", "").split(":")[-1].upper()

        # TCP/UDP
        src_port = dst_port = None
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        if tcp:
            src_port = int(tcp.get("tcp_tcp_srcport", 0)) or None
            dst_port = int(tcp.get("tcp_tcp_dstport", 0)) or None
            proto = "TCP"
        elif udp:
            src_port = int(udp.get("udp_udp_srcport", 0)) or None
            dst_port = int(udp.get("udp_udp_dstport", 0)) or None
            proto = "UDP"

        # DNS
        if "dns" in layers:
            proto = "DNS"

        info = ""
        if src_port and dst_port:
            info = f":{src_port} → :{dst_port}"

        return PacketInfo(
            timestamp=datetime.fromtimestamp(ts),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=length,
            info=info,
        )

    # -- common --

    def _handle_packet(self, pkt: PacketInfo) -> None:
        """Process a parsed packet — update stats, fire events, call callback."""
        src = pkt.src_ip or pkt.src_mac or "?"
        self._stats.record(pkt.protocol, src)

        if self._callback:
            try:
                self._callback(pkt)
            except Exception:
                logger.debug("Packet callback error", exc_info=True)

        if not self._bus:
            return

        # DNS query event
        if pkt.protocol == "DNS" and "DNS" in pkt.info:
            self._bus.publish(
                Event(
                    type=EventType.DNS_QUERY,
                    data={
                        "src_ip": pkt.src_ip,
                        "query": pkt.info,
                        "dst_port": pkt.dst_port,
                    },
                    source="capture",
                )
            )

        # cleartext detection
        if pkt.dst_port in (21, 23, 80, 25, 110, 143) and pkt.protocol == "TCP":
            self._bus.publish(
                Event(
                    type=EventType.CLEARTEXT_DETECTED,
                    data={
                        "src_ip": pkt.src_ip,
                        "dst_ip": pkt.dst_ip,
                        "port": pkt.dst_port,
                        "service": _cleartext_service(pkt.dst_port),
                    },
                    source="capture",
                )
            )


# -- helpers --


def _mac_str(raw: bytes) -> str:
    """bytes → aa:bb:cc:dd:ee:ff"""
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    """4 bytes → dotted quad"""
    return ".".join(str(b) for b in raw)


def _tcp_flags(flags: int) -> str:
    names = []
    if flags & 0x02:
        names.append("SYN")
    if flags & 0x10:
        names.append("ACK")
    if flags & 0x01:
        names.append("FIN")
    if flags & 0x04:
        names.append("RST")
    if flags & 0x08:
        names.append("PSH")
    if flags & 0x20:
        names.append("URG")
    return ",".join(names) or str(flags)


def _dns_type(qtype: int) -> str:
    return {
        1: "A",
        2: "NS",
        5: "CNAME",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }.get(qtype, str(qtype))


def _cleartext_service(port: int) -> str:
    return {21: "FTP", 23: "Telnet", 80: "HTTP", 25: "SMTP", 110: "POP3", 143: "IMAP"}.get(
        port, str(port)
    )
