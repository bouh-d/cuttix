"""Integration: scanner finds hosts → ARP controller cuts one.

All network I/O is mocked; we're testing the module wiring and
event flow between scanner, event bus, and ARP controller.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cuttix.core.audit_log import AuditLog
from cuttix.core.event_bus import EventBus, Event, EventType
from cuttix.modules.arp_state import ARPStateFile


SCANNER_MOD = "cuttix.modules.scanner"
CTRL_MOD = "cuttix.modules.arp_control"


def _fake_srp(pkt, **kw):
    class R:
        def __init__(self, ip, mac):
            self.psrc = ip
            self.hwsrc = mac

    return [
        (None, R("192.168.1.1", "aa:bb:cc:00:00:01")),
        (None, R("192.168.1.50", "aa:bb:cc:00:00:50")),
    ], []


@pytest.fixture
def patched_env(tmp_path):
    """Patch both scanner and controller scapy calls."""
    mac_map = {
        "192.168.1.1": "aa:bb:cc:00:00:01",
        "192.168.1.50": "aa:bb:cc:00:00:50",
        "192.168.1.100": "00:11:22:33:44:55",
    }
    with (
        # scanner patches
        patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp),
        patch(f"{SCANNER_MOD}.get_if_list", return_value=["eth0", "lo"]),
        patch(f"{SCANNER_MOD}.get_if_addr", return_value="192.168.1.100"),
        patch(f"{SCANNER_MOD}.get_default_interface", return_value="eth0"),
        patch(f"{SCANNER_MOD}.get_gateway_ip", return_value="192.168.1.1"),
        patch(f"{SCANNER_MOD}.mac_vendor") as mv,
        patch("socket.gethostbyaddr", side_effect=OSError),
        # controller patches
        patch(f"{CTRL_MOD}.send"),
        patch(f"{CTRL_MOD}.getmacbyip", side_effect=lambda ip: mac_map.get(ip)),
        patch(f"{CTRL_MOD}.get_if_hwaddr", return_value="00:11:22:33:44:55"),
        patch(f"{CTRL_MOD}.get_if_addr", return_value="192.168.1.100"),
        patch(f"{CTRL_MOD}.get_gateway_ip", return_value="192.168.1.1"),
    ):
        mv.lookup = MagicMock(return_value=None)
        yield {
            "state_dir": tmp_path / "state",
            "audit_dir": tmp_path / "audit",
        }


def test_scan_then_cut_flow(patched_env, event_bus):
    """Full flow: scan → discover hosts → cut one → verify events."""
    from cuttix.modules.scanner import NetworkScanner
    from cuttix.modules.arp_control import ARPController

    state = ARPStateFile(
        state_dir=patched_env["state_dir"],
        secret=b"integration-test-secret-32bytes!",
    )
    audit = AuditLog(log_dir=patched_env["audit_dir"])

    # track events
    discovered = []
    cut_events = []
    restored = []
    event_bus.subscribe(EventType.HOST_DISCOVERED, lambda e: discovered.append(e), "tracker")
    event_bus.subscribe(EventType.HOST_CUT, lambda e: cut_events.append(e), "tracker")
    event_bus.subscribe(EventType.HOST_RESTORED, lambda e: restored.append(e), "tracker")

    # 1) scan
    scanner = NetworkScanner(interface="eth0", event_bus=event_bus)
    hosts = scanner.scan(network="192.168.1.0/24")
    assert len(hosts) == 2
    assert len(discovered) == 2

    # 2) cut one host
    ctl = ARPController(
        interface="eth0",
        event_bus=event_bus,
        audit_log=audit,
        state_file=state,
    )
    ctl.cut_access("192.168.1.50")
    assert len(cut_events) == 1
    assert ctl.is_spoofed("192.168.1.50")

    # 3) verify scanner excludes spoofed from HOST_LOST
    lost = []
    event_bus.subscribe(EventType.HOST_LOST, lambda e: lost.append(e), "tracker2")

    scanner_with_ctl = NetworkScanner(
        interface="eth0",
        event_bus=event_bus,
        arp_control=ctl,
    )
    # first scan to populate known_hosts
    scanner_with_ctl.scan(network="192.168.1.0/24")

    # empty scan — spoofed host excluded from lost
    with patch(f"{SCANNER_MOD}.srp", return_value=([], [])):
        scanner_with_ctl.scan(network="192.168.1.0/24")

    lost_ips = [e.data.ip for e in lost]
    assert "192.168.1.50" not in lost_ips

    # 4) restore
    ctl.restore_access("192.168.1.50")
    assert len(restored) == 1
    assert not ctl.is_spoofed("192.168.1.50")


def test_audit_trail_integrity(patched_env, event_bus):
    """Verify the audit log chain after a cut+restore cycle."""
    from cuttix.modules.arp_control import ARPController

    state = ARPStateFile(
        state_dir=patched_env["state_dir"],
        secret=b"integration-test-secret-32bytes!",
    )
    audit = AuditLog(log_dir=patched_env["audit_dir"])

    ctl = ARPController(
        interface="eth0",
        event_bus=event_bus,
        audit_log=audit,
        state_file=state,
    )

    ctl.cut_access("192.168.1.50")
    ctl.restore_access("192.168.1.50")

    # verify HMAC chain
    valid, count = audit.verify_integrity()
    assert valid
    assert count == 2  # CUT + RESTORE
