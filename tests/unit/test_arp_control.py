"""Tests for ARPController — all scapy calls mocked."""
from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch, call

import pytest

from cuttix.core.audit_log import AuditLog
from cuttix.core.event_bus import EventBus, Event, EventType
from cuttix.core.exceptions import (
    AlreadySpoofedError,
    HostNotFoundError,
    NotSpoofedError,
    SecurityError,
)
from cuttix.modules.arp_state import ARPStateFile, SpoofEntry


CTRL_MOD = "cuttix.modules.arp_control"


@pytest.fixture
def mock_scapy():
    """Patch all scapy functions used by ARPController."""
    with (
        patch(f"{CTRL_MOD}.send") as mock_send,
        patch(f"{CTRL_MOD}.getmacbyip") as mock_getmac,
        patch(f"{CTRL_MOD}.get_if_hwaddr", return_value="00:11:22:33:44:55"),
        patch(f"{CTRL_MOD}.get_if_addr", return_value="192.168.1.100"),
        patch(f"{CTRL_MOD}.get_gateway_ip", return_value="192.168.1.1"),
    ):
        mock_getmac.side_effect = lambda ip: {
            "192.168.1.1": "aa:bb:cc:00:00:01",
            "192.168.1.50": "aa:bb:cc:00:00:50",
            "192.168.1.51": "aa:bb:cc:00:00:51",
            "192.168.1.100": "00:11:22:33:44:55",
        }.get(ip)

        yield {"send": mock_send, "getmacbyip": mock_getmac}


@pytest.fixture
def state_file(tmp_path):
    return ARPStateFile(state_dir=tmp_path, secret=b"test-secret-32-bytes-exactly!!!!!")


@pytest.fixture
def audit_log(tmp_path):
    return AuditLog(log_dir=tmp_path)


@pytest.fixture
def make_controller(mock_scapy, state_file, audit_log, event_bus):
    """Factory to create ARPController with all deps mocked."""
    from cuttix.modules.arp_control import ARPController

    def _make(**kwargs):
        defaults = dict(
            interface="eth0",
            event_bus=event_bus,
            audit_log=audit_log,
            state_file=state_file,
        )
        defaults.update(kwargs)
        return ARPController(**defaults)

    return _make


class TestCutAccess:
    def test_cut_basic(self, make_controller, mock_scapy):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        assert ctl.is_spoofed("192.168.1.50")
        spoofed = ctl.get_spoofed()
        assert "192.168.1.50" in spoofed

    def test_cut_sends_arp_packets(self, make_controller, mock_scapy):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        # give the spoof thread a moment to send at least one packet
        import time
        time.sleep(1.5)

        assert mock_scapy["send"].call_count >= 1

        # cleanup
        ctl.restore_access("192.168.1.50")

    def test_cut_publishes_event(self, make_controller, event_bus):
        cuts = []
        event_bus.subscribe(EventType.HOST_CUT, lambda e: cuts.append(e), "test")

        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        assert len(cuts) == 1
        assert cuts[0].data["target_ip"] == "192.168.1.50"

        ctl.restore_access("192.168.1.50")

    def test_cut_logs_audit(self, make_controller, audit_log):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        # check audit file has an entry
        assert audit_log.log_path.exists()
        content = audit_log.log_path.read_text()
        assert "CUT" in content
        assert "192.168.1.50" in content

        ctl.restore_access("192.168.1.50")

    def test_cut_persists_state(self, make_controller, state_file):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        entries = state_file.load()
        assert entries is not None
        assert len(entries) == 1
        assert entries[0].target_ip == "192.168.1.50"

        ctl.restore_access("192.168.1.50")


class TestCutSafety:
    def test_cant_cut_self(self, make_controller):
        ctl = make_controller()
        with pytest.raises(SecurityError, match="yourself"):
            ctl.cut_access("192.168.1.100")

    def test_cant_cut_gateway(self, make_controller):
        ctl = make_controller()
        with pytest.raises(SecurityError, match="gateway"):
            ctl.cut_access("192.168.1.1")

    def test_cant_double_cut(self, make_controller):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        with pytest.raises(AlreadySpoofedError):
            ctl.cut_access("192.168.1.50")

        ctl.restore_access("192.168.1.50")

    def test_cant_cut_unknown_host(self, make_controller, mock_scapy):
        mock_scapy["getmacbyip"].side_effect = lambda ip: None
        ctl = make_controller()

        with pytest.raises(HostNotFoundError):
            ctl.cut_access("192.168.1.99")


class TestRestoreAccess:
    def test_restore_basic(self, make_controller, mock_scapy):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")
        ctl.restore_access("192.168.1.50")

        assert not ctl.is_spoofed("192.168.1.50")

    def test_restore_sends_legit_arp(self, make_controller, mock_scapy):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        send_count_before = mock_scapy["send"].call_count
        ctl.restore_access("192.168.1.50")

        # restore sends 5 rounds × 2 packets = 10
        restore_calls = mock_scapy["send"].call_count - send_count_before
        assert restore_calls >= 10

    def test_restore_publishes_event(self, make_controller, event_bus):
        restores = []
        event_bus.subscribe(EventType.HOST_RESTORED, lambda e: restores.append(e), "test")

        ctl = make_controller()
        ctl.cut_access("192.168.1.50")
        ctl.restore_access("192.168.1.50")

        assert len(restores) == 1
        assert restores[0].data["target_ip"] == "192.168.1.50"

    def test_restore_clears_state_file(self, make_controller, state_file):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")
        ctl.restore_access("192.168.1.50")

        assert not state_file.exists()

    def test_restore_not_spoofed_raises(self, make_controller):
        ctl = make_controller()
        with pytest.raises(NotSpoofedError):
            ctl.restore_access("192.168.1.50")

    def test_restore_logs_audit(self, make_controller, audit_log):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")
        ctl.restore_access("192.168.1.50")

        content = audit_log.log_path.read_text()
        assert "RESTORE" in content


class TestRestoreAll:
    def test_restore_all(self, make_controller):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")
        ctl.cut_access("192.168.1.51")

        assert len(ctl.get_spoofed()) == 2

        ctl.restore_all()
        assert len(ctl.get_spoofed()) == 0

    def test_restore_all_empty(self, make_controller):
        ctl = make_controller()
        ctl.restore_all()  # should not raise


class TestOrphanRecovery:
    def test_recovers_orphaned_state(self, mock_scapy, state_file, audit_log, event_bus):
        """Simulate a crash: save state, create new controller, verify recovery."""
        from cuttix.modules.arp_state import SpoofEntry

        state_file.save([
            SpoofEntry(
                target_ip="192.168.1.50",
                target_mac="aa:bb:cc:00:00:50",
                gateway_ip="192.168.1.1",
                gateway_mac="aa:bb:cc:00:00:01",
                started_at="2025-01-01T12:00:00",
            )
        ])

        from cuttix.modules.arp_control import ARPController
        ctl = ARPController(
            interface="eth0",
            event_bus=event_bus,
            audit_log=audit_log,
            state_file=state_file,
        )

        # state file should be cleaned up after recovery
        assert not state_file.exists()

        # audit log should have ORPHAN_RESTORE
        content = audit_log.log_path.read_text()
        assert "ORPHAN_RESTORE" in content

        # restore ARP packets should have been sent
        assert mock_scapy["send"].call_count >= 10  # 10 rounds

    def test_no_crash_no_recovery(self, make_controller, state_file, mock_scapy):
        """Fresh start with no orphaned state."""
        ctl = make_controller()
        assert not state_file.exists()


class TestGetSpoofed:
    def test_get_spoofed_empty(self, make_controller):
        ctl = make_controller()
        assert ctl.get_spoofed() == {}

    def test_get_spoofed_after_cut(self, make_controller):
        ctl = make_controller()
        ctl.cut_access("192.168.1.50")

        spoofed = ctl.get_spoofed()
        assert "192.168.1.50" in spoofed
        assert spoofed["192.168.1.50"]["target_mac"] == "aa:bb:cc:00:00:50"

        ctl.restore_access("192.168.1.50")

    def test_is_spoofed(self, make_controller):
        ctl = make_controller()
        assert not ctl.is_spoofed("192.168.1.50")

        ctl.cut_access("192.168.1.50")
        assert ctl.is_spoofed("192.168.1.50")

        ctl.restore_access("192.168.1.50")
        assert not ctl.is_spoofed("192.168.1.50")
