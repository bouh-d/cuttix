"""Integration: scanner discovers hosts → IDS raises alerts → report picks them up.

All network I/O is mocked. Verifies the event flow between Scanner,
EventBus, NetworkIDS, Database, and AuditReportGenerator.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cuttix.config import IDSConfig
from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.db.database import Database
from cuttix.models.alert import AlertType
from cuttix.models.host import Host
from cuttix.modules.ids import NetworkIDS
from cuttix.modules.report import AuditReportGenerator
from cuttix.modules.scanner import NetworkScanner


SCANNER_MOD = "cuttix.modules.scanner"


def _fake_srp_run1(pkt, **kw):
    class R:
        def __init__(self, ip, mac):
            self.psrc = ip
            self.hwsrc = mac
    return [
        (None, R("192.168.1.1", "aa:bb:cc:00:00:01")),
        (None, R("192.168.1.50", "aa:bb:cc:00:00:50")),
    ], []


def _fake_srp_run2(pkt, **kw):
    class R:
        def __init__(self, ip, mac):
            self.psrc = ip
            self.hwsrc = mac
    # same IP 192.168.1.50 but different MAC → ARP spoof
    return [
        (None, R("192.168.1.1", "aa:bb:cc:00:00:01")),
        (None, R("192.168.1.50", "de:ad:be:ef:00:01")),
    ], []


@pytest.fixture
def scanner_env():
    patches = [
        patch(f"{SCANNER_MOD}.get_if_list", return_value=["eth0", "lo"]),
        patch(f"{SCANNER_MOD}.get_if_addr", return_value="192.168.1.100"),
        patch(f"{SCANNER_MOD}.get_default_interface", return_value="eth0"),
        patch(f"{SCANNER_MOD}.get_gateway_ip", return_value="192.168.1.1"),
        patch("socket.gethostbyaddr", side_effect=OSError),
    ]
    mv = patch(f"{SCANNER_MOD}.mac_vendor")
    started = [p.start() for p in patches]
    mv_mock = mv.start()
    mv_mock.lookup.return_value = "Acme"
    yield
    mv.stop()
    for p in patches:
        p.stop()


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(db_path=tmp_path / "integration.db")
    d.connect()
    yield d
    d.close()


class TestScanToIDSPipeline:
    def test_first_scan_raises_new_device_alerts(
        self, scanner_env, db: Database, tmp_path: Path
    ) -> None:
        bus = EventBus()
        ids = NetworkIDS(
            event_bus=bus,
            config=IDSConfig(),
            db=db,
            whitelist_path=tmp_path / "wl.json",
        )
        ids.start()

        scanner = NetworkScanner(interface="eth0", event_bus=bus)
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run1):
            hosts = scanner.scan(network="192.168.1.0/24")
            # scanner publishes HOST_DISCOVERED events → IDS consumes

        assert len(hosts) == 2
        new_alerts = [a for a in ids.get_alerts() if a.alert_type == AlertType.NEW_DEVICE]
        assert len(new_alerts) == 2
        macs = {a.source_mac for a in new_alerts}
        assert macs == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:50"}
        ids.stop()

    def test_two_scans_detect_arp_spoof(
        self, scanner_env, db: Database, tmp_path: Path
    ) -> None:
        bus = EventBus()
        ids = NetworkIDS(
            event_bus=bus,
            config=IDSConfig(),
            db=db,
            whitelist_path=tmp_path / "wl.json",
        )
        ids.start()

        scanner = NetworkScanner(interface="eth0", event_bus=bus)
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run1):
            scanner.scan(network="192.168.1.0/24")
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run2):
            scanner.scan(network="192.168.1.0/24")

        spoofs = [a for a in ids.get_alerts() if a.alert_type == AlertType.ARP_SPOOF]
        assert len(spoofs) == 1
        assert spoofs[0].source_ip == "192.168.1.50"
        assert spoofs[0].raw_data["new_mac"] == "de:ad:be:ef:00:01"
        ids.stop()

    def test_alerts_persisted_to_db(
        self, scanner_env, db: Database, tmp_path: Path
    ) -> None:
        bus = EventBus()
        ids = NetworkIDS(
            event_bus=bus,
            config=IDSConfig(),
            db=db,
            whitelist_path=tmp_path / "wl.json",
        )
        ids.start()

        scanner = NetworkScanner(interface="eth0", event_bus=bus)
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run1):
            scanner.scan(network="192.168.1.0/24")

        rows = db.get_alerts()
        assert len(rows) >= 2  # at least the new_device alerts
        types = {r["alert_type"] for r in rows}
        assert "NEW_DEVICE" in types
        ids.stop()


class TestScanToReport:
    def test_report_includes_discovered_hosts(
        self, scanner_env, db: Database
    ) -> None:
        bus = EventBus()
        scanner = NetworkScanner(interface="eth0", event_bus=bus)
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run1):
            hosts = scanner.scan(network="192.168.1.0/24")

        for h in hosts:
            db.upsert_host(h)

        out = AuditReportGenerator(db).generate(fmt="json")
        data = json.loads(out)
        assert data["summary"]["total_hosts"] == 2

    def test_report_includes_ids_alerts(
        self, scanner_env, db: Database, tmp_path: Path
    ) -> None:
        bus = EventBus()
        ids = NetworkIDS(
            event_bus=bus,
            config=IDSConfig(),
            db=db,
            whitelist_path=tmp_path / "wl.json",
        )
        ids.start()

        scanner = NetworkScanner(interface="eth0", event_bus=bus)
        with patch(f"{SCANNER_MOD}.srp", side_effect=_fake_srp_run1):
            hosts = scanner.scan(network="192.168.1.0/24")
        for h in hosts:
            db.upsert_host(h)

        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert data["summary"]["total_alerts"] >= 2
        ids.stop()
