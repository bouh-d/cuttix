from __future__ import annotations

import pytest

from cuttix.db.database import Database
from cuttix.models.host import Host
from cuttix.models.alert import Alert, AlertType, AlertSeverity
from cuttix.models.scan_result import PortEntry


class TestHostCRUD:
    def test_upsert_and_retrieve(self, memory_db):
        host = Host(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", vendor="TestCorp")
        memory_db.upsert_host(host)

        result = memory_db.get_host_by_mac("aa:bb:cc:dd:ee:ff")
        assert result is not None
        assert result["ip"] == "10.0.0.5"
        assert result["vendor"] == "TestCorp"

    def test_upsert_updates_existing(self, memory_db):
        host1 = Host(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", vendor="OldCorp")
        memory_db.upsert_host(host1)

        host2 = Host(ip="10.0.0.6", mac="aa:bb:cc:dd:ee:ff", vendor="NewCorp")
        memory_db.upsert_host(host2)

        result = memory_db.get_host_by_mac("aa:bb:cc:dd:ee:ff")
        assert result["ip"] == "10.0.0.6"  # updated
        assert result["session_count"] == 2

    def test_get_all_hosts(self, memory_db):
        for i in range(3):
            memory_db.upsert_host(Host(ip=f"10.0.0.{i}", mac=f"aa:bb:cc:dd:ee:{i:02x}"))
        hosts = memory_db.get_all_hosts()
        assert len(hosts) == 3

    def test_get_host_by_ip(self, memory_db):
        memory_db.upsert_host(Host(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff"))
        result = memory_db.get_host_by_ip("10.0.0.5")
        assert result is not None
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_missing_host_returns_none(self, memory_db):
        assert memory_db.get_host_by_mac("00:00:00:00:00:00") is None
        assert memory_db.get_host_by_ip("1.2.3.4") is None


class TestPortCRUD:
    def test_upsert_port(self, memory_db):
        memory_db.upsert_host(Host(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff"))
        memory_db.upsert_port("aa:bb:cc:dd:ee:ff", PortEntry(port=80, service="http"))

        ports = memory_db.get_ports_for_host("aa:bb:cc:dd:ee:ff")
        assert len(ports) == 1
        assert ports[0]["port"] == 80
        assert ports[0]["service"] == "http"


class TestAlertCRUD:
    def test_insert_and_retrieve_alert(self, memory_db):
        alert = Alert(
            alert_type=AlertType.ARP_SPOOF,
            severity=AlertSeverity.HIGH,
            description="MAC changed for 10.0.0.5",
            source_ip="10.0.0.99",
        )
        alert_id = memory_db.insert_alert(alert)
        assert alert_id > 0

        alerts = memory_db.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "ARP_SPOOF"

    def test_acknowledge_alert(self, memory_db):
        alert = Alert(
            alert_type=AlertType.NEW_DEVICE,
            severity=AlertSeverity.LOW,
            description="New device seen",
        )
        aid = memory_db.insert_alert(alert)
        memory_db.acknowledge_alert(aid)

        alerts = memory_db.get_alerts()
        assert alerts[0]["acknowledged"] == 1


class TestConfigState:
    def test_set_and_get(self, memory_db):
        memory_db.set_config_value("test_key", "test_value")
        assert memory_db.get_config_value("test_key") == "test_value"

    def test_disclaimer_flow(self, memory_db):
        assert memory_db.is_disclaimer_accepted() is False
        memory_db.accept_disclaimer()
        assert memory_db.is_disclaimer_accepted() is True
