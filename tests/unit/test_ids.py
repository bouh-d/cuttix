"""Tests for NetworkIDS — detection rules and event handling."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import pytest

from cuttix.config import IDSConfig
from cuttix.core.event_bus import Event, EventBus, EventType
from cuttix.models.alert import AlertSeverity, AlertType
from cuttix.models.host import Host
from cuttix.models.packet import PacketInfo
from cuttix.modules.ids import NetworkIDS


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def wl_path(tmp_path: Path) -> Path:
    return tmp_path / "whitelist.json"


@pytest.fixture
def ids(bus: EventBus, wl_path: Path) -> NetworkIDS:
    cfg = IDSConfig(
        detect_arp_spoof=True,
        detect_new_device=True,
        detect_rogue_dhcp=True,
        detect_port_scan=True,
        detect_mac_flooding=True,
        port_scan_threshold_ports=5,
        port_scan_threshold_seconds=5,
    )
    i = NetworkIDS(event_bus=bus, config=cfg, whitelist_path=wl_path)
    i.start()
    yield i
    i.stop()


def _host(ip: str, mac: str, vendor: str = "Acme") -> Host:
    return Host(ip=ip, mac=mac, vendor=vendor)


def _publish_host(bus: EventBus, host: Host) -> None:
    bus.publish(Event(type=EventType.HOST_DISCOVERED, data=host, source="scanner"))


def _publish_pkt(bus: EventBus, pkt: PacketInfo) -> None:
    bus.publish(Event(type=EventType.PACKET_CAPTURED, data=pkt, source="capture"))


class TestARPSpoofDetection:
    def test_same_mac_no_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_host(bus, _host("192.168.1.10", "aa:bb:cc:dd:ee:01"))
        _publish_host(bus, _host("192.168.1.10", "aa:bb:cc:dd:ee:01"))
        spoof_alerts = [a for a in ids.get_alerts() if a.alert_type == AlertType.ARP_SPOOF]
        assert spoof_alerts == []

    def test_mac_change_raises_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_host(bus, _host("192.168.1.20", "aa:bb:cc:dd:ee:01"))
        _publish_host(bus, _host("192.168.1.20", "aa:bb:cc:dd:ee:99"))
        spoof = [a for a in ids.get_alerts() if a.alert_type == AlertType.ARP_SPOOF]
        assert len(spoof) == 1
        assert spoof[0].severity == AlertSeverity.HIGH
        assert "192.168.1.20" in spoof[0].description

    def test_whitelist_skips_spoof(self, ids: NetworkIDS, bus: EventBus) -> None:
        ids.add_to_whitelist("aa:bb:cc:dd:ee:99")
        _publish_host(bus, _host("192.168.1.30", "aa:bb:cc:dd:ee:01"))
        _publish_host(bus, _host("192.168.1.30", "aa:bb:cc:dd:ee:99"))
        spoof = [a for a in ids.get_alerts() if a.alert_type == AlertType.ARP_SPOOF]
        assert spoof == []

    def test_arp_conflict_event(self, ids: NetworkIDS, bus: EventBus) -> None:
        bus.publish(
            Event(
                type=EventType.ARP_CONFLICT,
                data={"ip": "192.168.1.5", "macs": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]},
                source="scanner",
            )
        )
        alerts = [a for a in ids.get_alerts() if a.alert_type == AlertType.ARP_SPOOF]
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.CRITICAL


class TestNewDeviceDetection:
    def test_first_host_triggers_new_device(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_host(bus, _host("192.168.1.50", "11:22:33:44:55:66"))
        new = [a for a in ids.get_alerts() if a.alert_type == AlertType.NEW_DEVICE]
        assert len(new) == 1
        assert new[0].severity == AlertSeverity.LOW

    def test_same_mac_twice_only_one_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_host(bus, _host("192.168.1.60", "11:22:33:44:55:67"))
        _publish_host(bus, _host("192.168.1.60", "11:22:33:44:55:67"))
        new = [a for a in ids.get_alerts() if a.alert_type == AlertType.NEW_DEVICE]
        assert len(new) == 1

    def test_whitelisted_new_device_skipped(self, ids: NetworkIDS, bus: EventBus) -> None:
        ids.add_to_whitelist("11:22:33:44:55:68")
        _publish_host(bus, _host("192.168.1.70", "11:22:33:44:55:68"))
        new = [a for a in ids.get_alerts() if a.alert_type == AlertType.NEW_DEVICE]
        assert new == []

    def test_seed_known_hosts_suppresses_alerts(self, bus: EventBus, wl_path: Path) -> None:
        cfg = IDSConfig()
        i = NetworkIDS(event_bus=bus, config=cfg, whitelist_path=wl_path)
        i.seed_known_hosts(
            {
                "192.168.1.80": Host(ip="192.168.1.80", mac="aa:11:22:33:44:55"),
            }
        )
        i.start()
        try:
            _publish_host(bus, _host("192.168.1.80", "aa:11:22:33:44:55"))
            new = [a for a in i.get_alerts() if a.alert_type == AlertType.NEW_DEVICE]
            assert new == []
        finally:
            i.stop()


class TestPortScanDetection:
    def _pkt(self, src: str, dst_port: int) -> PacketInfo:
        return PacketInfo(
            timestamp=datetime.now(),
            src_ip=src,
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=dst_port,
            protocol="TCP",
        )

    def test_below_threshold_no_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        for port in (22, 80, 443):
            _publish_pkt(bus, self._pkt("10.0.0.50", port))
        scans = [a for a in ids.get_alerts() if a.alert_type == AlertType.PORT_SCAN]
        assert scans == []

    def test_threshold_reached_raises_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        for port in (22, 80, 443, 3306, 8080):
            _publish_pkt(bus, self._pkt("10.0.0.51", port))
        scans = [a for a in ids.get_alerts() if a.alert_type == AlertType.PORT_SCAN]
        assert len(scans) == 1
        assert scans[0].source_ip == "10.0.0.51"
        assert scans[0].raw_data["unique_ports"] >= 5

    def test_different_src_tracked_separately(self, ids: NetworkIDS, bus: EventBus) -> None:
        for p in (22, 80, 443, 21):
            _publish_pkt(bus, self._pkt("10.0.0.60", p))
        for p in (25, 110, 143, 993):
            _publish_pkt(bus, self._pkt("10.0.0.61", p))
        scans = [a for a in ids.get_alerts() if a.alert_type == AlertType.PORT_SCAN]
        assert scans == []

    def test_duplicate_ports_not_counted_twice(self, ids: NetworkIDS, bus: EventBus) -> None:
        for _ in range(10):
            _publish_pkt(bus, self._pkt("10.0.0.62", 80))
        scans = [a for a in ids.get_alerts() if a.alert_type == AlertType.PORT_SCAN]
        assert scans == []


class TestRogueDHCPDetection:
    def _dhcp_offer(self, src_ip: str, src_mac: str = "de:ad:be:ef:00:01") -> PacketInfo:
        return PacketInfo(
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip="255.255.255.255",
            src_mac=src_mac,
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_port=67,
            dst_port=68,
            protocol="UDP",
        )

    def test_unauthorized_dhcp_raises_alert(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_pkt(bus, self._dhcp_offer("192.168.1.200"))
        rogue = [a for a in ids.get_alerts() if a.alert_type == AlertType.ROGUE_DHCP]
        assert len(rogue) == 1
        assert rogue[0].source_ip == "192.168.1.200"

    def test_authorized_dhcp_ignored(self, ids: NetworkIDS, bus: EventBus) -> None:
        ids.set_authorized_dhcp(["192.168.1.1"])
        _publish_pkt(bus, self._dhcp_offer("192.168.1.1"))
        rogue = [a for a in ids.get_alerts() if a.alert_type == AlertType.ROGUE_DHCP]
        assert rogue == []

    def test_non_dhcp_packet_ignored(self, ids: NetworkIDS, bus: EventBus) -> None:
        pkt = PacketInfo(
            timestamp=datetime.now(),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=443,
            dst_port=54321,
            protocol="TCP",
        )
        _publish_pkt(bus, pkt)
        rogue = [a for a in ids.get_alerts() if a.alert_type == AlertType.ROGUE_DHCP]
        assert rogue == []


class TestWhitelistPersistence:
    def test_whitelist_persists_to_disk(self, bus: EventBus, wl_path: Path) -> None:
        i1 = NetworkIDS(event_bus=bus, whitelist_path=wl_path)
        i1.add_to_whitelist("aa:bb:cc:00:00:01")
        i1.add_to_whitelist("aa:bb:cc:00:00:02")
        assert wl_path.exists()

        i2 = NetworkIDS(event_bus=EventBus(), whitelist_path=wl_path)
        assert "aa:bb:cc:00:00:01" in i2.get_whitelist()
        assert "aa:bb:cc:00:00:02" in i2.get_whitelist()

    def test_remove_from_whitelist(self, bus: EventBus, wl_path: Path) -> None:
        i = NetworkIDS(event_bus=bus, whitelist_path=wl_path)
        i.add_to_whitelist("aa:bb:cc:00:00:03")
        i.remove_from_whitelist("aa:bb:cc:00:00:03")
        assert "aa:bb:cc:00:00:03" not in i.get_whitelist()

    def test_mac_normalized_to_lowercase(self, bus: EventBus, wl_path: Path) -> None:
        i = NetworkIDS(event_bus=bus, whitelist_path=wl_path)
        i.add_to_whitelist("AA:BB:CC:DD:EE:FF")
        assert "aa:bb:cc:dd:ee:ff" in i.get_whitelist()


class TestLifecycle:
    def test_start_stop_idempotent(self, bus: EventBus, wl_path: Path) -> None:
        i = NetworkIDS(event_bus=bus, whitelist_path=wl_path)
        i.start()
        i.start()
        i.stop()
        i.stop()

    def test_alerts_filtered_by_since(self, ids: NetworkIDS, bus: EventBus) -> None:
        _publish_host(bus, _host("192.168.1.100", "cc:cc:cc:cc:cc:01"))
        cutoff = time.time() + 0.01
        time.sleep(0.02)
        _publish_host(bus, _host("192.168.1.101", "cc:cc:cc:cc:cc:02"))

        all_alerts = ids.get_alerts()
        recent = ids.get_alerts(since=cutoff)
        assert len(all_alerts) >= 2
        assert len(recent) < len(all_alerts)

    def test_alerts_published_on_bus(self, bus: EventBus, wl_path: Path) -> None:
        i = NetworkIDS(event_bus=bus, whitelist_path=wl_path)
        i.start()
        received = []
        bus.subscribe(EventType.NEW_DEVICE, lambda e: received.append(e), "test")
        _publish_host(bus, _host("192.168.1.200", "ee:ff:00:11:22:33"))
        assert len(received) == 1
        i.stop()
