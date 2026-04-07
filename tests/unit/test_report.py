"""Tests for AuditReportGenerator — CSV, JSON, PDF, vuln detection."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

import pytest

from cuttix.db.database import Database
from cuttix.models.alert import Alert, AlertSeverity, AlertType
from cuttix.models.host import Host
from cuttix.models.scan_result import PortEntry
from cuttix.modules.report import (
    AuditReportGenerator,
    DANGEROUS_PORTS,
    _port_severity,
)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(db_path=tmp_path / "test.db")
    d.connect()
    yield d
    d.close()


@pytest.fixture
def populated_db(db: Database) -> Database:
    h1 = Host(ip="192.168.1.10", mac="aa:bb:cc:00:00:01", vendor="Acme",
              hostname="pc-alice", os_guess="Linux")
    h2 = Host(ip="192.168.1.11", mac="aa:bb:cc:00:00:02", vendor="Beta",
              hostname="pc-bob", os_guess="Windows", is_gateway=False)
    db.upsert_host(h1)
    db.upsert_host(h2)

    db.upsert_port(h1.mac, PortEntry(port=22, state="open", service="ssh"))
    db.upsert_port(h1.mac, PortEntry(port=23, state="open", service="telnet"))
    db.upsert_port(h1.mac, PortEntry(port=443, state="open", service="https"))
    db.upsert_port(h2.mac, PortEntry(port=3389, state="open", service="rdp"))
    db.upsert_port(h2.mac, PortEntry(port=8080, state="closed", service="http-alt"))

    db.insert_alert(Alert(
        alert_type=AlertType.ARP_SPOOF,
        severity=AlertSeverity.HIGH,
        description="MAC changed for 192.168.1.10",
        source_ip="192.168.1.10",
    ))
    db.insert_alert(Alert(
        alert_type=AlertType.NEW_DEVICE,
        severity=AlertSeverity.LOW,
        description="new device seen",
        source_ip="192.168.1.99",
    ))
    return db


class TestSupportedFormats:
    def test_json_csv_always_supported(self, db: Database) -> None:
        gen = AuditReportGenerator(db)
        fmts = gen.get_supported_formats()
        assert "json" in fmts
        assert "csv" in fmts

    def test_rejects_unsupported_format(self, db: Database) -> None:
        gen = AuditReportGenerator(db)
        with pytest.raises(ValueError):
            gen.generate(fmt="xml")


class TestJSONOutput:
    def test_empty_db_produces_valid_json(self, db: Database) -> None:
        gen = AuditReportGenerator(db)
        out = gen.generate(fmt="json")
        data = json.loads(out)
        assert data["summary"]["total_hosts"] == 0
        assert data["summary"]["total_alerts"] == 0
        assert data["hosts"] == []
        assert data["alerts"] == []

    def test_populated_json_contains_hosts(self, populated_db: Database) -> None:
        gen = AuditReportGenerator(populated_db)
        data = json.loads(gen.generate(fmt="json"))
        assert data["summary"]["total_hosts"] == 2
        assert data["summary"]["total_alerts"] == 2
        ips = {h["ip"] for h in data["hosts"]}
        assert "192.168.1.10" in ips
        assert "192.168.1.11" in ips

    def test_json_contains_vulnerabilities(self, populated_db: Database) -> None:
        data = json.loads(AuditReportGenerator(populated_db).generate(fmt="json"))
        vulns = data["vulnerabilities"]
        ports = {v["port"] for v in vulns}
        # telnet (23) and rdp (3389) should be flagged, telnet is critical
        assert 23 in ports
        assert 3389 in ports
        assert 443 not in ports  # https is not dangerous

    def test_json_includes_recommendations(self, populated_db: Database) -> None:
        data = json.loads(AuditReportGenerator(populated_db).generate(fmt="json"))
        recs = data["recommendations"]
        assert len(recs) >= 2
        assert any("Telnet" in r or "23" in r for r in recs)

    def test_json_write_to_file(self, populated_db: Database, tmp_path: Path) -> None:
        out_file = tmp_path / "report.json"
        gen = AuditReportGenerator(populated_db)
        gen.generate(fmt="json", output_path=str(out_file))
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["summary"]["total_hosts"] == 2


class TestCSVOutput:
    def test_csv_contains_inventory_header(self, populated_db: Database) -> None:
        out = AuditReportGenerator(populated_db).generate(fmt="csv")
        assert "# Network Inventory" in out
        assert "# Vulnerabilities" in out
        assert "# Alerts" in out

    def test_csv_is_parsable(self, populated_db: Database) -> None:
        out = AuditReportGenerator(populated_db).generate(fmt="csv")
        reader = csv.reader(io.StringIO(out))
        rows = list(reader)
        assert len(rows) > 5
        # find inventory section
        inv_idx = next(i for i, r in enumerate(rows) if r and r[0] == "# Network Inventory")
        assert rows[inv_idx + 1][0] == "IP"

    def test_csv_lists_open_ports_only(self, populated_db: Database) -> None:
        out = AuditReportGenerator(populated_db).generate(fmt="csv")
        # port 8080 is closed, shouldn't appear in open ports column
        assert "8080" not in out or "closed" not in out

    def test_csv_write_to_file(self, populated_db: Database, tmp_path: Path) -> None:
        out_file = tmp_path / "report.csv"
        AuditReportGenerator(populated_db).generate(
            fmt="csv", output_path=str(out_file))
        assert out_file.exists()
        assert "# Network Inventory" in out_file.read_text()


class TestVulnerabilityDetection:
    def test_no_open_ports_no_vulns(self, db: Database) -> None:
        h = Host(ip="10.0.0.1", mac="aa:bb:cc:00:00:ff")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=23, state="closed"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert data["vulnerabilities"] == []

    def test_telnet_flagged_as_critical(self, db: Database) -> None:
        h = Host(ip="10.0.0.2", mac="aa:bb:cc:00:00:fe")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=23, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        vulns = data["vulnerabilities"]
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "critical"
        assert vulns[0]["service"] == "Telnet"

    def test_mysql_flagged_as_high(self, db: Database) -> None:
        h = Host(ip="10.0.0.3", mac="aa:bb:cc:00:00:fd")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=3306, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert data["vulnerabilities"][0]["severity"] == "high"

    def test_ignore_unknown_dangerous_ports(self, db: Database) -> None:
        h = Host(ip="10.0.0.4", mac="aa:bb:cc:00:00:fc")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=9999, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert data["vulnerabilities"] == []


class TestPortSeverity:
    def test_critical_ports(self) -> None:
        assert _port_severity(23) == "critical"
        assert _port_severity(445) == "critical"
        assert _port_severity(3389) == "critical"

    def test_high_ports(self) -> None:
        assert _port_severity(21) == "high"
        assert _port_severity(3306) == "high"

    def test_default_medium(self) -> None:
        assert _port_severity(80) == "medium"
        assert _port_severity(110) == "medium"

    def test_dangerous_port_constant_has_entries(self) -> None:
        assert 21 in DANGEROUS_PORTS
        assert 23 in DANGEROUS_PORTS
        assert 3389 in DANGEROUS_PORTS
        for port, (name, desc) in DANGEROUS_PORTS.items():
            assert isinstance(port, int)
            assert isinstance(name, str) and name
            assert isinstance(desc, str) and desc


class TestRecommendations:
    def test_cleartext_service_recommendation(self, db: Database) -> None:
        h = Host(ip="10.0.0.5", mac="aa:bb:cc:00:00:fb")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=21, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert any("FTP" in r and "10.0.0.5" in r for r in data["recommendations"])

    def test_database_port_recommendation(self, db: Database) -> None:
        h = Host(ip="10.0.0.6", mac="aa:bb:cc:00:00:fa")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=5432, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        assert any("PostgreSQL" in r or "5432" in r for r in data["recommendations"])

    def test_no_duplicate_recommendations(self, db: Database) -> None:
        # same host, same port scanned twice shouldn't duplicate
        h = Host(ip="10.0.0.7", mac="aa:bb:cc:00:00:f9")
        db.upsert_host(h)
        db.upsert_port(h.mac, PortEntry(port=23, state="open"))
        db.upsert_port(h.mac, PortEntry(port=23, state="open"))
        data = json.loads(AuditReportGenerator(db).generate(fmt="json"))
        telnet_recs = [r for r in data["recommendations"] if "Telnet" in r]
        assert len(telnet_recs) == 1


class TestPDFOutput:
    def test_pdf_generation_if_reportlab_available(
        self, populated_db: Database, tmp_path: Path
    ) -> None:
        pytest.importorskip("reportlab")
        out_file = tmp_path / "report.pdf"
        gen = AuditReportGenerator(populated_db)
        result = gen.generate(fmt="pdf", output_path=str(out_file))
        assert out_file.exists()
        assert out_file.stat().st_size > 1000  # valid PDF has some content
        assert str(out_file) == result
        # basic PDF header check
        assert out_file.read_bytes()[:4] == b"%PDF"

    def test_pdf_empty_db(self, db: Database, tmp_path: Path) -> None:
        pytest.importorskip("reportlab")
        out_file = tmp_path / "empty.pdf"
        AuditReportGenerator(db).generate(fmt="pdf", output_path=str(out_file))
        assert out_file.exists()
        assert out_file.read_bytes()[:4] == b"%PDF"
