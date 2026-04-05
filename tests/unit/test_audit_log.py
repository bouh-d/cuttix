from __future__ import annotations

import pytest
from pathlib import Path

from cuttix.core.audit_log import AuditLog


@pytest.fixture
def audit_log(tmp_path):
    return AuditLog(log_dir=tmp_path)


class TestAuditLog:
    def test_log_creates_file(self, audit_log, tmp_path):
        audit_log.log_action(
            action="CUT",
            target_ip="10.0.0.5",
            target_mac="aa:bb:cc:dd:ee:ff",
            operator_ip="10.0.0.1",
        )
        assert (tmp_path / "audit.log").exists()

    def test_log_entry_contains_action(self, audit_log, tmp_path):
        audit_log.log_action(
            action="RESTORE",
            target_ip="10.0.0.5",
            target_mac="aa:bb:cc:dd:ee:ff",
            operator_ip="10.0.0.1",
        )
        content = (tmp_path / "audit.log").read_text()
        assert "RESTORE" in content
        assert "10.0.0.5" in content

    def test_integrity_check_passes(self, audit_log):
        for i in range(5):
            audit_log.log_action(
                action="CUT",
                target_ip=f"10.0.0.{i}",
                target_mac=f"aa:bb:cc:dd:ee:{i:02x}",
                operator_ip="10.0.0.1",
            )
        valid, count = audit_log.verify_integrity()
        assert valid is True
        assert count == 5

    def test_tamper_detection(self, audit_log, tmp_path):
        audit_log.log_action(
            action="CUT",
            target_ip="10.0.0.5",
            target_mac="aa:bb:cc:dd:ee:ff",
            operator_ip="10.0.0.1",
        )
        audit_log.log_action(
            action="RESTORE",
            target_ip="10.0.0.5",
            target_mac="aa:bb:cc:dd:ee:ff",
            operator_ip="10.0.0.1",
        )

        # tamper with the file
        log_file = tmp_path / "audit.log"
        lines = log_file.read_text().splitlines()
        # modify first line's data
        tampered = lines[0].replace("CUT", "FAKE")
        lines[0] = tampered
        log_file.write_text("\n".join(lines) + "\n")

        valid, line_num = audit_log.verify_integrity()
        assert valid is False

    def test_empty_log_is_valid(self, audit_log):
        valid, count = audit_log.verify_integrity()
        assert valid is True
        assert count == 0
