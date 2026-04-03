from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from cuttix.models.host import Host, HostStatus
from cuttix.models.alert import Alert, AlertType, AlertSeverity
from cuttix.models.scan_result import ScanResult, PortEntry

logger = logging.getLogger(__name__)


def _default_db_dir() -> Path:
    """Same XDG logic as audit_log."""
    if sys.platform == "linux":
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".local" / "share"
    d = base / "cuttix"
    d.mkdir(parents=True, exist_ok=True)
    return d


class Database:
    """SQLite wrapper. Nothing fancy — just parameterized queries and WAL mode."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            db_path = _default_db_dir() / "cuttix.db"
        elif db_path == ":memory:":
            pass  # in-memory for tests
        else:
            db_path = Path(db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

        self._path = str(db_path)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._init_schema()
        logger.info("Database connected: %s", self._path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        return self._conn  # type: ignore[return-value]

    def _init_schema(self) -> None:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            schema = schema_path.read_text()
            self.conn.executescript(schema)
        else:
            logger.warning("schema.sql not found at %s, skipping init", schema_path)

    # -- hosts --

    def upsert_host(self, host: Host) -> None:
        self.conn.execute(
            """
            INSERT INTO hosts (mac, ip, vendor, hostname, os_guess, os_confidence,
                              first_seen, last_seen, is_gateway, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                vendor = COALESCE(excluded.vendor, hosts.vendor),
                hostname = COALESCE(excluded.hostname, hosts.hostname),
                os_guess = COALESCE(excluded.os_guess, hosts.os_guess),
                os_confidence = MAX(excluded.os_confidence, hosts.os_confidence),
                last_seen = excluded.last_seen,
                session_count = hosts.session_count + 1,
                updated_at = datetime('now')
            """,
            (host.mac, host.ip, host.vendor, host.hostname,
             host.os_guess, host.os_confidence,
             host.first_seen.isoformat(), host.last_seen.isoformat(),
             int(host.is_gateway), host.notes),
        )
        self.conn.commit()

    def get_all_hosts(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def get_host_by_mac(self, mac: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE mac = ?", (mac.lower(),)).fetchone()
        return dict(row) if row else None

    def get_host_by_ip(self, ip: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
        return dict(row) if row else None

    # -- ports --

    def upsert_port(self, host_mac: str, entry: PortEntry) -> None:
        self.conn.execute(
            """
            INSERT INTO ports (host_mac, port, protocol, state, service, banner, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_mac, port, protocol) DO UPDATE SET
                state = excluded.state,
                service = COALESCE(excluded.service, ports.service),
                banner = COALESCE(excluded.banner, ports.banner),
                version = COALESCE(excluded.version, ports.version),
                scanned_at = datetime('now')
            """,
            (host_mac.lower(), entry.port, entry.protocol, entry.state,
             entry.service, entry.banner, entry.version),
        )
        self.conn.commit()

    def get_ports_for_host(self, host_mac: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM ports WHERE host_mac = ? ORDER BY port",
            (host_mac.lower(),),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- alerts --

    def insert_alert(self, alert: Alert) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO alerts (alert_type, severity, source_ip, source_mac,
                               target_ip, target_mac, description, raw_data,
                               correlation_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (alert.alert_type.name, alert.severity.value,
             alert.source_ip, alert.source_mac,
             alert.target_ip, alert.target_mac,
             alert.description,
             json.dumps(alert.raw_data) if alert.raw_data else None,
             alert.correlation_id),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_alerts(self, limit: int = 100, alert_type: str | None = None) -> list[dict[str, Any]]:
        if alert_type:
            rows = self.conn.execute(
                "SELECT * FROM alerts WHERE alert_type = ? ORDER BY created_at DESC LIMIT ?",
                (alert_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        self.conn.commit()

    # -- config state --

    def get_config_value(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM config_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_config_value(self, key: str, value: str) -> None:
        self.conn.execute(
            """
            INSERT INTO config_state (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
            """,
            (key, value),
        )
        self.conn.commit()

    # -- disclaimer --

    def is_disclaimer_accepted(self) -> bool:
        return self.get_config_value("disclaimer_accepted") == "1"

    def accept_disclaimer(self) -> None:
        self.set_config_value("disclaimer_accepted", "1")
