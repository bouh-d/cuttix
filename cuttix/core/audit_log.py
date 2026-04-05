from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def _get_data_dir() -> Path:
    """XDG-compliant data directory.
    Linux:   ~/.local/share/cuttix/
    macOS:   ~/Library/Application Support/cuttix/
    Windows: %LOCALAPPDATA%/cuttix/
    """
    if sys.platform == "linux":
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".local" / "share"

    data_dir = base / "cuttix"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


class AuditLog:
    """Append-only log with HMAC chain for tamper detection.

    Each entry is a JSON line. The HMAC of each line includes
    the previous HMAC, forming a hash chain — if any line is
    modified or deleted, the chain breaks.

    This log CANNOT be disabled. That's the point.
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        base = log_dir or _get_data_dir()
        base.mkdir(parents=True, exist_ok=True)

        self._log_path = base / "audit.log"
        self._secret_path = base / ".audit_secret"
        self._secret = self._load_or_create_secret()
        self._last_hmac = self._get_last_hmac()

        # restrict permissions
        try:
            os.chmod(base, 0o700)
            os.chmod(self._secret_path, 0o600)
        except OSError:
            pass  # windows

    def log_action(
        self,
        action: str,
        target_ip: str,
        target_mac: str,
        operator_ip: str,
        auto_restore_minutes: int = 0,
        **extra: str,
    ) -> None:
        """Append a signed entry. Called for every CUT/RESTORE/ORPHAN_RESTORE."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target_ip": target_ip,
            "target_mac": target_mac,
            "operator_ip": operator_ip,
            "auto_restore_min": auto_restore_minutes,
            **extra,
        }

        line = json.dumps(entry, separators=(",", ":"))
        entry_hmac = self._compute_hmac(line)

        # write: data | hmac
        with open(self._log_path, "a") as f:
            f.write(f"{line}|{entry_hmac}\n")

        self._last_hmac = entry_hmac

        logger.info(
            "AUDIT: %s %s (%s) by %s",
            action, target_ip, target_mac, operator_ip,
        )

    def verify_integrity(self) -> tuple[bool, int]:
        """Check the HMAC chain. Returns (valid, line_count)."""
        if not self._log_path.exists():
            return True, 0

        prev_hmac = "0" * 64
        count = 0

        with open(self._log_path) as f:
            for line_num, raw_line in enumerate(f, 1):
                raw_line = raw_line.rstrip("\n")
                if "|" not in raw_line:
                    logger.error("Audit log corrupted at line %d: no HMAC separator", line_num)
                    return False, line_num

                data, stored_hmac = raw_line.rsplit("|", 1)
                expected = self._compute_hmac(data, prev_hmac=prev_hmac)

                if not hmac.compare_digest(stored_hmac, expected):
                    logger.error("Audit log HMAC mismatch at line %d — tampered?", line_num)
                    return False, line_num

                prev_hmac = stored_hmac
                count += 1

        return True, count

    def _compute_hmac(self, data: str, prev_hmac: str | None = None) -> str:
        """HMAC-SHA256 of data chained with previous HMAC."""
        chain = prev_hmac or self._last_hmac
        msg = f"{chain}:{data}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _load_or_create_secret(self) -> bytes:
        if self._secret_path.exists():
            return self._secret_path.read_bytes()
        secret = os.urandom(32)
        self._secret_path.write_bytes(secret)
        try:
            os.chmod(self._secret_path, 0o600)
        except OSError:
            pass
        return secret

    def _get_last_hmac(self) -> str:
        """Read the last HMAC from the log file, or return zeros for empty log."""
        if not self._log_path.exists():
            return "0" * 64
        try:
            # read last line
            with open(self._log_path, "rb") as f:
                f.seek(0, 2)  # end
                pos = f.tell()
                if pos == 0:
                    return "0" * 64
                # scan backwards for newline
                while pos > 0:
                    pos -= 1
                    f.seek(pos)
                    if f.read(1) == b"\n" and pos < f.seek(0, 2) - 1:
                        break
                last_line = f.readline().decode().rstrip("\n")
            if "|" in last_line:
                return last_line.rsplit("|", 1)[1]
        except Exception:
            pass
        return "0" * 64

    @property
    def log_path(self) -> Path:
        return self._log_path
