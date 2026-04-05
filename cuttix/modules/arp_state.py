"""HMAC-signed state file for ARP spoofing — survives kill -9.

XDG-compliant path, atomic writes, integrity verification.
This is layer 3 of the kill switch.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SpoofEntry:
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    started_at: str  # ISO format
    auto_restore_at: str | None = None


def _state_dir() -> Path:
    """XDG-compliant state directory.
    Linux:   ~/.local/state/cuttix/
    macOS:   ~/Library/Application Support/cuttix/
    Windows: %LOCALAPPDATA%/cuttix/
    """
    if sys.platform == "linux":
        base = Path(os.environ.get(
            "XDG_STATE_HOME", Path.home() / ".local" / "state"
        ))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get(
            "LOCALAPPDATA", Path.home() / "AppData" / "Local"
        ))
    else:
        base = Path.home() / ".local" / "state"

    d = base / "cuttix"
    d.mkdir(parents=True, exist_ok=True)
    return d


class ARPStateFile:
    """Signed state file for orphan recovery.

    Format on disk: JSON payload + "|" + HMAC-SHA256 hex digest.
    The HMAC key is derived from a per-install secret stored alongside
    the audit log (same secret, different use).
    """

    FILENAME = "arp_state.json"

    def __init__(self, state_dir: Path | None = None, secret: bytes | None = None) -> None:
        self._dir = state_dir or _state_dir()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / self.FILENAME
        self._secret = secret or self._load_secret()

    @property
    def path(self) -> Path:
        return self._path

    # -- read / write --

    def save(self, entries: list[SpoofEntry]) -> None:
        """Atomic write with HMAC signature."""
        payload = json.dumps(
            [asdict(e) for e in entries],
            separators=(",", ":"),
        )
        sig = self._sign(payload)
        content = f"{payload}|{sig}\n"

        # write to tmp then rename — atomic on POSIX
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.replace(tmp, str(self._path))
        except Exception:
            # cleanup on failure
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        logger.debug("ARP state saved (%d entries)", len(entries))

    def load(self) -> list[SpoofEntry] | None:
        """Load and verify. Returns None if missing, empty, or tampered."""
        if not self._path.exists():
            return None

        try:
            raw = self._path.read_text().strip()
        except OSError as exc:
            logger.error("Can't read state file: %s", exc)
            return None

        if "|" not in raw:
            logger.error("State file missing HMAC separator — corrupt")
            self.remove()
            return None

        payload, stored_sig = raw.rsplit("|", 1)

        expected = self._sign(payload)
        if not hmac.compare_digest(stored_sig, expected):
            logger.error("State file HMAC mismatch — tampered or stale secret")
            self.remove()
            return None

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            logger.error("State file JSON parse error")
            self.remove()
            return None

        entries = []
        for item in data:
            try:
                entries.append(SpoofEntry(**item))
            except TypeError as exc:
                logger.warning("Skipping bad entry: %s", exc)

        return entries

    def remove(self) -> None:
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass

    def exists(self) -> bool:
        return self._path.exists()

    # -- HMAC --

    def _sign(self, data: str) -> str:
        return hmac.new(
            self._secret, data.encode(), hashlib.sha256
        ).hexdigest()

    def _load_secret(self) -> bytes:
        """Reuse the audit log secret if it exists, otherwise create one."""
        # check audit secret first (same directory layout)
        from cuttix.core.audit_log import _get_data_dir
        secret_path = _get_data_dir() / ".audit_secret"
        if secret_path.exists():
            return secret_path.read_bytes()

        # fall back to our own
        own_secret = self._dir / ".state_secret"
        if own_secret.exists():
            return own_secret.read_bytes()

        secret = os.urandom(32)
        own_secret.write_bytes(secret)
        try:
            os.chmod(own_secret, 0o600)
        except OSError:
            pass
        return secret
