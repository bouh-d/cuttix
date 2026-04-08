"""MAC address → vendor name via IEEE OUI database."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# loaded once, shared across the process
_oui_db: dict[str, str] = {}
_loaded = False


def _oui_path() -> Path:
    """assets/oui.csv ships with the package."""
    return Path(__file__).resolve().parent.parent.parent / "assets" / "oui.csv"


def _ensure_loaded() -> None:
    global _loaded, _oui_db
    if _loaded:
        return

    path = _oui_path()
    if not path.exists():
        logger.warning("OUI database not found at %s — vendor lookups disabled", path)
        _loaded = True
        return

    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    prefix = row[0].strip().lower().replace("-", ":")
                    _oui_db[prefix] = row[1].strip()
        logger.debug("Loaded %d OUI entries", len(_oui_db))
    except Exception as e:
        logger.error("Failed to parse OUI database: %s", e)

    _loaded = True


def lookup(mac: str) -> str | None:
    """Return vendor name for a MAC address, or None if unknown.

    Accepts formats: aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabbccddeeff
    """
    _ensure_loaded()

    mac = mac.lower().replace("-", ":").replace(".", ":")
    # handle bare hex (no separators)
    if ":" not in mac and len(mac) == 12:
        mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))

    oui = ":".join(mac.split(":")[:3])
    return _oui_db.get(oui)


def get_db_size() -> int:
    _ensure_loaded()
    return len(_oui_db)
