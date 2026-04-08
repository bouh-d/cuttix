from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class _JSONFormatter(logging.Formatter):
    """One JSON object per line — parseable by jq, Loki, etc."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra_data"):
            entry["extra"] = record.extra_data
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Configure cuttix root logger.

    Console gets human-readable format, file gets JSON.
    """
    root = logging.getLogger("cuttix")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # don't duplicate if called twice
    if root.handlers:
        return

    # console: short and readable
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root.addHandler(console)

    # file: structured JSON
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(_JSONFormatter())
        root.addHandler(fh)
