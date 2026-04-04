from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cuttix.core.exceptions import ConfigError

logger = logging.getLogger(__name__)

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


# -- default config values --

@dataclass
class ScannerConfig:
    interval: int = 30
    timeout: float = 2.0
    retries: int = 2
    network: str = "auto"


@dataclass
class ARPControlConfig:
    auto_restore_minutes: int = 0
    spoof_interval: float = 1.0


@dataclass
class PortScannerConfig:
    default_technique: str = "connect"
    max_workers: int = 20
    timeout_per_port: float = 2.0
    rate_limit: int = 0


@dataclass
class CaptureConfig:
    backend: str = "pypcap"
    default_filter: str = ""
    max_buffer_packets: int = 10000


@dataclass
class IDSConfig:
    detect_arp_spoof: bool = True
    detect_new_device: bool = True
    detect_rogue_dhcp: bool = True
    detect_port_scan: bool = True
    detect_mac_flooding: bool = True
    detect_dns_spoofing: bool = False  # off by default, CDN false positives
    port_scan_threshold_ports: int = 10
    port_scan_threshold_seconds: int = 5
    whitelist: list[str] = field(default_factory=list)


@dataclass
class ReportConfig:
    default_format: str = "json"
    include_recommendations: bool = True
    anonymize: bool = False


@dataclass
class GUIConfig:
    theme: str = "dark"
    chart_refresh_ms: int = 1000
    desktop_notifications: bool = True


@dataclass
class AppConfig:
    """Top-level config, mirrors the TOML structure."""
    interface: str = "auto"
    log_level: str = "INFO"
    log_file: str = ""
    data_dir: str = "auto"

    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    arp_control: ARPControlConfig = field(default_factory=ARPControlConfig)
    port_scanner: PortScannerConfig = field(default_factory=PortScannerConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    ids: IDSConfig = field(default_factory=IDSConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    gui: GUIConfig = field(default_factory=GUIConfig)


def _merge_section(target: Any, data: dict[str, Any]) -> None:
    """Overwrite dataclass fields from a dict, skip unknown keys."""
    for key, value in data.items():
        if hasattr(target, key):
            setattr(target, key, value)
        else:
            logger.warning("Unknown config key: %s", key)


def load_config(path: Path | None = None) -> AppConfig:
    """Load config from TOML file. Missing values use defaults."""
    config = AppConfig()

    if path is None:
        # check common locations
        candidates = [
            Path("cuttix.toml"),
            Path.home() / ".config" / "cuttix" / "cuttix.toml",
            Path("/etc/cuttix/cuttix.toml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path is None or not path.exists():
        logger.info("No config file found, using defaults")
        return config

    if tomllib is None:
        raise ConfigError("Python 3.11+ required for TOML support (or install tomli)")

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except Exception as e:
        raise ConfigError(f"Failed to read {path}: {e}") from e

    # top-level keys
    for key in ("interface", "log_level", "log_file", "data_dir"):
        if key in raw.get("general", {}):
            setattr(config, key, raw["general"][key])

    # section keys
    section_map = {
        "scanner": config.scanner,
        "arp_control": config.arp_control,
        "port_scanner": config.port_scanner,
        "capture": config.capture,
        "ids": config.ids,
        "report": config.report,
        "gui": config.gui,
    }
    for section_name, section_obj in section_map.items():
        if section_name in raw:
            _merge_section(section_obj, raw[section_name])

    logger.info("Loaded config from %s", path)
    return config
