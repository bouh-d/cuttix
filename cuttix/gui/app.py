"""GUI entry point — wires EventBus, StateStore, modules, and MainWindow."""
from __future__ import annotations

import logging
import sys
from typing import Any

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from pathlib import Path

from cuttix.config import load_config
from cuttix.core.event_bus import EventBus
from cuttix.gui.main_window import MainWindow
from cuttix.gui.state import StateStore
from cuttix.gui.themes import ThemeManager
from cuttix.utils.logger import setup_logging

logger = logging.getLogger(__name__)


def _build_scanner(iface: str, bus: EventBus) -> Any:
    try:
        from cuttix.modules.scanner import NetworkScanner
        return NetworkScanner(interface=iface, event_bus=bus)
    except Exception as exc:
        logger.warning("Scanner unavailable: %s", exc)
        from cuttix.modules import NullScanner
        return NullScanner()


def _build_arp_controller(iface: str, bus: EventBus) -> Any:
    try:
        from cuttix.modules.arp_control import ARPController
        return ARPController(interface=iface, event_bus=bus)
    except Exception as exc:
        logger.warning("ARP controller unavailable: %s", exc)
        from cuttix.modules import NullARPController
        return NullARPController()


def _build_ids(bus: EventBus, cfg: Any) -> Any:
    try:
        from cuttix.modules.ids import NetworkIDS
        ids = NetworkIDS(event_bus=bus, config=cfg.ids)
        ids.start()
        return ids
    except Exception as exc:
        logger.warning("IDS unavailable: %s", exc)
        return None


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv

    config = load_config()
    setup_logging(level=config.log_level, log_file=config.log_file or None)

    iface = config.interface
    if not iface or iface == "auto":
        from cuttix.utils.network import get_default_interface
        iface = get_default_interface() or "eth0"

    app = QApplication(argv)
    app.setApplicationName("Cuttix")

    theme_pref_path = Path.home() / ".config" / "cuttix" / "ui_state.json"
    theme = ThemeManager(persist_path=theme_pref_path, initial=config.gui.theme)
    app.setStyleSheet(theme.stylesheet())

    bus = EventBus()
    store = StateStore(bus)
    store.connect_bus()

    scanner = _build_scanner(iface, bus)
    arp_ctrl = _build_arp_controller(iface, bus)
    ids = _build_ids(bus, config)

    window = MainWindow(store, arp_ctrl, theme_manager=theme)
    window.show()

    # run an initial scan 500ms after launch so the dashboard populates
    def _first_scan() -> None:
        try:
            scanner.scan()
        except Exception as exc:
            logger.warning("Initial scan failed: %s", exc)
    QTimer.singleShot(500, _first_scan)

    exit_code = app.exec()

    if ids is not None:
        try:
            ids.stop()
        except Exception:
            pass
    store.disconnect_bus()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
