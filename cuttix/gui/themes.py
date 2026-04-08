"""Theme manager — dark/light QSS pair + persistence helper.

The two stylesheets share the same selectors so toggling never leaves
half-styled widgets behind. The currently chosen theme is stored as
JSON in the user's data dir so it survives across sessions, and falls
back to the value from ``cuttix.toml`` (gui.theme) on first launch.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from cuttix.gui.style import DARK_QSS

logger = logging.getLogger(__name__)


LIGHT_QSS = """
* {
    font-family: "Segoe UI", "SF Pro Display", "Inter", sans-serif;
    font-size: 10pt;
    color: #1c1f24;
}

QMainWindow, QWidget {
    background-color: #f4f5f7;
}

QLabel {
    color: #1c1f24;
}

#legalDisclaimer {
    color: #b35900;
    font-size: 9pt;
    padding: 8px;
    border: 1px solid #e0a458;
    border-radius: 4px;
    background-color: #fff6e6;
}

QFrame#kpiCard {
    background-color: #ffffff;
    border: 1px solid #d8dce3;
    border-radius: 8px;
    min-height: 80px;
}
QLabel#kpiValue {
    font-size: 28pt;
    font-weight: 600;
    color: #1c1f24;
}
QLabel#kpiTitle {
    font-size: 9pt;
    color: #6c7480;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f4f5f7;
    gridline-color: #e3e6ec;
    border: 1px solid #d8dce3;
    selection-background-color: #2c7be5;
    selection-color: #ffffff;
}
QTableWidget::item {
    padding: 6px;
}
QHeaderView::section {
    background-color: #eef0f4;
    color: #4a5260;
    padding: 8px;
    border: none;
    border-right: 1px solid #d8dce3;
    border-bottom: 1px solid #d8dce3;
    font-weight: 600;
}

QPushButton {
    background-color: #2c7be5;
    color: #ffffff;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #1f63bc;
}
QPushButton:pressed {
    background-color: #174d92;
}
QPushButton:disabled {
    background-color: #c8ccd4;
    color: #7a8290;
}

QLineEdit {
    background-color: #ffffff;
    border: 1px solid #d8dce3;
    padding: 6px 10px;
    border-radius: 4px;
    color: #1c1f24;
}
QLineEdit:focus {
    border-color: #2c7be5;
}

QGroupBox {
    border: 1px solid #d8dce3;
    border-radius: 6px;
    padding: 12px;
    margin-top: 12px;
    color: #4a5260;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}

QListWidget {
    background-color: #ffffff;
    border: 1px solid #d8dce3;
    border-radius: 4px;
}
QListWidget::item {
    padding: 8px;
}
QListWidget::item:selected {
    background-color: #2c7be5;
    color: #ffffff;
}

QStatusBar {
    background-color: #eef0f4;
    color: #4a5260;
    border-top: 1px solid #d8dce3;
}

QListWidget#sidebar {
    background-color: #ffffff;
    border: none;
    border-right: 1px solid #d8dce3;
    padding: 8px 0;
    font-size: 11pt;
}
QListWidget#sidebar::item {
    padding: 12px 20px;
    border-left: 3px solid transparent;
    color: #4a5260;
}
QListWidget#sidebar::item:selected {
    background-color: #eef0f4;
    border-left: 3px solid #2c7be5;
    color: #1c1f24;
}
QListWidget#sidebar::item:hover {
    background-color: #f4f5f7;
}
"""


THEMES: dict[str, str] = {"dark": DARK_QSS, "light": LIGHT_QSS}


class ThemePalette:
    """Hex colors that don't belong in QSS (used by custom-painted widgets)."""

    DARK = {
        "bg": "#1e1e24",
        "bg_alt": "#2a2a32",
        "fg": "#ecf0f1",
        "fg_muted": "#95a5a6",
        "accent": "#3498db",
        "grid": "#3a3a44",
        "warn": "#f39c12",
        "danger": "#e74c3c",
        "ok": "#27ae60",
    }
    LIGHT = {
        "bg": "#f4f5f7",
        "bg_alt": "#ffffff",
        "fg": "#1c1f24",
        "fg_muted": "#6c7480",
        "accent": "#2c7be5",
        "grid": "#d8dce3",
        "warn": "#b35900",
        "danger": "#c0392b",
        "ok": "#1e7e34",
    }

    @classmethod
    def for_theme(cls, name: str) -> dict[str, str]:
        return cls.LIGHT if name == "light" else cls.DARK


class ThemeManager:
    """Holds the active theme name and persists it across launches."""

    DEFAULT = "dark"

    def __init__(self, persist_path: Path | None = None, initial: str | None = None) -> None:
        self._path = Path(persist_path) if persist_path else None
        loaded = self._load()
        self._current = loaded or initial or self.DEFAULT
        if self._current not in THEMES:
            self._current = self.DEFAULT

    @property
    def current(self) -> str:
        return self._current

    def stylesheet(self, name: str | None = None) -> str:
        return THEMES.get(name or self._current, DARK_QSS)

    def palette(self, name: str | None = None) -> dict[str, str]:
        return ThemePalette.for_theme(name or self._current)

    def set_theme(self, name: str) -> str:
        if name not in THEMES:
            raise ValueError(f"unknown theme: {name}")
        self._current = name
        self._save()
        return name

    def toggle(self) -> str:
        return self.set_theme("light" if self._current == "dark" else "dark")

    def available(self) -> list[str]:
        return list(THEMES.keys())

    # -- persistence --

    def _load(self) -> str | None:
        if self._path is None or not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            name = data.get("theme")
            if isinstance(name, str) and name in THEMES:
                return name
        except Exception as exc:
            logger.warning("Failed to load theme preference: %s", exc)
        return None

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps({"theme": self._current}), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to persist theme preference: %s", exc)
