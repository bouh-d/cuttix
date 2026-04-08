"""Tests for the GUI ThemeManager (no Qt required)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cuttix.gui.themes import (
    DARK_QSS,
    LIGHT_QSS,
    THEMES,
    ThemeManager,
    ThemePalette,
)


class TestDefaults:
    def test_default_is_dark(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json")
        assert tm.current == "dark"
        assert tm.stylesheet() == DARK_QSS

    def test_initial_overrides_default(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json", initial="light")
        assert tm.current == "light"
        assert tm.stylesheet() == LIGHT_QSS

    def test_unknown_initial_falls_back(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json", initial="bogus")
        assert tm.current == "dark"


class TestToggle:
    def test_toggle_dark_to_light(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json", initial="dark")
        tm.toggle()
        assert tm.current == "light"

    def test_toggle_round_trip(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json", initial="dark")
        tm.toggle()
        tm.toggle()
        assert tm.current == "dark"


class TestSetTheme:
    def test_set_theme_explicit(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json")
        tm.set_theme("light")
        assert tm.current == "light"

    def test_set_unknown_raises(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json")
        with pytest.raises(ValueError):
            tm.set_theme("solarized")


class TestPersistence:
    def test_set_theme_writes_file(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "ui.json"
        tm = ThemeManager(persist_path=path)
        tm.set_theme("light")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["theme"] == "light"

    def test_loads_persisted_theme_on_init(self, tmp_path: Path) -> None:
        path = tmp_path / "ui.json"
        path.write_text(json.dumps({"theme": "light"}))
        tm = ThemeManager(persist_path=path)
        assert tm.current == "light"

    def test_corrupt_file_falls_back(self, tmp_path: Path) -> None:
        path = tmp_path / "ui.json"
        path.write_text("not json at all")
        tm = ThemeManager(persist_path=path, initial="dark")
        assert tm.current == "dark"

    def test_no_path_skips_persistence(self) -> None:
        tm = ThemeManager(persist_path=None, initial="dark")
        # should not raise
        tm.set_theme("light")
        tm2 = ThemeManager(persist_path=None)
        assert tm2.current == "dark"


class TestPalette:
    def test_dark_palette_keys(self) -> None:
        p = ThemePalette.for_theme("dark")
        assert "bg" in p and "accent" in p

    def test_light_palette_differs(self) -> None:
        d = ThemePalette.for_theme("dark")
        light = ThemePalette.for_theme("light")
        assert d["bg"] != light["bg"]

    def test_theme_manager_palette_matches_current(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json", initial="light")
        assert tm.palette() == ThemePalette.LIGHT


class TestRegistry:
    def test_themes_registry_has_both(self) -> None:
        assert set(THEMES.keys()) >= {"dark", "light"}

    def test_available_returns_list(self, tmp_path: Path) -> None:
        tm = ThemeManager(persist_path=tmp_path / "ui.json")
        assert "dark" in tm.available()
        assert "light" in tm.available()
