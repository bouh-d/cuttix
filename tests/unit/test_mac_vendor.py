from __future__ import annotations

import csv
from pathlib import Path

import pytest

from cuttix.utils import mac_vendor


@pytest.fixture(autouse=True)
def _reset_cache():
    """Force reload between tests."""
    mac_vendor._loaded = False
    mac_vendor._oui_db = {}
    yield
    mac_vendor._loaded = False
    mac_vendor._oui_db = {}


@pytest.fixture
def mini_oui(tmp_path, monkeypatch):
    """Create a tiny OUI file for testing."""
    oui = tmp_path / "oui.csv"
    oui.write_text(
        "b8:27:eb,Raspberry Pi\n"
        "00:50:56,VMware\n"
        "00:0c:29,VMware\n"
        "ac:de:48,Private\n"
    )
    monkeypatch.setattr(mac_vendor, "_oui_path", lambda: oui)
    return oui


class TestMacVendorLookup:
    def test_known_vendor(self, mini_oui):
        assert mac_vendor.lookup("b8:27:eb:aa:bb:cc") == "Raspberry Pi"

    def test_unknown_mac(self, mini_oui):
        assert mac_vendor.lookup("ff:ff:ff:aa:bb:cc") is None

    def test_case_insensitive(self, mini_oui):
        assert mac_vendor.lookup("B8:27:EB:AA:BB:CC") == "Raspberry Pi"

    def test_dash_separator(self, mini_oui):
        assert mac_vendor.lookup("00-50-56-aa-bb-cc") == "VMware"

    def test_bare_hex(self, mini_oui):
        assert mac_vendor.lookup("000c29aabbcc") == "VMware"

    def test_db_size(self, mini_oui):
        mac_vendor.lookup("anything")  # triggers load
        assert mac_vendor.get_db_size() == 4

    def test_missing_oui_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mac_vendor, "_oui_path", lambda: tmp_path / "nope.csv")
        assert mac_vendor.lookup("b8:27:eb:aa:bb:cc") is None
        assert mac_vendor.get_db_size() == 0
