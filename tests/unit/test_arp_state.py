"""Tests for ARPStateFile — HMAC-signed persistence."""
from __future__ import annotations

import json
import os

import pytest

from cuttix.modules.arp_state import ARPStateFile, SpoofEntry


@pytest.fixture
def state_file(tmp_path):
    secret = b"test-secret-32-bytes-exactly!!!!!"
    return ARPStateFile(state_dir=tmp_path, secret=secret)


def _entry(**overrides) -> SpoofEntry:
    defaults = dict(
        target_ip="192.168.1.50",
        target_mac="aa:bb:cc:dd:ee:ff",
        gateway_ip="192.168.1.1",
        gateway_mac="11:22:33:44:55:66",
        started_at="2025-01-01T12:00:00",
    )
    defaults.update(overrides)
    return SpoofEntry(**defaults)


class TestARPStateFileBasic:
    def test_save_and_load(self, state_file):
        entries = [_entry()]
        state_file.save(entries)

        loaded = state_file.load()
        assert loaded is not None
        assert len(loaded) == 1
        assert loaded[0].target_ip == "192.168.1.50"
        assert loaded[0].target_mac == "aa:bb:cc:dd:ee:ff"

    def test_multiple_entries(self, state_file):
        entries = [
            _entry(target_ip="192.168.1.50"),
            _entry(target_ip="192.168.1.51", target_mac="aa:bb:cc:dd:ee:00"),
        ]
        state_file.save(entries)

        loaded = state_file.load()
        assert len(loaded) == 2
        ips = {e.target_ip for e in loaded}
        assert ips == {"192.168.1.50", "192.168.1.51"}

    def test_empty_list_removes_file(self, state_file):
        state_file.save([_entry()])
        assert state_file.exists()

        state_file.save([])
        # empty list writes the file (it's still valid)
        loaded = state_file.load()
        assert loaded is not None
        assert len(loaded) == 0

    def test_load_nonexistent(self, state_file):
        assert state_file.load() is None

    def test_remove(self, state_file):
        state_file.save([_entry()])
        assert state_file.exists()
        state_file.remove()
        assert not state_file.exists()

    def test_auto_restore_field(self, state_file):
        entries = [_entry(auto_restore_at="2025-01-01T13:00:00")]
        state_file.save(entries)

        loaded = state_file.load()
        assert loaded[0].auto_restore_at == "2025-01-01T13:00:00"

    def test_auto_restore_none(self, state_file):
        entries = [_entry(auto_restore_at=None)]
        state_file.save(entries)

        loaded = state_file.load()
        assert loaded[0].auto_restore_at is None


class TestARPStateFileIntegrity:
    def test_tampered_payload_rejected(self, state_file):
        state_file.save([_entry()])

        # tamper with the file
        raw = state_file.path.read_text()
        payload, sig = raw.strip().rsplit("|", 1)
        # flip a character
        tampered = payload.replace("192.168.1.50", "192.168.1.99")
        state_file.path.write_text(f"{tampered}|{sig}\n")

        loaded = state_file.load()
        assert loaded is None  # rejected
        assert not state_file.exists()  # cleaned up

    def test_tampered_hmac_rejected(self, state_file):
        state_file.save([_entry()])

        raw = state_file.path.read_text()
        payload, _ = raw.strip().rsplit("|", 1)
        state_file.path.write_text(f"{payload}|{'0' * 64}\n")

        loaded = state_file.load()
        assert loaded is None

    def test_corrupt_json_rejected(self, state_file):
        state_file.path.write_text("not json|" + "a" * 64 + "\n")
        loaded = state_file.load()
        assert loaded is None

    def test_missing_separator_rejected(self, state_file):
        state_file.path.write_text("no separator here\n")
        loaded = state_file.load()
        assert loaded is None

    def test_different_secret_cant_read(self, tmp_path):
        sf1 = ARPStateFile(state_dir=tmp_path, secret=b"secret-aaaaaaaaaaaaaaaaaaaaaaaaa")
        sf1.save([_entry()])

        sf2 = ARPStateFile(state_dir=tmp_path, secret=b"secret-bbbbbbbbbbbbbbbbbbbbbbbbb")
        loaded = sf2.load()
        assert loaded is None


class TestARPStateFileAtomic:
    def test_save_is_atomic(self, state_file):
        """After save, the file should be consistent."""
        state_file.save([_entry()])
        loaded = state_file.load()
        assert loaded is not None

        # save again with different data
        state_file.save([_entry(target_ip="10.0.0.1")])
        loaded = state_file.load()
        assert loaded[0].target_ip == "10.0.0.1"
