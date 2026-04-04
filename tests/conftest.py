"""Shared fixtures for all tests."""
from __future__ import annotations

import pytest
from pathlib import Path

from cuttix.core.event_bus import EventBus
from cuttix.db.database import Database


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def tmp_db(tmp_path):
    db = Database(db_path=tmp_path / "test.db")
    db.connect()
    yield db
    db.close()


@pytest.fixture
def memory_db():
    db = Database(db_path=":memory:")
    db.connect()
    yield db
    db.close()
