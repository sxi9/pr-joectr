from __future__ import annotations

import pytest

from tainttrail.config import Config
from tainttrail.store import Store


@pytest.fixture()
def cfg(tmp_path, monkeypatch) -> Config:
    """A project config rooted in a fresh temporary directory."""
    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.delenv("TAINTTRAIL_DB", raising=False)
    monkeypatch.delenv("TAINTTRAIL_MODE", raising=False)
    monkeypatch.setenv("TAINTTRAIL_KEY", "test-key-not-a-secret")
    root = tmp_path / "project"
    root.mkdir()
    return Config(root=root, home=root / ".tainttrail")


@pytest.fixture()
def store(cfg) -> Store:
    """An open store on a real ``.rl`` file inside the temporary project."""
    s = Store(cfg.db_path, timeout_ms=cfg.lock_timeout_ms)
    s.open()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def mem() -> Store:
    """An open in-memory store with the schema applied."""
    s = Store(":memory:")
    s.open()
    try:
        yield s
    finally:
        s.close()
