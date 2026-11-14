from __future__ import annotations

import pytest

from tainttrail.config import Config
from tainttrail.store import Store


@pytest.fixture(autouse=True)
def _callers_environment_does_not_reach_the_tests(monkeypatch):
    """Tests compare printed text and work in temporary projects.

    A terminal that forces colour, or a TAINTTRAIL_DB left over from trying the README's
    commands, must not change what they see.
    """
    for name in ("FORCE_COLOR", "CLICOLOR_FORCE", "CLICOLOR", "NO_COLOR", "TAINTTRAIL_DB", "TAINTTRAIL_HOME",
                 "TAINTTRAIL_MODE"):
        monkeypatch.delenv(name, raising=False)


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
