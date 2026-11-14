"""A thin wrapper around a Relate store.

Relate keeps the whole graph in the memory of the one process that has it open, and a
single-file ``.rl`` store admits exactly one opener at a time. An agent harness runs
every hook as its own short-lived process, and parallel tool calls mean parallel hooks.
So each hook opens the store, does its work in a few milliseconds and closes it, and
the opens are put in a queue: an advisory file lock serialises TaintTrail's own
processes, and a retry loop covers other openers (the ``relate`` CLI, a viewer).
"""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from typing import Any, Iterator

import relate

from .schema import ensure_schema

MEMORY = ":memory:"


class StoreError(RuntimeError):
    """Base class for store failures."""


class StoreLocked(StoreError):
    """The store stayed locked by another process for the whole timeout."""


class StoreMissing(StoreError):
    """A read-only open found no store at the path."""


def to_plain(value: Any) -> Any:
    """Turn Relate graph values into JSON-safe Python values.

    Nodes become ``{"id", "labels", "props"}``, relationships
    ``{"type", "start", "end", "props"}`` and paths ``{"nodes", "rels"}``. Node ids are
    the ``id`` *property* when the node has one (every TaintTrail node does), so the
    result is stable across stores and exports; relationship endpoints use the same ids
    when the relationship arrives as part of a path.
    """
    if isinstance(value, relate.Node):
        props = {k: to_plain(v) for k, v in dict(value.properties).items()}
        return {"id": props.get("id", props.get("key", props.get("name", value.element_id))),
                "labels": list(value.labels), "props": props}
    if isinstance(value, relate.Relationship):
        return {"type": value.type, "start": value.start, "end": value.end,
                "props": {k: to_plain(v) for k, v in dict(value.properties).items()}}
    if isinstance(value, relate.Path):
        nodes = list(value.nodes)
        by_internal = {n.id: to_plain(n)["id"] for n in nodes}
        rels = []
        for r in value.relationships:
            plain = to_plain(r)
            plain["start"] = by_internal.get(r.start, r.start)
            plain["end"] = by_internal.get(r.end, r.end)
            rels.append(plain)
        return {"nodes": [to_plain(n) for n in nodes], "rels": rels}
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class Store:
    """One open of a Relate store. Use it as a context manager and keep it short."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        read_only: bool = False,
        timeout_ms: int = 4_000,
        bootstrap: bool = True,
    ) -> None:
        self.path = os.fspath(path)
        self.read_only = read_only
        self.timeout_ms = timeout_ms
        self.bootstrap = bootstrap and not read_only
        self._conn: relate.Connection | None = None
        self._lock_fd: int | None = None

    # -- lifecycle ----------------------------------------------------------------

    def open(self) -> "Store":
        if self._conn is not None:
            return self
        if self.path == MEMORY:
            self._conn = relate.connect(MEMORY)
            if self.bootstrap:
                ensure_schema(self._conn)
            return self

        deadline = time.monotonic() + self.timeout_ms / 1000.0
        target = Path(self.path)
        if self.read_only and not target.exists():
            raise StoreMissing(f"no TaintTrail graph at {self.path}; nothing has been recorded yet")
        target.parent.mkdir(parents=True, exist_ok=True)
        self._acquire_file_lock(deadline)
        try:
            self._conn = self._connect(deadline)
            if self.bootstrap:
                ensure_schema(self._conn)
        except BaseException:
            self._release_file_lock()
            raise
        return self

    def close(self) -> None:
        conn, self._conn = self._conn, None
        try:
            if conn is not None and not conn.closed:
                conn.close()
        finally:
            self._release_file_lock()

    def __enter__(self) -> "Store":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def conn(self) -> relate.Connection:
        if self._conn is None:
            raise StoreError("store is not open")
        return self._conn

    # -- queries ---------------------------------------------------------------------

    def run(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run one statement and return its rows as plain dicts."""
        cur = self.conn.execute(query, params or {})
        return [{k: to_plain(v) for k, v in dict(row).items()} for row in cur.fetchall()]

    def one(self, query: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        rows = self.run(query, params)
        return rows[0] if rows else None

    def scalar(self, query: str, params: dict[str, Any] | None = None, default: Any = None) -> Any:
        row = self.one(query, params)
        if not row:
            return default
        return next(iter(row.values()))

    def write(self, query: str, params: dict[str, Any] | None = None) -> dict[str, int]:
        """Run one write statement and return its counters."""
        cur = self.conn.execute(query, params or {})
        return dict(cur.stats or {})

    @contextlib.contextmanager
    def transaction(self) -> Iterator["Store"]:
        """Group statements so they commit together or not at all.

        Nested use joins the outer transaction.
        """
        conn = self.conn
        if not conn.autocommit:
            yield self
            return
        conn.autocommit = False
        try:
            yield self
            conn.commit()
        except BaseException:
            with contextlib.suppress(Exception):
                conn.rollback()
            raise
        finally:
            conn.autocommit = True

    @contextlib.contextmanager
    def rehearsal(self) -> Iterator["Store"]:
        """Apply changes, look at the result, then throw the changes away.

        Used for what-if analysis: remove a permission inside the block, re-run the path
        query, and the rollback leaves the stored graph untouched.
        """
        conn = self.conn
        if not conn.autocommit:
            raise StoreError("rehearsal() cannot run inside another transaction")
        conn.autocommit = False
        try:
            yield self
        finally:
            with contextlib.suppress(Exception):
                conn.rollback()
            conn.autocommit = True

    # -- locking ------------------------------------------------------------------------

    def _connect(self, deadline: float) -> relate.Connection:
        delay = 0.01
        while True:
            try:
                return relate.connect(self.path, read_only=self.read_only)
            except relate.Error as exc:
                if "locked" not in str(exc).lower():
                    raise
                if time.monotonic() >= deadline:
                    raise StoreLocked(
                        f"{self.path} is held by another process (waited {self.timeout_ms} ms)"
                    ) from exc
            time.sleep(delay)
            delay = min(delay * 1.6, 0.2)

    def _acquire_file_lock(self, deadline: float) -> None:
        lock_path = self.path + ".lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        delay = 0.005
        while True:
            if _try_lock(fd):
                self._lock_fd = fd
                return
            if time.monotonic() >= deadline:
                os.close(fd)
                raise StoreLocked(f"{self.path} is busy (waited {self.timeout_ms} ms for {lock_path})")
            time.sleep(delay)
            delay = min(delay * 1.6, 0.1)

    def _release_file_lock(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is None:
            return
        with contextlib.suppress(OSError):
            _unlock(fd)
        with contextlib.suppress(OSError):
            os.close(fd)


try:  # POSIX
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

except ImportError:  # pragma: no cover - Windows
    import msvcrt

    def _try_lock(fd: int) -> bool:
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def open_store(cfg, *, read_only: bool = False) -> Store:
    """The store of a project, ready to be used as a context manager."""
    return Store(cfg.db_path, read_only=read_only, timeout_ms=cfg.lock_timeout_ms)
