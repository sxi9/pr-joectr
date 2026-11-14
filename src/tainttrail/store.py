"""A thin wrapper around a Relate store.

Relate keeps the whole graph in the memory of the one process that has it open, and a
single-file ``.rl`` store admits exactly one opener at a time. An agent harness runs
every hook as its own short-lived process, and parallel tool calls mean parallel hooks.
So each hook opens the store, does its work in a few milliseconds and closes it, and
the opens are put in a queue: an advisory file lock serialises TaintTrail's own
processes, and a retry loop covers other openers (the ``relate`` CLI, a viewer).

A hook can be killed at any moment: by its timeout, by the user interrupting the agent,
by the machine. A store that is being written in place when that happens can be left in
a state the engine refuses to open, and a guard whose store does not open lets every
call through. So a writer never touches the live file. It works on a private copy and
publishes it with a rename when the engine has closed it cleanly, which is atomic: a
kill leaves the live file as it was. The version before the last publish is kept next
to it, and a live file that does not open (damaged from outside, or by a crash of the
machine) is set aside and replaced by that version, or by a new graph.
"""

from __future__ import annotations

import contextlib
import glob
import os
import shutil
import time
from pathlib import Path
from typing import Any, Iterator

import relate

from .schema import ensure_schema

MEMORY = ":memory:"
SINGLE_FILE = ".rl"           # the extension tells Relate to keep the store in one file
STALE_WORK_SECONDS = 120


class StoreError(RuntimeError):
    """Base class for store failures."""


class StoreLocked(StoreError):
    """The store stayed locked by another process for the whole timeout."""


class StoreMissing(StoreError):
    """A read-only open found no store at the path."""


class StoreDamaged(StoreError):
    """The store file exists and the engine cannot open it."""


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
        self._work: str | None = None
        # Side files of a single-file store "graph.rl": a writer's private copy
        # "graph.work-<pid>.rl", the version before the last publish "graph.prev.rl", and a
        # live file that did not open "graph.damaged-<utc time>.rl". They keep the extension
        # because Relate chooses single-file mode by it. A directory store is written in place.
        self._base = self.path[: -len(SINGLE_FILE)] if self.path.endswith(SINGLE_FILE) else None
        # Set when this open found the live file damaged: what was set aside, what replaced it.
        self.recovered: dict[str, str] | None = None

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
        if not target.parent.exists():
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._acquire_file_lock(deadline)
        try:
            if self.read_only:
                self._conn = self._connect_read_only(deadline)
            else:
                self._conn = self._connect_for_write(deadline)
                if self.bootstrap:
                    ensure_schema(self._conn)
                    self._note_recovery()
        except BaseException:
            self._drop_connection()
            self._discard_work()
            self._release_file_lock()
            raise
        return self

    def close(self) -> None:
        conn, self._conn = self._conn, None
        try:
            if conn is not None and not conn.closed:
                conn.close()
            if self._work is not None and conn is not None:
                self._publish()
        finally:
            self._discard_work()
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

    def _connect(self, path: str, deadline: float, *, read_only: bool) -> relate.Connection:
        delay = 0.01
        while True:
            try:
                return relate.connect(path, read_only=read_only)
            except relate.Error as exc:
                if "locked" not in str(exc).lower():
                    raise
                if time.monotonic() >= deadline:
                    raise StoreLocked(
                        f"{self.path} is held by another process (waited {self.timeout_ms} ms)"
                    ) from exc
            time.sleep(delay)
            delay = min(delay * 1.6, 0.2)

    def _connect_read_only(self, deadline: float) -> relate.Connection:
        try:
            return self._connect(self.path, deadline, read_only=True)
        except BaseException as exc:
            if not _engine_failure(exc):
                raise
            problem = _engine_problem()
            if problem is not None:
                raise StoreError(f"the Relate engine does not start ({problem}); the graph at {self.path} "
                                 "was not touched") from exc
            raise StoreDamaged(
                f"{self.path} cannot be opened ({_first_line(exc)}). The next recorded event, or "
                "`tainttrail doctor`, sets the file aside and continues from the version before it."
            ) from exc

    # -- writing without touching the live file -------------------------------------------

    @property
    def previous_path(self) -> str | None:
        """Where the version before the last publish is kept (single-file stores only)."""
        return None if self._base is None else f"{self._base}.prev{SINGLE_FILE}"

    def _connect_for_write(self, deadline: float) -> relate.Connection:
        """Open a private copy of the store; ``close`` publishes it. Called with the lock held."""
        if self._base is None:
            return self._connect(self.path, deadline, read_only=False)
        self._sweep_stale_work()
        work = f"{self._base}.work-{os.getpid()}{SINGLE_FILE}"
        self._work = work
        prev = f"{self._base}.prev{SINGLE_FILE}"
        if not os.path.exists(self.path):
            _remove(prev)   # the graph was deleted on purpose: its older version goes with it
            return self._connect(work, deadline, read_only=False)
        _copy_private(self.path, work)
        try:
            return self._connect(work, deadline, read_only=False)
        except BaseException as exc:
            if not _engine_failure(exc):
                raise
            error = _first_line(exc)
        _remove(work)
        # A refusal is not proof of damage. The engine also refuses every store, a new one
        # included, when its environment is wrong (an unknown RELATE_* variable, for one). Then
        # the graph is fine and must be left exactly where it is.
        problem = _engine_problem()
        if problem is not None:
            self._work = None
            raise StoreError(f"the Relate engine does not start ({problem}); the graph at {self.path} was not touched")
        # The engine works and this file does not open. Set it aside; continue from the version
        # before it if that one opens, and from an empty graph if not. Nothing is deleted.
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        damaged = f"{self._base}.damaged-{stamp}{SINGLE_FILE}"
        os.replace(self.path, damaged)
        self.recovered = {"damaged": damaged, "error": error, "restored": "empty"}
        if os.path.exists(prev):
            _copy_private(prev, work)
            try:
                conn = self._connect(work, deadline, read_only=False)
                self.recovered["restored"] = "previous"
                return conn
            except BaseException as exc:
                if not _engine_failure(exc):
                    raise
                _remove(work)
                os.replace(prev, f"{self._base}.damaged-{stamp}-previous{SINGLE_FILE}")
        return self._connect(work, deadline, read_only=False)

    def _publish(self) -> None:
        """Make the cleanly closed private copy the live file, keeping the version it replaces."""
        work, self._work = self._work, None
        if work is None:
            return
        if os.path.exists(self.path):
            prev = f"{self._base}.prev{SINGLE_FILE}"
            link = f"{self._base}.prev-{os.getpid()}{SINGLE_FILE}"
            try:
                os.link(self.path, link)
                os.replace(link, prev)
            except OSError:   # no hard links here: go on without a previous version
                _remove(link)
        os.replace(work, self.path)

    def _discard_work(self) -> None:
        work, self._work = self._work, None
        if work is not None:
            _remove(work)

    def _drop_connection(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

    def _sweep_stale_work(self) -> None:
        """Remove private copies and half-made links that a killed writer left behind."""
        base = glob.escape(self._base or self.path)
        leftovers = glob.glob(f"{base}.work-*{SINGLE_FILE}") + glob.glob(f"{base}.prev-*{SINGLE_FILE}")
        for path in leftovers:
            try:
                pid = int(path[: -len(SINGLE_FILE)].rsplit("-", 1)[-1])
            except ValueError:
                pid = 0
            try:
                fresh = time.time() - os.path.getmtime(path) < STALE_WORK_SECONDS
            except OSError:
                continue
            if pid != os.getpid() and fresh and _alive(pid):
                continue   # only possible where the file lock does not work; leave it alone
            _remove(path)

    def _note_recovery(self) -> None:
        """Leave a record in the graph when this open had to set a damaged file aside."""
        if not self.recovered or self._conn is None:
            return
        self._conn.execute(
            "MERGE (m:Meta {key: 'recovered'}) "
            "SET m.at = $at, m.damaged = $damaged, m.error = $error, m.restored = $restored, "
            "    m.count = coalesce(m.count, 0) + 1",
            {"at": int(time.time() * 1000), **self.recovered},
        )

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


def _engine_failure(exc: BaseException) -> bool:
    """Whether an exception is the engine refusing a file (an engine panic is not an ``Exception``)."""
    return isinstance(exc, relate.Error) or type(exc).__name__ == "PanicException"


def _engine_problem() -> str | None:
    """Why the engine cannot open even an empty in-memory store, or None when it can."""
    try:
        relate.connect(MEMORY).close()
    except BaseException as exc:
        if not _engine_failure(exc):
            raise
        return _first_line(exc)
    return None


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip().splitlines()
    return (text[0] if text else type(exc).__name__)[:300]


def _remove(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


def _copy_private(src: str, dst: str) -> None:
    """Copy a store file to a new file only its owner can read."""
    _remove(dst)
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    shutil.copyfile(src, dst)


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def open_store(cfg, *, read_only: bool = False) -> Store:
    """The store of a project, ready to be used as a context manager."""
    return Store(cfg.db_path, read_only=read_only, timeout_ms=cfg.lock_timeout_ms)
