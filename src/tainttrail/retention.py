"""Keeping the live graph small.

Relate loads a store into memory when it is opened and writes it back when it is closed,
and the guard does both for every hook event. Measured on recorded sessions that costs
about 45 ms per thousand nodes, so the graph the rules work on has to stay small, however
long a project has been guarded.

Sessions are the unit. Once the recorded sessions pass the budget (``max_live_nodes``),
the oldest ones are written to archive files and removed from the live graph, sessions in
which nothing was held first. An archive file is an export, the format ``tainttrail ui``
and ``tainttrail export`` already use, so an archived session can still be opened and
queried. The current session and the two before it always stay.

What later sessions depend on also stays: the flags on entities (trusted, untrusted,
sensitive), the content that tainted a file (the target of ``TAINTED_BY``), derivation
edges between entities, tool labels and the capability map. The rules themselves only
ever look at the current session plus those.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable

from .config import Config
from .store import Store

ARCHIVE_DIRNAME = "archive"
KEEP_RECENT = 2          # sessions besides the current one that are never archived
PRUNE_TO = 0.6           # archive until the graph is this fraction of the budget

_SESSIONS = """
MATCH (s:Session)
RETURN s.id AS id, coalesce(s.started_at, 0) AS started,
       EXISTS { MATCH (f:Finding {session_id: s.id}) WHERE f.action IN ['ask', 'deny'] } AS held
ORDER BY started, id
"""

# One session's own nodes. Content that tainted a file is kept: it is the evidence a later
# session's inherited-taint finding points at.
_DROP_SESSION = (
    "MATCH (f:Finding {session_id: $sid}) DETACH DELETE f",
    "MATCH (c:ToolCall {session_id: $sid}) DETACH DELETE c",
    """
    MATCH (c:Content {session_id: $sid})
    WHERE NOT EXISTS { MATCH (:Entity)-[:TAINTED_BY]->(c) }
    DETACH DELETE c
    """,
    "MATCH (s:Session {id: $sid}) DETACH DELETE s",
)

# What no remaining node refers to any more. A link whose only edge goes to its host counts.
_DROP_ORPHANS = (
    "MATCH (k:Chunk) WHERE NOT EXISTS { MATCH (:Content)-[:HAS_CHUNK]->(k) } DETACH DELETE k",
    """
    MATCH (e:Entity {kind: 'url'})
    WHERE NOT EXISTS { MATCH (e)-[r]-() WHERE type(r) <> 'ON_HOST' }
      AND NOT coalesce(e.untrusted, false) AND NOT coalesce(e.trusted, false) AND NOT coalesce(e.sensitive, false)
    DETACH DELETE e
    """,
    """
    MATCH (e:Entity)
    WHERE NOT EXISTS { MATCH (e)--() }
      AND NOT coalesce(e.untrusted, false) AND NOT coalesce(e.trusted, false) AND NOT coalesce(e.sensitive, false)
      AND NOT coalesce(e.reviewed, false)
    DELETE e
    """,
)


def archive_dir(cfg: Config) -> Path:
    return cfg.home / ARCHIVE_DIRNAME


def archived(cfg: Config) -> list[Path]:
    """The archive files of a project, oldest first."""
    try:
        return sorted(p for p in archive_dir(cfg).iterdir() if p.suffix == ".json")
    except OSError:
        return []


def live_nodes(store: Store) -> int:
    """How many nodes recorded sessions account for. The capability map is not counted:
    it does not grow with use, and archiving sessions would not shrink it."""
    return int(store.scalar(
        "MATCH (n) WHERE n:Session OR n:ToolCall OR n:Content OR n:Entity OR n:Chunk OR n:Finding RETURN count(n)",
        default=0) or 0)


def prune(store: Store, cfg: Config, *, keep: Iterable[str] = (), budget: int | None = None,
          seconds: float = 3.0) -> list[dict[str, Any]]:
    """Archive the oldest sessions while the graph is over budget.

    Returns one record per archived session: ``{"id", "started", "file", "held"}``. Does
    nothing when the budget is 0 (keep everything) or the graph is within it. Call it
    inside the caller's transaction, so a session is never half removed. After ``seconds``
    it stops with what it has done, because it runs inside a hook that has a time limit.
    """
    budget = cfg.max_live_nodes if budget is None else budget
    if budget <= 0:
        return []
    total = live_nodes(store)
    if total <= budget:
        return []
    sessions = store.run(_SESSIONS)
    current = set(keep)
    others = [s for s in sessions if s["id"] not in current]
    candidates = others[: max(0, len(others) - KEEP_RECENT)]
    # Sessions in which the guard held nothing go first; incidents are kept as long as there is room.
    candidates.sort(key=lambda s: (bool(s["held"]), s["started"], s["id"]))
    done: list[dict[str, Any]] = []
    target = int(budget * PRUNE_TO)
    started = time.monotonic()
    for session in candidates:
        if total <= target:
            break
        if done and time.monotonic() - started > seconds:
            break   # the hook has a time limit; the next session start carries on
        file = _archive(store, cfg, session)
        for statement in _DROP_SESSION:
            store.write(statement, {"sid": session["id"]})
        for statement in _DROP_ORPHANS:
            store.write(statement)
        done.append({"id": session["id"], "started": session["started"], "held": bool(session["held"]), "file": str(file)})
        total = live_nodes(store)
    if done:
        store.write(
            "MERGE (m:Meta {key: 'archive'}) SET m.sessions = coalesce(m.sessions, 0) + $n, m.last_at = $at",
            {"n": len(done), "at": int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1000)},
        )
    return done


def _archive(store: Store, cfg: Config, session: dict[str, Any]) -> Path:
    """Write one session as an export file that only its owner can read."""
    from .export import export_graph   # imported late: export imports the store, and so does this

    export = export_graph(store, session_id=session["id"], chunks="linked", keep_paths=True,
                          project=cfg.root.name, root=cfg.root)
    export["meta"]["archived"] = True
    started = _dt.datetime.fromtimestamp((session["started"] or 0) / 1000, _dt.timezone.utc)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(session["id"]))[:48]
    directory = archive_dir(cfg)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{started:%Y%m%dT%H%M%SZ}-{safe}.json"
    temp = target.with_name(target.name + f".tmp-{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(export, fh, separators=(",", ":"))
    os.replace(temp, target)
    return target
