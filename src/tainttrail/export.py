"""Exports: the graph, or one session of it, as a file someone else can open.

Three formats, one content:

* ``json``   - ``tainttrail-export/1``, what the browser viewer loads;
* ``cypher`` - a seed script any Cypher engine can replay;
* ``rl``     - a standalone Relate store, the session as one evidence file.

An export is meant to be shared, so the home directory is written as ``~`` and nothing
in it is a secret value to begin with: the graph only ever held keyed fingerprints.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__, schema as S
from .config import Config
from .store import Store, StoreMissing, open_store

FORMAT = "tainttrail-export/1"

_NODE = "elementId(n) AS eid, labels(n) AS labels, properties(n) AS props"

# What belongs to one session: the session, what it did, what it read, what was
# concluded, and the part of the capability map its calls touched.
_SESSION_NODE_QUERIES: tuple[str, ...] = (
    f"MATCH (n:Session {{id: $sid}}) RETURN {_NODE}",
    f"MATCH (:Session {{id: $sid}})-[:BY]->(n) RETURN {_NODE}",
    f"MATCH (n:ToolCall {{session_id: $sid}}) RETURN {_NODE}",
    f"MATCH (n:Content {{session_id: $sid}}) RETURN {_NODE}",
    f"MATCH (n:Finding {{session_id: $sid}}) RETURN {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[]->(n:Entity) RETURN DISTINCT {_NODE}",
    f"MATCH (:Content {{session_id: $sid}})-[]->(n:Entity) RETURN DISTINCT {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[]->(:Entity)-[:ON_HOST|DERIVED_FROM]->(n:Entity) RETURN DISTINCT {_NODE}",
    f"MATCH (:Content {{session_id: $sid}})-[]->(:Entity)-[:ON_HOST]->(n:Entity) RETURN DISTINCT {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[:INVOKES]->(n:Tool) RETURN DISTINCT {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[:INVOKES]->(:Tool)-[:HAS_CAPABILITY]->(n) RETURN DISTINCT {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[:INVOKES]->(:Tool)<-[:PROVIDES]-(n:Server) RETURN DISTINCT {_NODE}",
    f"MATCH (:ToolCall {{session_id: $sid}})-[:CARRIES]->(n:Chunk) RETURN DISTINCT {_NODE}",
    f"MATCH (:Finding {{session_id: $sid}})-[:EVIDENCE]->(n) RETURN DISTINCT {_NODE}",
    # Taint that crossed a session boundary: the earlier content and where it came from.
    f"MATCH (:Content {{session_id: $sid}})-[:FROM]->(:Entity)-[:TAINTED_BY]->(n:Content) RETURN DISTINCT {_NODE}",
    f"MATCH (:Content {{session_id: $sid}})-[:FROM]->(:Entity)-[:TAINTED_BY]->(:Content)-[:FROM]->(n:Entity) "
    f"RETURN DISTINCT {_NODE}",
)
_SESSION_ALL_CHUNKS = f"MATCH (:Content {{session_id: $sid}})-[:HAS_CHUNK]->(n:Chunk) RETURN DISTINCT {_NODE}"

_ALL_NODES_LINKED = (
    f"MATCH (n) WHERE NOT n:Meta AND (NOT n:Chunk OR EXISTS {{ MATCH (:ToolCall)-[:CARRIES]->(n) }}) RETURN {_NODE}"
)
_ALL_NODES = f"MATCH (n) WHERE NOT n:Meta RETURN {_NODE}"
_ALL_RELS = "MATCH (a)-[r]->(b) RETURN elementId(a) AS a, elementId(b) AS b, type(r) AS type, properties(r) AS props"

_SESSIONS = """
MATCH (s:Session)
OPTIONAL MATCH (s)-[:RAN]->(c:ToolCall)
WITH s, count(c) AS calls, sum(CASE WHEN c.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
     sum(CASE WHEN c.decision = 'ask' THEN 1 ELSE 0 END) AS asked
OPTIONAL MATCH (f:Finding {session_id: s.id})
RETURN s.id AS id, s.started_at AS started_at, s.agent_kind AS agent, s.mode AS mode,
       calls, denied, asked, count(f) AS findings
ORDER BY started_at DESC, id
"""

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def latest_session(store: Store) -> str | None:
    return store.scalar("MATCH (s:Session) RETURN s.id ORDER BY s.started_at DESC, s.id DESC LIMIT 1")


def export_graph(store: Store, *, session_id: str | None = None, chunks: str = "linked",
                 keep_paths: bool = False, project: str = "") -> dict[str, Any]:
    """The whole graph, or one session with everything needed to explain it.

    ``chunks="linked"`` leaves out fingerprints no tool call ever carried; they are most
    of the nodes and none of the story. ``chunks="all"`` keeps them.
    """
    if chunks not in ("linked", "all"):
        raise ValueError("chunks must be 'linked' or 'all'")
    raw: dict[str, dict[str, Any]] = {}
    if session_id is None:
        for row in store.run(_ALL_NODES if chunks == "all" else _ALL_NODES_LINKED):
            raw[row["eid"]] = row
    else:
        if not store.one("MATCH (s:Session {id: $sid}) RETURN s.id AS id", {"sid": session_id}):
            raise LookupError(f"no session {session_id!r} in the graph")
        queries = _SESSION_NODE_QUERIES + ((_SESSION_ALL_CHUNKS,) if chunks == "all" else ())
        for query in queries:
            for row in store.run(query, {"sid": session_id}):
                if S.META not in row["labels"]:
                    raw.setdefault(row["eid"], row)

    ids: dict[str, str] = {}
    taken: set[str] = set()
    nodes: list[dict[str, Any]] = []
    for eid, row in raw.items():
        labels = [lbl for lbl in row["labels"] if lbl in S.NODE_LABELS] or list(row["labels"])
        props = dict(row["props"])
        if S.CAPABILITY in labels:
            node_id = f"cap:{props.get('name')}"
        else:
            node_id = str(props.get("id") or eid)
        if node_id in taken:  # two labels sharing an id; keep both nodes distinguishable
            node_id = f"{labels[0]}:{node_id}"
        taken.add(node_id)
        ids[eid] = node_id
        nodes.append({"id": node_id, "labels": labels, "props": props})

    rels: list[dict[str, Any]] = []
    for row in store.run(_ALL_RELS):
        if row["a"] in ids and row["b"] in ids:
            rels.append({"type": row["type"], "start": ids[row["a"]], "end": ids[row["b"]],
                         "props": dict(row["props"] or {})})

    nodes.sort(key=lambda n: (n["labels"][0], n["id"]))
    rels.sort(key=lambda r: (r["type"], r["start"], r["end"], json.dumps(r["props"], sort_keys=True)))
    sessions = [s for s in store.run(_SESSIONS) if session_id is None or s["id"] == session_id]
    counts: dict[str, int] = {}
    for n in nodes:
        counts[n["labels"][0]] = counts.get(n["labels"][0], 0) + 1
    export = {
        "meta": {
            "format": FORMAT,
            "exported_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": __version__,
            "project": project,
            "session": session_id,
            "chunks": chunks,
            "sessions": sessions,
            "counts": {"nodes": len(nodes), "rels": len(rels), **counts},
        },
        "nodes": nodes,
        "rels": rels,
    }
    return export if keep_paths else _hide_home(export)


def _hide_home(export: dict[str, Any]) -> dict[str, Any]:
    """Write the home directory as ``~`` everywhere, ids included, so ids still match."""
    home = Path.home().as_posix().rstrip("/")
    if not home or home == "/":
        return export
    pattern = re.compile(re.escape(home) + r"(?=/|$|[\"'\s:])")

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return pattern.sub("~", value) if home in value else value
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(export)


# -- Cypher ------------------------------------------------------------------------------


def cypher_literal(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(cypher_literal(v) for v in value) + "]"
    text = str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    return f"'{text}'"


def _props_literal(props: dict[str, Any]) -> str:
    items = [f"{_ident(k)}: {cypher_literal(v)}" for k, v in sorted(props.items()) if v is not None]
    return "{" + ", ".join(items) + "}" if items else ""


def _ident(name: str) -> str:
    return name if _IDENT.match(name) else "`" + name.replace("`", "``") + "`"


def _match_key(node: dict[str, Any]) -> str:
    """A pattern that finds exactly this node again."""
    label = _ident(node["labels"][0])
    if S.CAPABILITY in node["labels"]:
        return f"(:{label} {{name: {cypher_literal(node['props'].get('name'))}}})"
    return f"(:{label} {{id: {cypher_literal(node['props'].get('id'))}}})"


def to_cypher(export: dict[str, Any]) -> str:
    """A seed script: constraints, then one statement per node and per relationship."""
    lines = [
        f"// {FORMAT} exported {export['meta']['exported_at']} by tainttrail {export['meta']['version']}",
        f"// {export['meta']['counts']['nodes']} nodes, {export['meta']['counts']['rels']} relationships",
    ]
    lines += [statement + ";" for statement in S.DDL]
    by_id = {n["id"]: n for n in export["nodes"]}
    for node in export["nodes"]:
        labels = "".join(f":{_ident(lbl)}" for lbl in node["labels"])
        if S.CAPABILITY in node["labels"]:
            lines.append(f"MERGE ({labels} {_props_literal({'name': node['props'].get('name')})});")
        else:
            lines.append(f"CREATE ({labels} {_props_literal(node['props'])});")
    for rel in export["rels"]:
        a, b = by_id[rel["start"]], by_id[rel["end"]]
        pa = _match_key(a).replace("(:", "(a:", 1)
        pb = _match_key(b).replace("(:", "(b:", 1)
        props = _props_literal(rel["props"])
        lines.append(f"MATCH {pa} MATCH {pb} CREATE (a)-[:{_ident(rel['type'])}{' ' + props if props else ''}]->(b);")
    return "\n".join(lines) + "\n"


# -- standalone store ----------------------------------------------------------------------


def write_rl(export: dict[str, Any], path: str | os.PathLike[str], *, batch: int = 500) -> None:
    """Write the export as its own Relate store: one file, openable with ``relate -d``."""
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"{target} already exists")
    by_id = {n["id"]: n for n in export["nodes"]}
    with Store(target) as store:  # bootstraps the schema and the Capability nodes
        with store.transaction():
            groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
            for node in export["nodes"]:
                if S.CAPABILITY in node["labels"]:
                    continue
                groups.setdefault(tuple(node["labels"]), []).append(node["props"])
            for labels, rows in groups.items():
                label_text = "".join(f":{_ident(lbl)}" for lbl in labels)
                for i in range(0, len(rows), batch):
                    store.write(f"UNWIND $rows AS row CREATE (n{label_text}) SET n = row", {"rows": rows[i:i + batch]})
            rel_groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
            for rel in export["rels"]:
                a, b = by_id[rel["start"]], by_id[rel["end"]]
                ka = "name" if S.CAPABILITY in a["labels"] else "id"
                kb = "name" if S.CAPABILITY in b["labels"] else "id"
                key = (rel["type"], a["labels"][0], ka, b["labels"][0], kb)
                rel_groups.setdefault(key, []).append({"a": a["props"].get(ka), "b": b["props"].get(kb),
                                                       "props": rel["props"]})
            for (rtype, la, ka, lb, kb), rows in rel_groups.items():
                query = (f"UNWIND $rows AS row MATCH (a:{_ident(la)} {{{ka}: row.a}}) "
                         f"MATCH (b:{_ident(lb)} {{{kb}: row.b}}) CREATE (a)-[r:{_ident(rtype)}]->(b) SET r = row.props")
                for i in range(0, len(rows), batch):
                    store.write(query, {"rows": rows[i:i + batch]})


# -- command ---------------------------------------------------------------------------------


def add_export_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session", metavar="ID",
                        help="export one session (an id, or 'last'); default is the whole graph")
    parser.add_argument("--format", choices=("json", "cypher", "rl"), default=None,
                        help="json (default), cypher seed script, or a standalone .rl store; "
                             "inferred from --out when it ends in .json, .cypher or .rl")
    parser.add_argument("--out", "-o", metavar="PATH", help="write here instead of stdout (required for rl)")
    parser.add_argument("--all-chunks", action="store_true",
                        help="keep every content fingerprint, not only those a tool call carried")
    parser.add_argument("--keep-paths", action="store_true",
                        help="keep absolute paths instead of writing the home directory as ~")


def cmd_export(args: argparse.Namespace, cfg: Config) -> int:
    fmt = args.format
    if fmt is None and args.out:
        fmt = {".json": "json", ".cypher": "cypher", ".cql": "cypher", ".rl": "rl"}.get(Path(args.out).suffix.lower())
    fmt = fmt or "json"
    if fmt == "rl" and not args.out:
        print("tainttrail export: --format rl needs --out PATH", file=sys.stderr)
        return 2
    try:
        with open_store(cfg, read_only=True) as store:
            session = args.session
            if session == "last":
                session = latest_session(store)
                if session is None:
                    print("tainttrail export: no sessions recorded yet", file=sys.stderr)
                    return 1
            export = export_graph(store, session_id=session, chunks="all" if args.all_chunks else "linked",
                                  keep_paths=args.keep_paths, project=cfg.root.name)
    except StoreMissing as exc:
        print(f"tainttrail export: {exc}", file=sys.stderr)
        return 1
    except LookupError as exc:
        print(f"tainttrail export: {exc}", file=sys.stderr)
        return 1

    if fmt == "rl":
        try:
            write_rl(export, args.out)
        except FileExistsError as exc:
            print(f"tainttrail export: {exc}", file=sys.stderr)
            return 1
        text = None
    elif fmt == "cypher":
        text = to_cypher(export)
    else:
        text = json.dumps(export, indent=1, sort_keys=True) + "\n"

    if text is not None:
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    if args.out:
        counts = export["meta"]["counts"]
        print(f"wrote {args.out}: {counts['nodes']} nodes, {counts['rels']} relationships", file=sys.stderr)
    return 0
