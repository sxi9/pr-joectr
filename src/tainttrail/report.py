"""Read queries for the command line, and how their results look in a terminal.

Everything a person sees from ``tainttrail status|log|findings|explain`` is produced
here: the queries that read the graph and the plain-text rendering of sessions,
timelines, findings and attack paths.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import textwrap
from typing import Any, Iterable

from . import schema as S
from .model import PathStep
from .store import Store

# -- colour --------------------------------------------------------------------------------

_CODES = {
    "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "gray": "90", "bright_red": "91", "bright_yellow": "93",
}

ROLE_STYLE = {
    "untrusted": ("magenta",), "sensitive": ("cyan",), "destination": ("yellow",), "call": ("bold",),
    "fingerprint": ("gray",), "user": ("green",), "file": (), "entity": (), "content": (),
}
ACTION_STYLE = {"deny": ("bright_red", "bold"), "ask": ("bright_yellow", "bold"), "allow": ("green",)}
ACTION_WORD = {"deny": "DENIED", "ask": "ASKED", "allow": "allowed"}
SEVERITY_STYLE = {"critical": ("bright_red", "bold"), "high": ("red",), "medium": ("yellow",),
                  "low": (), "info": ("gray",)}


def use_color(stream: Any = None) -> bool:
    """Colour when writing to a terminal, or when FORCE_COLOR asks for it. NO_COLOR wins."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(text: str, *styles: str, color: bool = True) -> str:
    if not color or not styles or not text:
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes else text


def _unicode_ok() -> bool:
    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in enc


def printable(value: Any) -> Any:
    """Recorded text as it may be shown on a terminal.

    A command, a prompt or a tool result can hold escape sequences, and whoever wrote the
    content the guard was watching chose them. Printed raw they move the cursor, erase lines
    or repaint the very table that says what was denied. Control and format characters
    (bidirectional overrides and zero-width characters among them) are replaced; line breaks
    and tabs stay.
    """
    if isinstance(value, str):
        if value.isprintable():
            return value
        mark = "\ufffd" if _unicode_ok() else "?"
        return "".join(ch if ch in "\n\t" or ch.isprintable() else mark for ch in value)
    if isinstance(value, dict):
        return {k: printable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(printable(v) for v in value)
    if isinstance(value, PathStep):
        return PathStep(**{k: printable(v) for k, v in vars(value).items()})
    return value


def _ellipsis(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: max(0, width - 1)] + ("…" if _unicode_ok() else "~")


def when(ts: int | None) -> str:
    if not ts:
        return ""
    return _dt.datetime.fromtimestamp(ts / 1000, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# -- queries -------------------------------------------------------------------------------

_Q_SESSIONS = """
MATCH (s:Session)
OPTIONAL MATCH (s)-[:RAN]->(c:ToolCall)
WITH s, count(c) AS calls, sum(CASE WHEN c.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
     sum(CASE WHEN c.decision = 'ask' THEN 1 ELSE 0 END) AS asked
OPTIONAL MATCH (f:Finding {session_id: s.id})
RETURN s.id AS id, s.started_at AS started_at, s.agent_kind AS agent, s.mode AS mode, s.cwd AS cwd,
       calls, denied, asked, count(f) AS findings
ORDER BY started_at DESC, id DESC
"""

_Q_CALLS = """
MATCH (c:ToolCall {session_id: $sid})
OPTIONAL MATCH (c)-[:RETURNED]->(o:Content)
OPTIONAL MATCH (f:Finding)-[:FLAGS]->(c)
WITH c, o, collect(DISTINCT f) AS on_call
OPTIONAL MATCH (g:Finding)-[:FLAGS]->(o)
WITH c, o, on_call, collect(DISTINCT g) AS on_result
WITH c, o, on_call + on_result AS found
WITH c, o, [x IN found WHERE x.action IN ['ask', 'deny'] OR x.intended IN ['ask', 'deny'] OR x.rule = 'TT009' | x.rule] AS rules
RETURN 'call' AS kind, c.seq AS seq, coalesce(c.num, c.seq) AS num, c.id AS id, c.tool AS tool, c.summary AS summary,
       c.decision AS decision, c.status AS status, coalesce(c.is_sink, false) AS is_sink, c.agent AS agent,
       c.ts AS ts, coalesce(o.untrusted, false) AS untrusted, coalesce(o.sensitive, false) AS sensitive,
       coalesce(o.injection_score, 0.0) AS injection, rules
ORDER BY seq
"""

_Q_RECEIVED = """
MATCH (:Session {id: $sid})-[:RECEIVED]->(p:Content)
RETURN CASE p.origin WHEN 'memory' THEN 'memory' WHEN 'attached' THEN 'attached' ELSE 'prompt' END AS kind,
       p.seq AS seq, null AS num, p.id AS id,
       p.origin AS tool, p.excerpt AS summary, 'allow' AS decision, 'done' AS status, false AS is_sink,
       'main' AS agent, p.ts AS ts, coalesce(p.untrusted, false) AS untrusted,
       coalesce(p.sensitive, false) AS sensitive, 0.0 AS injection, [] AS rules
ORDER BY seq
"""

_Q_FINDINGS = """
MATCH (f:Finding)
WHERE ($sid IS NULL OR f.session_id = $sid)
RETURN f.id AS id, f.rule AS rule, f.name AS name, f.severity AS severity, f.action AS action,
       f.intended AS intended, f.title AS title, f.explanation AS explanation, f.session_id AS session_id,
       f.target_id AS target_id, f.target_label AS target_label, f.ts AS ts, f.path_json AS path_json,
       f.query AS query, f.params_json AS params_json
ORDER BY ts DESC, id DESC
"""


def sessions(store: Store) -> list[dict[str, Any]]:
    return store.run(_Q_SESSIONS)


def resolve_session(store: Store, ref: str | None) -> str | None:
    """A session id from an id, a unique prefix of one, ``last`` or nothing (the latest)."""
    rows = sessions(store)
    if not rows:
        return None
    if not ref or ref == "last":
        return rows[0]["id"]
    exact = [r["id"] for r in rows if r["id"] == ref]
    if exact:
        return exact[0]
    matches = [r["id"] for r in rows if r["id"].startswith(ref)]
    return matches[0] if len(matches) == 1 else None


def timeline(store: Store, session_id: str) -> list[dict[str, Any]]:
    """Prompts, inherited memory and tool calls of a session, in order."""
    rows = store.run(_Q_RECEIVED, {"sid": session_id}) + store.run(_Q_CALLS, {"sid": session_id})
    return sorted(rows, key=lambda r: (r["seq"] or 0, r["kind"] != "memory"))


def findings(store: Store, *, session_id: str | None = None, min_severity: str = "info",
             blocking_only: bool = False, limit: int | None = None) -> list[dict[str, Any]]:
    floor = S.SEVERITIES.index(min_severity) if min_severity in S.SEVERITIES else 0
    out = []
    for row in store.run(_Q_FINDINGS, {"sid": session_id}):
        if S.SEVERITIES.index(row["severity"]) < floor if row["severity"] in S.SEVERITIES else False:
            continue
        if blocking_only and row["action"] not in ("ask", "deny") and row["intended"] not in ("ask", "deny"):
            continue
        out.append(_finding_row(row))
        if limit and len(out) >= limit:
            break
    return out


def get_finding(store: Store, ref: str | None) -> dict[str, Any] | None:
    """A finding by id, by unique id suffix or prefix, or the most recent blocking one."""
    rows = [_finding_row(r) for r in store.run(_Q_FINDINGS, {"sid": None})]
    if not rows:
        return None
    if not ref or ref == "last":
        blocking = [r for r in rows if r["action"] in ("ask", "deny") or r["intended"] in ("ask", "deny")]
        return (blocking or rows)[0]
    for row in rows:
        if row["id"] == ref:
            return row
    matches = [r for r in rows if r["id"].startswith(ref) or r["id"].endswith(ref) or r["rule"] == ref.upper()]
    if len(matches) == 1:
        return matches[0]
    if matches and ref.upper() in S_RULE_IDS:
        return matches[0]  # a rule id means its most recent finding
    return None


S_RULE_IDS = frozenset(f"TT{n:03d}" for n in range(1, 100))


def _finding_row(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    try:
        row["path"] = [PathStep(**step) for step in json.loads(row.pop("path_json") or "[]")]
    except (TypeError, ValueError):
        row["path"] = []
    try:
        row["params"] = json.loads(row.pop("params_json") or "{}")
    except ValueError:
        row["params"] = {}
    row["intended"] = row.get("intended") or row["action"]
    return row


def status(store: Store) -> dict[str, Any]:
    rows = sessions(store)
    counts = store.one(
        """
        MATCH (n)
        RETURN sum(CASE WHEN n:ToolCall THEN 1 ELSE 0 END) AS calls,
               sum(CASE WHEN n:ToolCall AND n.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
               sum(CASE WHEN n:ToolCall AND n.decision = 'ask' THEN 1 ELSE 0 END) AS asked,
               sum(CASE WHEN n:Content AND n.untrusted THEN 1 ELSE 0 END) AS untrusted,
               sum(CASE WHEN n:Content AND n.sensitive THEN 1 ELSE 0 END) AS sensitive,
               sum(CASE WHEN n:Finding THEN 1 ELSE 0 END) AS findings,
               sum(CASE WHEN n:Tool THEN 1 ELSE 0 END) AS tools,
               sum(CASE WHEN n:Server THEN 1 ELSE 0 END) AS servers,
               count(n) AS nodes
        """
    ) or {}
    return {"sessions": len(rows), "latest": rows[0] if rows else None, **counts}


# -- rendering -----------------------------------------------------------------------------


def render_path(steps: Iterable[PathStep], *, color: bool = False, decision: str | None = None,
                indent: str = "  ", target: str | None = None) -> str:
    """An attack path, one node per line, with the edge between each pair.

    The arrow points the way the stored edge points, so the diagram reads as evidence:
    ``page MENTIONS host``, ``call SENDS_TO host``.
    """
    steps = printable(list(steps))
    steps = list(steps)
    if not steps:
        return f"{indent}(no path recorded)"
    uni = _unicode_ok()
    down, up, bar = ("▼", "▲", "│") if uni else ("v", "^", "|")
    role_width = max(len(s.role or s.label.lower()) for s in steps)
    lines: list[str] = []
    for step in steps:
        role = step.role or step.label.lower()
        tag = paint(role.ljust(role_width), *ROLE_STYLE.get(role, ()), color=color)
        title = step.title[5:] if role == "call" and step.title.startswith("call ") else step.title
        line = f"{indent}{tag}  {title}"
        # The verdict belongs to the call the finding flags, not to an earlier call on the same path.
        if step.label == S.TOOL_CALL and decision in ("deny", "ask") and (target is None or step.node_id == target):
            line += "   " + paint(ACTION_WORD[decision], *ACTION_STYLE[decision], color=color)
        lines.append(line)
        if step.rel is None:
            continue
        pad = indent + " " * 2
        if not step.rel.isupper():  # shared context, not a stored edge
            lines.append(pad + paint(f"{bar} {step.rel}", "dim", color=color))
        elif step.forward:
            lines.append(pad + paint(f"{bar} {step.rel}", "dim", color=color))
            lines.append(pad + paint(down, "dim", color=color))
        else:
            lines.append(pad + paint(up, "dim", color=color))
            lines.append(pad + paint(f"{bar} {step.rel}", "dim", color=color))
    return "\n".join(lines)


def render_finding(f: dict[str, Any], *, color: bool = False, width: int = 96, show_query: bool = True) -> str:
    """One finding in full: verdict, explanation, path, and the query that found it."""
    f = printable(f)
    action, intended = f["action"], f.get("intended") or f["action"]
    if action == "allow" and intended in ("ask", "deny"):
        verdict = paint(f"would be {ACTION_WORD[intended]}", *ACTION_STYLE[intended], color=color) + \
            paint(" (monitor mode)", "dim", color=color)
    else:
        verdict = paint(ACTION_WORD.get(action, action), *ACTION_STYLE.get(action, ()), color=color)
    head = "  ".join([
        paint(f"{f['rule']} {f['name']}", "bold", color=color),
        paint(f["severity"], *SEVERITY_STYLE.get(f["severity"], ()), color=color),
        verdict,
    ])
    out = [head, paint(f["title"], "bold", color=color), ""]
    out += textwrap.wrap(f["explanation"], width=width) or [""]
    out += ["", paint("Path", "bold", color=color),
            render_path(f.get("path") or [], color=color, decision=intended if intended in ("ask", "deny") else None,
                        target=f.get("target_id") if f.get("target_label") == S.TOOL_CALL else None)]
    if show_query and f.get("query"):
        out += ["", paint("Cypher that found it", "bold", color=color)]
        out += ["  " + line for line in f["query"].strip().splitlines()]
        if f.get("params"):
            out.append(paint("  with " + json.dumps(f["params"], sort_keys=True), "dim", color=color))
    out += ["", paint(f"finding {f['id']}   {when(f.get('ts'))}", "dim", color=color)]
    return "\n".join(out)


def render_findings(rows: list[dict[str, Any]], *, color: bool = False, width: int = 110) -> str:
    rows = printable(rows)
    if not rows:
        return "No findings."
    lines = []
    for f in rows:
        intended = f.get("intended") or f["action"]
        shown = intended if f["action"] == "allow" and intended in ("ask", "deny") else f["action"]
        word = ACTION_WORD.get(shown, shown) + ("*" if shown != f["action"] else "")
        lines.append("  ".join([
            paint(f["rule"], "bold", color=color),
            paint(f["severity"].ljust(8), *SEVERITY_STYLE.get(f["severity"], ()), color=color),
            paint(word.ljust(8), *ACTION_STYLE.get(shown, ()), color=color),
            _ellipsis(f["title"], max(20, width - 34)),
        ]))
        lines.append(paint(f"      {f['id']}", "dim", color=color))
    if any((f.get("intended") or f["action"]) != f["action"] for f in rows):
        lines.append(paint("  * not enforced: the project is in monitor mode or the rule is overridden", "dim", color=color))
    return "\n".join(lines)


def render_timeline(rows: list[dict[str, Any]], *, color: bool = False, width: int = 110) -> str:
    """A session as a table: what entered the context, what was called, what was decided."""
    rows = printable(rows)
    if not rows:
        return "No events recorded for this session."
    what_w = max(24, width - 46)
    lines = [paint(f"{'#':>3}  {'tool':<11} {'what':<{what_w}}  {'brought in':<11} decision", "dim", color=color)]
    for r in rows:
        flags = []
        if r["untrusted"]:
            flags.append(paint("untrusted", *ROLE_STYLE["untrusted"], color=color))
        if r["sensitive"]:
            flags.append(paint("sensitive", *ROLE_STYLE["sensitive"], color=color))
        visible = ("untrusted" if r["untrusted"] else "") + (" " if r["untrusted"] and r["sensitive"] else "") + \
            ("sensitive" if r["sensitive"] else "")
        flag_text = " ".join(flags) + " " * max(0, 11 - len(visible)) if flags else " " * 11
        if r["kind"] == "prompt":
            tool, what = paint(f"{'prompt':<11}", "green", color=color), r["summary"] or ""
        elif r["kind"] == "memory":
            tool, what = paint(f"{'memory':<11}", "magenta", color=color), r["summary"] or ""
        elif r["kind"] == "attached":
            tool, what = paint(f"{'@file':<11}", "green", color=color), r["summary"] or ""
        else:
            name = r["tool"] or ""
            if name.startswith("mcp__"):
                name = name.split("__", 2)[-1]
            tool = f"{_ellipsis(name, 11):<11}"
            what = r["summary"] or ""
            prefix = f"{r['tool']}: "
            if what.startswith(prefix):
                what = what[len(prefix):]
            elif what.startswith(f"{r['tool']} "):
                what = what[len(r["tool"]) + 1:]
        decision = r["decision"] or "allow"
        if decision in ("deny", "ask"):
            verdict = paint(ACTION_WORD[decision], *ACTION_STYLE[decision], color=color)
            if r["rules"]:
                verdict += " " + " ".join(sorted(set(r["rules"])))
        elif r["rules"]:
            verdict = paint("noted " + " ".join(sorted(set(r["rules"]))), "dim", color=color)
        else:
            verdict = ""
        num = str(r["num"]) if r.get("num") else ""
        lines.append(f"{num:>3}  {tool} {_ellipsis(what, what_w):<{what_w}}  {flag_text} {verdict}".rstrip())
    return "\n".join(lines)


def render_sessions(rows: list[dict[str, Any]], *, color: bool = False) -> str:
    rows = printable(rows)
    if not rows:
        return "No sessions recorded yet."
    lines = [paint(f"{'session':<38} {'started':<24} {'calls':>5} {'asked':>5} {'denied':>6} {'findings':>8}",
                   "dim", color=color)]
    for r in rows:
        denied = paint(f"{r['denied']:>6}", *(ACTION_STYLE["deny"] if r["denied"] else ()), color=color)
        asked = paint(f"{r['asked']:>5}", *(ACTION_STYLE["ask"] if r["asked"] else ()), color=color)
        lines.append(f"{_ellipsis(r['id'], 38):<38} {when(r['started_at']):<24} {r['calls']:>5} {asked} {denied} "
                     f"{r['findings']:>8}")
    return "\n".join(lines)
