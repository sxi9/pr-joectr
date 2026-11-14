"""Detection rules.

Every rule asks the graph a path question about one tool call. The path a rule finds is
both the evidence and the explanation: it is stored on the finding together with the
Cypher that produced it, so anyone can re-run it.

The rules look for three things at once, the conditions under which an agent can be
made to leak:

* untrusted content, which a third party could have written, is in the session;
* sensitive data is in reach, and there is evidence it is in the outgoing call;
* the call sends data somewhere it can be read from outside.

Evidence is concrete. A ``CARRIES`` edge means the arguments of the call contain a
keyed fingerprint of text that was seen in sensitive content. A destination is
"injected" when untrusted content named it and nothing the user typed or any trusted
content did.
"""

from __future__ import annotations


import json
import re
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

from . import schema as S
from .config import Config
from .extract import fingerprint
from .model import CallAnalysis, ContentAnalysis, Finding, PathStep
from .store import Store

# One fingerprint of a secret or a long token is evidence on its own. Lines of text
# repeat by coincidence, so it takes several.
MIN_LINE_CHUNKS = 3
INJECTION_WARN_SCORE = 0.5
# Below this, content that merely mentions a file or a command is treated as documentation.
LIKELY_INJECTION = 0.3


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    default_action: str
    title: str
    when: str  # "pre" | "post"


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule("TT001", "exfil.confirmed", "critical", "deny",
             "Sensitive data would leave the machine while untrusted content is in the session", "pre"),
        Rule("TT002", "trifecta.complete", "medium", "ask",
             "Untrusted content, sensitive data and an outbound call meet in one session", "pre"),
        Rule("TT003", "dest.injected", "high", "ask",
             "Data would go to a destination that only untrusted content named", "pre"),
        Rule("TT004", "read.steered", "high", "ask",
             "Untrusted content pointed the agent at a sensitive file", "pre"),
        Rule("TT005", "persist.tainted", "high", "ask",
             "An instruction or autorun file would be written under untrusted influence", "pre"),
        Rule("TT006", "leak.sensitive_egress", "high", "ask",
             "Sensitive data would leave the machine", "pre"),
        Rule("TT007", "exec.injected", "critical", "deny",
             "Code named by untrusted content would be downloaded and run", "pre"),
        Rule("TT008", "taint.inherited", "info", "allow",
             "Content came from a file an earlier session wrote under untrusted influence", "post"),
        Rule("TT009", "injection.suspected", "medium", "allow",
             "A tool result reads like instructions aimed at the agent", "post"),
        Rule("TT010", "guard.tamper", "high", "ask",
             "The guard's own files or hook registration would be changed", "pre"),
        Rule("TT011", "scope.crossed", "high", "ask",
             "Private data read from one repository would be written to another", "pre"),
    )
}

# -- the path queries -------------------------------------------------------------------
# Parameters: $call is the ToolCall id, $dest an Entity id, $content a Content id.

CYPHER: dict[str, str] = {
    # untrusted content -> destination <- call -> fingerprint <- sensitive content
    "TT001.carry.injected": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})
          <-[:SENDS_TO]-(c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)
          <-[:HAS_CHUNK]-(s:Content {sensitive: true})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END, u.seq, k.id
LIMIT 1""",
    # untrusted content -> destination <- call -> uploaded sensitive file
    "TT001.upload.injected": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})
          <-[:SENDS_TO]-(c:ToolCall {id: $call})-[:UPLOADS]->(f:Entity {sensitive: true})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # destination <- call -> fingerprint <- sensitive content
    "egress.carry": """
MATCH p = (d:Entity {id: $dest})<-[:SENDS_TO]-(c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)
          <-[:HAS_CHUNK]-(s:Content {sensitive: true})
RETURN p
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END, k.id
LIMIT 1""",
    # destination <- call -> uploaded sensitive file
    "egress.upload": """
MATCH p = (d:Entity {id: $dest})<-[:SENDS_TO]-(c:ToolCall {id: $call})-[:UPLOADS]->(f:Entity {sensitive: true})
RETURN p
LIMIT 1""",
    # a sink with no known destination: call -> fingerprint <- sensitive content
    "egress.carry.nodest": """
MATCH p = (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(s:Content {sensitive: true})
RETURN p
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END, k.id
LIMIT 1""",
    "egress.upload.nodest": """
MATCH p = (c:ToolCall {id: $call})-[:UPLOADS]->(f:Entity {sensitive: true})
RETURN p
LIMIT 1""",
    # untrusted content -> destination <- call
    "TT003": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})<-[:SENDS_TO]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # the three corners of the trifecta, which share a session rather than an edge
    # (one corner at a time: joining both sets first is every untrusted result times every
    # sensitive one, which a long session over a ticket system turns into millions of rows)
    "TT002": """
MATCH (c:ToolCall {id: $call})
MATCH (u:Content {session_id: c.session_id, untrusted: true}) WHERE u.seq < c.seq
WITH c, u ORDER BY u.seq DESC LIMIT 1
MATCH (s:Content {session_id: c.session_id, sensitive: true}) WHERE s.seq < c.seq
RETURN u, c, s
ORDER BY s.seq DESC
LIMIT 1""",
    # untrusted content -> sensitive file <- call
    "TT004": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(f:Entity {sensitive: true})<-[:READS]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
  AND NOT EXISTS {
    MATCH (t:Content)-[tm:MENTIONS]->(f)
    WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false
      AND NOT coalesce(tm.weak, false)
      AND NOT EXISTS { MATCH (u2:Content {untrusted: true})-[:MENTIONS]->(f)
                       WHERE u2.session_id = c.session_id AND u2.seq < t.seq }
  }
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # untrusted content -> fingerprint <- call -> protected file
    "TT005.copy": """
MATCH p = (u:Content {untrusted: true})-[:HAS_CHUNK]->(k:Chunk)<-[:CARRIES]-(c:ToolCall {id: $call})
          -[:WRITES]->(f:Entity {id: $dest})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    "TT005.context": """
MATCH p = (c:ToolCall {id: $call})-[:WRITES]->(f:Entity {id: $dest})
RETURN p
LIMIT 1""",
    # untrusted content -> download source <- call
    "TT007.download": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})
          <-[:FETCHES|EXECUTES|SENDS_TO]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # untrusted content -> line of text <- command
    "TT007.copied": """
MATCH p = (u:Content {untrusted: true})-[:HAS_CHUNK]->(k:Chunk {kind: 'line'})<-[:CARRIES]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # untrusted content -> download source <- downloaded file <- call that runs it
    "TT007.staged": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity)<-[:DERIVED_FROM]-(f:Entity)<-[:EXECUTES]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    "TT007.staged.host": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(h:Entity)<-[:ON_HOST]-(d:Entity)<-[:DERIVED_FROM]-(f:Entity)
          <-[:EXECUTES]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
ORDER BY u.seq
LIMIT 1""",
    # untrusted content, then a read of repository P, then a write to repository Q
    "TT011": """
MATCH (c:ToolCall {id: $call})-[:SENDS_TO]->(q:Entity {kind: 'repo'})
MATCH (r:ToolCall {session_id: c.session_id})-[:READS]->(p:Entity {kind: 'repo'})
WHERE r.seq < c.seq AND p.id <> q.id
  AND EXISTS { MATCH (r)-[:RETURNED]->(:Content {sensitive: true}) }
  AND NOT EXISTS {
    MATCH (t:Content {origin: 'user'})-[:MENTIONS]->(p)
    WHERE t.session_id = c.session_id AND t.seq < c.seq
  }
WITH c, q, r, p ORDER BY r.seq DESC LIMIT 1
MATCH (r)-[:RETURNED]->(s:Content {sensitive: true})
MATCH (u:Content {session_id: c.session_id, untrusted: true})
WHERE u.seq < r.seq
RETURN u, r, p, s, c, q
ORDER BY u.seq DESC
LIMIT 1""",
    # a copy of a sensitive file, written or staged in this session, behind a push
    "egress.commit": """
MATCH (c:ToolCall {id: $call})
MATCH (w:ToolCall {session_id: c.session_id})-[e:WRITES|READS]->(f:Entity {kind: 'file'})
WHERE w.seq <= c.seq AND coalesce(f.sensitive, false) AND f.value STARTS WITH $root
  AND (coalesce(e.staged, false) OR (type(e) = 'WRITES' AND EXISTS { MATCH (f)-[:DERIVED_FROM]->(:Entity {sensitive: true}) }))
OPTIONAL MATCH (f)-[:DERIVED_FROM]->(src:Entity {sensitive: true})
RETURN f.id AS id, f.name AS name, f.kind AS kind, f.value AS path, w.id AS writer, src.id AS source
ORDER BY w.seq DESC""",
    # earlier session's untrusted content <- tainted file <- this content
    "TT008": """
MATCH p = (o:Content {id: $content})-[:FROM]->(e:Entity)-[:TAINTED_BY]->(u:Content)
WHERE u.session_id <> o.session_id
RETURN p
LIMIT 1""",
    "TT010": """
MATCH p = (c:ToolCall {id: $call})-[:WRITES]->(f:Entity {id: $dest})
RETURN p
LIMIT 1""",
    # how any untrusted content of the session connects to a call, by the shortest chain
    "explain": """
MATCH p = SHORTEST 1 (u:Content {untrusted: true, session_id: $session})-[:""" + S.rel_union() + """]-{1,6}(c:ToolCall {id: $call})
RETURN p""",
}

# The call, and the two corners of its session each on its own: the latest untrusted content and
# the latest sensitive content before it, with how many there are. Carrying one set across the
# match of the other made this grow with their product.
_Q_CONTEXT = "MATCH (c:ToolCall {id: $call}) RETURN c.session_id AS sid, c.seq AS seq, c.ts AS ts, c.tool AS tool"
_Q_CORNER = """
MATCH (x:Content {session_id: $sid})
WHERE x.seq < $seq AND coalesce(x[$flag], false)
WITH x ORDER BY x.seq DESC
RETURN collect(x.id)[0] AS last, count(x) AS n
"""

# Where a call sends, fetches or executes, and who named each place earlier in the session.
# A mention in trusted content counts only if no untrusted content had named the place before it:
# once a page has named a host, command output that repeats the name (`echo`, a log, this guard's
# own `explain`) must not turn the host into one the project knows.
_Q_TARGETS = """
MATCH (c:ToolCall {id: $call})-[r]->(d:Entity)
WHERE type(r) IN $rels
RETURN DISTINCT d.id AS id, d.kind AS kind, d.value AS value, d.name AS name, coalesce(r.via, '') AS via,
  coalesce(d.local, false) AS local, coalesce(d.trusted, false) AS trusted,
  EXISTS { MATCH (u:Content {untrusted: true})-[:MENTIONS]->(d)
           WHERE u.session_id = c.session_id AND u.seq < c.seq } AS by_untrusted,
  EXISTS { MATCH (t:Content)-[tm:MENTIONS]->(d)
           WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false
             AND NOT coalesce(tm.weak, false)
             AND NOT EXISTS { MATCH (u2:Content {untrusted: true})-[:MENTIONS]->(d)
                              WHERE u2.session_id = c.session_id AND u2.seq < t.seq } } AS by_trusted,
  EXISTS { MATCH (q:Content {origin: 'user'})-[:MENTIONS]->(d)
           WHERE q.session_id = c.session_id AND q.seq < c.seq } AS by_user
ORDER BY id
"""

# Text that goes back to the repository or the object it was read from is not leaving anything:
# a typo fixed in a README through the GitHub server, a step added to a Notion page. The reading
# call READS the entity this call writes to. A text that merely mentions the source does not
# qualify, which is why a repository needs SENDS_TO and an MCP object its `object` flag.
_SAME_OBJECT = """EXISTS { MATCH (p)<-[:RETURNED]-(r:ToolCall)-[:READS]->(e:Entity)<-[x:SENDS_TO|REFERENCES]-(c)
           WHERE (e.kind = 'repo' AND type(x) = 'SENDS_TO' AND coalesce(p.untrusted, false))
              OR (e.kind = 'mcp' AND coalesce(x.object, false)) }"""

_Q_CARRIED_SENSITIVE = """
MATCH (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(p:Content {sensitive: true})
WHERE NOT """ + _SAME_OBJECT + """
WITH p, collect(DISTINCT k) AS ks
OPTIONAL MATCH (p)-[:FROM]->(src:Entity)
RETURN p.id AS content, p.origin AS origin, src.name AS source, src.id AS source_id,
       size([k IN ks WHERE k.kind IN ['secret', 'token']]) AS strong,
       size([k IN ks WHERE k.kind = 'line']) AS lines,
       [k IN ks WHERE k.kind = 'secret' | k.hint] AS hints
ORDER BY strong DESC, lines DESC
"""

# Sensitive content of the session, and whether each piece came from where this call writes.
_Q_SENSITIVE_ELSEWHERE = """
MATCH (c:ToolCall {id: $call})
MATCH (p:Content {session_id: c.session_id, sensitive: true}) WHERE p.seq < c.seq
OPTIONAL MATCH (p)-[:FROM]->(src:Entity)
RETURN p.id AS id, src.id AS source, """ + _SAME_OBJECT + """ AS same_object,
       EXISTS { MATCH (p)<-[:RETURNED]-(r2:ToolCall)-[ro:READS]->(:Entity {kind: 'mcp'}) WHERE coalesce(ro.object, false) } AS has_object
"""

# How much the untrusted content of the session reads like instructions, at most.
_Q_INJECTION_LIKE = """
MATCH (c:ToolCall {id: $call})
MATCH (u:Content {session_id: c.session_id, untrusted: true}) WHERE u.seq < c.seq
RETURN max(coalesce(u.injection_score, 0.0)) AS top
"""

_Q_NAMED_BY_UNTRUSTED = """
MATCH (c:ToolCall {id: $call})
MATCH (u:Content {untrusted: true})-[:MENTIONS]->(:Entity {id: $dest})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN count(u) AS n
"""

_Q_COPIED_FROM = """
MATCH (u:Content {untrusted: true})-[:HAS_CHUNK]->(k:Chunk)<-[:CARRIES]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN max(coalesce(u.injection_score, 0.0)) AS top
"""

# The file that holds a credential usually says where it is used (API_URL next to API_TOKEN).
_Q_NAMED_BY_SECRETS_FILE = """
MATCH (c:ToolCall {id: $call})
MATCH (t:Content)-[:MENTIONS]->(:Entity {id: $dest})
WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false
  AND 'path:sensitive' IN t.reasons
RETURN count(t) AS n
"""

_Q_UPLOADED_SENSITIVE = """
MATCH (c:ToolCall {id: $call})-[:UPLOADS]->(f:Entity)
WHERE coalesce(f.sensitive, false)
RETURN f.id AS id, f.name AS name, f.kind AS kind
ORDER BY id
"""

_Q_CARRIED_UNTRUSTED = """
MATCH (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(u:Content {untrusted: true})
WHERE u.session_id = c.session_id AND u.seq < c.seq AND k.kind IN $kinds
RETURN u.id AS content, count(DISTINCT k) AS n
ORDER BY n DESC
LIMIT 1
"""

_Q_FOLLOWED_LINK = """
MATCH (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk {kind: 'url'})
RETURN count(k) AS n
"""

_Q_PROTECTED_WRITES = """
MATCH (c:ToolCall {id: $call})-[:WRITES]->(f:Entity)
WHERE coalesce(f.protected, false)
RETURN f.id AS id, f.name AS name, f.value AS path,
  EXISTS { MATCH (q:Content {origin: 'user'})-[:MENTIONS]->(f)
           WHERE q.session_id = c.session_id AND q.seq < c.seq } AS by_user
ORDER BY id
"""

_Q_DESCRIBE = {
    S.CONTENT: """
MATCH (n:Content {id: $id})
OPTIONAL MATCH (n)-[:FROM]->(src:Entity)
OPTIONAL MATCH (call:ToolCall)-[:RETURNED]->(n)
RETURN properties(n) AS p, src.kind AS src_kind, src.value AS src_value, src.name AS src_name, call.tool AS tool
LIMIT 1""",
    S.TOOL_CALL: "MATCH (n:ToolCall {id: $id}) RETURN properties(n) AS p",
    S.ENTITY: "MATCH (n:Entity {id: $id}) RETURN properties(n) AS p",
    S.CHUNK: "MATCH (n:Chunk {id: $id}) RETURN properties(n) AS p",
}

_SCRIPT_NAME = re.compile(r"(?:\.(?:sh|bash|zsh|py|pl|rb|js|mjs|ps1|bat|cmd|exe|bin|run|command|appimage)|/(?:install|setup|bootstrap|run)[\w.-]*)$", re.I)
_TAMPER_COMMAND = re.compile(r"TAINTTRAIL_DISABLE|tainttrail\s+uninstall|-m\s+tainttrail\s+uninstall")
_SETTINGS_FILE = re.compile(r"/\.claude/settings(\.local)?\.json$")


# -- titles ------------------------------------------------------------------------------


def _name(text: Any, limit: int = 60) -> str:
    """A name from the outside world, fit to stand inside one of the guard's own sentences.

    File names, URL paths, host names and command lines are chosen by whoever wrote the content
    the guard is watching, and the guard repeats them to the model and in the permission prompt.
    So: one line (a line break in a name would let it start a paragraph of its own), printable
    characters only, and too short to be a sentence.
    """
    line = " ".join("".join(ch if ch.isprintable() else " " for ch in str(text)).split())
    if len(line) <= limit:
        return line
    head = (limit - 1) * 2 // 3
    return line[:head] + "…" + line[len(line) - (limit - 1 - head):]


def _short_url(url: str) -> str:
    """A link as shown in a sentence: its host and the start of its path."""
    rest = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(url))
    host, sep, path = rest.partition("/")
    return _name(host, 60) + (sep + _name(path, 30) if path else "")


def content_title(props: dict[str, Any], src_kind: str | None = None, src_value: str | None = None,
                  src_name: str | None = None, tool: str | None = None) -> str:
    origin = props.get("origin")
    if origin == "user":
        return "your prompt"
    if origin == "memory":
        return f"{_name(src_name or 'an instruction file')}, loaded at session start"
    if src_kind == "url" and src_value:
        return f"web page {_short_url(src_value)}"
    if src_kind == "file" and src_name:
        return f"contents of {_name(src_name)}"
    if src_kind == "host" and src_value:
        return f"response from {_name(src_value)}"
    if src_value:
        return _name(src_value)
    if tool:
        return f"output of {_name(tool, 80)}"
    return "tool output"


def node_title(node: dict[str, Any], extra: dict[str, Any] | None = None) -> str:
    """A short human description of a node as returned by ``store.to_plain``."""
    labels = node.get("labels") or []
    p = node.get("props") or {}
    extra = extra or {}
    if S.CONTENT in labels:
        return content_title(p, extra.get("src_kind"), extra.get("src_value"), extra.get("src_name"), extra.get("tool"))
    if S.TOOL_CALL in labels:
        return f"call #{p.get('num') or p.get('seq') or '?'}  {_name(p.get('summary') or p.get('tool') or '', 120)}".rstrip()
    if S.ENTITY in labels:
        kind, value = p.get("kind"), str(p.get("value") or "")
        if kind == "file":
            return f"file {_name(p.get('name') or value)}"
        if kind == "url":
            return _short_url(value)
        if kind == "env":
            return "the process environment" if value == "*" else f"${_name(value)}"
        if kind == "repo":
            return f"repository {_name(value)}"
        return _name(value)
    if S.CHUNK in labels:
        kind, hint = p.get("kind"), p.get("hint") or ""
        if kind == "secret":
            return f"fingerprint of a secret ({hint})" if hint else "fingerprint of a secret"
        if kind == "token":
            return "fingerprint of a long token"
        if kind == "url":
            return "the exact link"
        return "fingerprint of a line of text"
    return str(node.get("id", ""))


def _role(node: dict[str, Any]) -> str:
    labels = node.get("labels") or []
    p = node.get("props") or {}
    if S.CONTENT in labels:
        if p.get("origin") == "user":
            return "user"
        if p.get("sensitive"):
            return "sensitive"
        if p.get("untrusted"):
            return "untrusted"
        return "content"
    if S.TOOL_CALL in labels:
        return "call"
    if S.CHUNK in labels:
        return "fingerprint"
    if S.ENTITY in labels:
        if p.get("kind") == "file":
            return "sensitive" if p.get("sensitive") else "file"
        if p.get("kind") in ("host", "url", "repo", "email", "mcp"):
            return "destination"
        return "entity"
    return ""


# -- evaluation --------------------------------------------------------------------------


class _Eval:
    def __init__(self, store: Store, cfg: Config | None, call_id: str, call: CallAnalysis | None) -> None:
        self.store = store
        self.cfg = cfg
        self.call_id = call_id
        self.call = call
        self.ctx = store.one(_Q_CONTEXT, {"call": call_id}) or {}
        if self.ctx:
            for flag in ("untrusted", "sensitive"):
                corner = store.one(_Q_CORNER, {"sid": self.ctx["sid"], "seq": self.ctx["seq"], "flag": flag}) or {}
                self.ctx[f"last_{flag}"] = corner.get("last")
                self.ctx[f"n_{flag}"] = corner.get("n") or 0
        self._described: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
        self._dest_known = False    # set by egress(): every destination is safe or named by the project's secrets file

    # -- small lookups ----------------------------------------------------------------

    @property
    def untrusted_in_session(self) -> bool:
        return bool(self.ctx.get("n_untrusted"))

    @property
    def sensitive_in_session(self) -> bool:
        return bool(self.ctx.get("n_sensitive"))

    def targets(self, *rels: str) -> list[dict[str, Any]]:
        return self.store.run(_Q_TARGETS, {"call": self.call_id, "rels": list(rels)})

    def describe(self, label: str, node_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        key = (label, node_id)
        if key not in self._described:
            row = self.store.one(_Q_DESCRIBE[label], {"id": node_id}) if label in _Q_DESCRIBE else None
            props = dict(row["p"]) if row else {"id": node_id}
            extra = {k: v for k, v in (row or {}).items() if k != "p"}
            self._described[key] = ({"id": node_id, "labels": [label], "props": props}, extra)
        return self._described[key]

    def step(self, label: str, node_id: str, rel: str | None = None, forward: bool = True,
             role: str | None = None) -> PathStep:
        node, extra = self.describe(label, node_id)
        return PathStep(node_id=node_id, label=label, title=node_title(node, extra),
                        rel=rel, forward=forward, role=role or _role(node))

    def steps_from_path(self, path: dict[str, Any]) -> list[PathStep]:
        nodes, rels = path["nodes"], path["rels"]
        steps: list[PathStep] = []
        for i, node in enumerate(nodes):
            label = next((lbl for lbl in node["labels"] if lbl in S.NODE_LABELS), node["labels"][0])
            rel = rels[i] if i < len(rels) else None
            steps.append(self.step(
                label, node["id"],
                rel=rel["type"] if rel else None,
                forward=(rel["start"] == node["id"]) if rel else True,
            ))
        return steps

    def run_path(self, key: str, **params: Any) -> tuple[list[PathStep], str, dict[str, Any]]:
        """Run one of the path queries. Returns (steps, query text, parameters)."""
        query = CYPHER[key].strip()
        params = {"call": self.call_id, **params}
        needed = {k: v for k, v in params.items() if f"${k}" in query}
        row = self.store.one(query, needed)
        if not row or "p" not in row or not row["p"]:
            return [], query, needed
        return self.steps_from_path(row["p"]), query, needed

    def finding(self, rule_id: str, *, action: str, title: str, explanation: str,
                path: list[PathStep], severity: str | None = None, query: str = "",
                params: dict[str, Any] | None = None, target_id: str | None = None,
                target_label: str = S.TOOL_CALL) -> Finding | None:
        rule = RULES[rule_id]
        final = self.cfg.rule_action(rule_id, action) if self.cfg is not None else action
        if final == "off":
            return None
        return Finding(
            rule=rule.id, name=rule.name, severity=severity or rule.severity, action=final,
            title=title, explanation=explanation, path=path,
            session_id=str(self.ctx.get("sid") or ""), target_id=target_id or self.call_id,
            target_label=target_label, ts=int(self.ctx.get("ts") or 0), intended=action,
            query=query, params=params or {},
        )

    def _injection_score(self, content_id: str) -> float:
        node, _ = self.describe(S.CONTENT, content_id)
        return float(node["props"].get("injection_score") or 0.0)

    def provenance(self, entity_id: str) -> dict[str, Any]:
        """Who named an entity earlier in the session, and whether it is on the allow-list."""
        return self.store.one(
            """
            MATCH (c:ToolCall {id: $call}) MATCH (d:Entity {id: $id})
            RETURN coalesce(d.trusted, false) AS trusted, coalesce(d.local, false) AS local,
              EXISTS { MATCH (t:Content)-[tm:MENTIONS]->(d)
                       WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false
                         AND NOT coalesce(tm.weak, false)
                         AND NOT EXISTS { MATCH (u2:Content {untrusted: true})-[:MENTIONS]->(d)
                                          WHERE u2.session_id = c.session_id AND u2.seq < t.seq } } AS by_trusted,
              EXISTS { MATCH (q:Content {origin: 'user'})-[:MENTIONS]->(d)
                       WHERE q.session_id = c.session_id AND q.seq < c.seq } AS by_user
            """,
            {"call": self.call_id, "id": entity_id},
        ) or {"trusted": False, "local": False, "by_trusted": False, "by_user": False}

    def title_of(self, label: str, node_id: str | None) -> str:
        if not node_id:
            return "untrusted content"
        node, extra = self.describe(label, node_id)
        return node_title(node, extra)

    # -- the egress ladder: TT001, TT006, TT003, TT002 ----------------------------------

    def egress(self) -> list[Finding]:
        call = self.call
        if call is None:
            return []
        args_leave = bool(call.extra.get("args_leave"))   # an MCP tool nobody labelled a sink
        if not call.is_sink and not args_leave:
            return []
        dests = self.targets(S.SENDS_TO)
        direct = [d for d in dests if d["via"] != "suffix"]
        parents = [d for d in dests if d["via"] == "suffix"]   # the domains a host sits under
        external = [d for d in direct if not d["local"]]
        if direct and not external:
            return []  # everything stays on this machine or the local network

        def under(host: dict[str, Any]) -> list[dict[str, Any]]:
            return [p for p in parents if host["kind"] == "host" and host["value"].endswith("." + p["value"])]

        safe_ids = {d["id"] for d in external if d["trusted"] or d["by_user"]
                    or any(p["trusted"] or p["by_user"] for p in under(d))}
        for d in external:  # a URL is as safe as its host
            if d["kind"] == "url" and d["id"] not in safe_ids and _host_id(d["value"]) in safe_ids:
                safe_ids.add(d["id"])
        all_safe = bool(external) and all(d["id"] in safe_ids for d in external)
        if not external and call.extra.get("dest_trusted"):
            all_safe = True
        user_named = bool(external) and all(
            _named_by_user(d, external) or any(p["by_user"] for p in under(d)) for d in external)

        def is_injected(d: dict[str, Any]) -> bool:
            return d["by_untrusted"] and not d["by_trusted"] and not d["trusted"] and not d["by_user"]

        injected = [d for d in external if is_injected(d) and d["id"] not in safe_ids]
        # A parent domain that only untrusted content named taints every host under it.
        injected += [p for p in parents if is_injected(p) and not p["local"]
                     and any(h["id"] not in safe_ids for h in external if h in external and p in under(h))]
        injected.sort(key=lambda d: (_SPECIFICITY.get(d["kind"], 9), -len(d["value"])))

        carried = [
            r for r in self.store.run(_Q_CARRIED_SENSITIVE, {"call": self.call_id})
            if r["strong"] >= 1 or r["lines"] >= MIN_LINE_CHUNKS
        ]
        # A destination is "known" when it is safe, or when the project's own secrets file names it.
        known = set(safe_ids) | {d["id"] for d in external if d["by_trusted"]
                                 and self.store.scalar(_Q_NAMED_BY_SECRETS_FILE, {"call": self.call_id, "dest": d["id"]}, 0)}
        known |= {d["id"] for d in external if d["kind"] == "url" and _host_id(d["value"]) in known}
        self._dest_known = bool(external) and all(d["id"] in known for d in external)
        by_file = {d["id"] for d in external if d["by_trusted"]
                   and self.store.scalar(_Q_NAMED_BY_SECRETS_FILE, {"call": self.call_id, "dest": d["id"]}, 0)}
        by_file |= {d["id"] for d in external if d["kind"] == "url" and _host_id(d["value"]) in by_file}
        self._dest_in_secrets_file = bool(external) and all(d["id"] in by_file for d in external)
        uploaded = self.store.run(_Q_UPLOADED_SENSITIVE, {"call": self.call_id})
        committed: list[dict[str, Any]] = []
        if call.sink_kind == "git":
            committed = [c for c in self.store.run(CYPHER["egress.commit"].strip(),
                                                   {"call": self.call_id, "root": self._root_prefix()})
                         if not self._git_ignored(c["path"])]
            seen = {u["id"] for u in uploaded}
            uploaded += [c for c in {c["id"]: c for c in committed}.values() if c["id"] not in seen]
        primary = (injected or sorted(external, key=lambda d: _SPECIFICITY.get(d["kind"], 9)) or [None])[0]
        dest_name = _dest_name(primary)

        if carried or uploaded:
            what = _describe_payload(carried, uploaded)
            f = self._sensitive_egress(primary, injected, carried, uploaded, what, dest_name,
                                       user_named, all_safe, committed)
            return [f] if f else []
        if not call.is_sink:
            return []   # an unlabelled tool is only judged on evidence of what it carries

        payload = bool(call.extra.get("carries_payload", True))
        # Following a link excuses a GET of exactly that link, not a request with a body: a page that
        # lists https://host/collect?src=x must not get a POST to it waved through.
        followed = (bool(self.store.scalar(_Q_FOLLOWED_LINK, {"call": self.call_id}, 0))
                    and (call.tool == "WebFetch" or bool(call.extra.get("plain_get"))))
        if followed and self.cfg is not None:
            # ... and every URL the call contacts has to be one of the listed links, as written.
            listed = {r["id"] for r in self.store.run(
                "MATCH (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk {kind: 'url'}) RETURN k.id AS id", {"call": self.call_id})}
            urls = [str(u) for u in (call.extra.get("get_urls") or [])]
            key = self.cfg.key()
            followed = bool(urls) and all(fingerprint(u, key) in listed for u in urls)
        if injected and payload and not followed:
            d = injected[0]
            path, query, params = self.run_path("TT003", dest=d["id"])
            source = path[0].title if path else "untrusted content"
            sev = "high" if self.sensitive_in_session else "medium"
            more = " Sensitive data has also been read in this session." if self.sensitive_in_session else ""
            f = self.finding(
                "TT003", action="ask", severity=sev,
                title=f"Data would go to {_dest_name(d)}, which only untrusted content named",
                explanation=(f"{_cap(source)} named {_dest_name(d)}. Nothing you typed and no trusted content "
                             f"mentions it, and this call sends data there.{more}"),
                path=path, query=query, params=params,
            )
            return [f] if f else []

        crossed = self.scope_crossed() if payload else []
        if crossed:
            return crossed

        if self.untrusted_in_session and self._sensitive_elsewhere() and payload and not all_safe and not followed:
            row = self.store.one(CYPHER["TT002"].strip(), {"call": self.call_id})
            path: list[PathStep] = []
            if row:
                path = [
                    self.step(S.CONTENT, row["u"]["id"], rel="in the same session", role="untrusted"),
                    self.step(S.TOOL_CALL, row["c"]["id"], rel="in the same session", forward=False),
                    self.step(S.CONTENT, row["s"]["id"], role="sensitive"),
                ]
            f = self.finding(
                "TT002", action="ask",
                title=f"Outbound call to {dest_name} in a session that holds untrusted content and sensitive data",
                explanation=(f"This session has read untrusted content ({path[0].title if path else 'earlier'}) "
                             f"and sensitive data ({path[2].title if path else 'earlier'}). This call can carry "
                             f"data to {dest_name}. Check what it sends before you allow it."),
                path=path, query=CYPHER["TT002"].strip(), params={"call": self.call_id},
            )
            return [f] if f else []
        return []

    def _sensitive_elsewhere(self) -> bool:
        """Is there sensitive content in the session that did not come from where this call writes?

        A reply in the Slack thread that was just read, a comment on the ticket that was just
        fetched: the only "sensitive data" in such a session belongs to the workspace being
        written to. Counted as elsewhere: anything read from another object, and for a sink that
        reaches the public (GitHub) anything not read from the very same repository.
        """
        if not self.sensitive_in_session:
            return False
        call = self.call
        server = None
        if call is not None and call.sink_kind == "mcp" and call.labels.sink_scope in ("org", "private"):
            server = call.extra.get("mcp_server")
        for row in self.store.run(_Q_SENSITIVE_ELSEWHERE, {"call": self.call_id}):
            if row["same_object"]:
                continue
            if server and str(row["source"] or "").startswith(f"mcp:{server}/") and not row["has_object"]:
                continue        # found in this workspace by a search or a list, written to this workspace
            return True
        return False

    @staticmethod
    def _not_a_stranger(d: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
        """A host under a domain the user named or that is allow-listed, or a URL on such a host."""
        host = d["value"] if d["kind"] == "host" else (_host_id(d["value"]) or ":").split(":", 1)[1]
        for x in rows:
            if x["kind"] != "host" or not (x["by_user"] or x["trusted"]):
                continue
            if x["value"] == host or host.endswith("." + x["value"]):
                return True
        return False

    def scope_crossed(self) -> list[Finding]:
        """TT011: private data from one repository, a write to another, untrusted content before both."""
        row = self.store.one(CYPHER["TT011"].strip(), {"call": self.call_id})
        if not row:
            return []
        p_name, q_name = row["p"]["props"].get("value"), row["q"]["props"].get("value")
        path = [
            self.step(S.CONTENT, row["u"]["id"], rel="in the same session", role="untrusted"),
            self.step(S.TOOL_CALL, row["r"]["id"], rel=S.READS, forward=True),
            self.step(S.ENTITY, row["p"]["id"], rel="in the same session", role="sensitive"),
            self.step(S.TOOL_CALL, row["c"]["id"], rel=S.SENDS_TO, forward=True),
            self.step(S.ENTITY, row["q"]["id"], role="destination"),
        ]
        f = self.finding(
            "TT011", action="ask",
            title=f"Data read from {p_name} would be written to {q_name}",
            explanation=(f"After reading untrusted content ({path[0].title}), the agent read private data from "
                         f"{p_name}, which you did not mention, and this call writes to {q_name}. A summary leaves "
                         "no fingerprint, so check what is being written."),
            path=path, query=CYPHER["TT011"].strip(), params={"call": self.call_id},
        )
        return [f] if f else []

    def _root_prefix(self) -> str:
        return (self.cfg.root.as_posix().rstrip("/") + "/") if self.cfg is not None else "/"

    def _git_ignored(self, path: str) -> bool:
        """Whether the project's top-level .gitignore covers a path. A plain reading, not git's full rules."""
        if self.cfg is None or not path:
            return False
        root = self.cfg.root.as_posix().rstrip("/")
        if not path.startswith(root + "/"):
            return False
        rel = path[len(root) + 1:]
        try:
            with open(f"{root}/.gitignore", encoding="utf-8", errors="replace") as fh:
                patterns = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError:
            return False
        import fnmatch

        ignored = False
        for pattern in patterns:
            negate = pattern.startswith("!")
            pat = pattern.lstrip("!").lstrip("/")
            if pat.endswith("/"):
                hit = rel.startswith(pat) or ("/" + pat) in ("/" + rel + "/")
            else:
                hit = (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], pat)
                       or rel.startswith(pat + "/"))
            if hit:
                ignored = not negate
        return ignored

    def _sensitive_egress(self, primary, injected, carried, uploaded, what, dest_name,
                          user_named, all_safe, committed=()) -> Finding | None:
        dest_id = primary["id"] if primary else None
        use_upload = bool(uploaded) and not carried
        if committed and not carried and all(u["id"] in {c["id"] for c in committed} for u in uploaded):
            return self._committed_egress(primary, committed, dest_name)
        if injected:
            key = "TT001.upload.injected" if use_upload else "TT001.carry.injected"
            path, query, params = self.run_path(key, dest=dest_id)
            if not path and carried and uploaded:  # the other kind of evidence may complete the path
                path, query, params = self.run_path("TT001.upload.injected", dest=dest_id)
        else:
            path, query, params = [], "", {}
        if not path:
            if dest_id:
                path, query, params = self.run_path("egress.upload" if use_upload else "egress.carry", dest=dest_id)
            if not path:
                path, query, params = self.run_path("egress.upload.nodest" if use_upload else "egress.carry.nodest")

        if self.untrusted_in_session or injected:
            source = self.title_of(S.CONTENT, self.ctx.get("last_untrusted"))
            if injected:
                source = path[0].title if path and path[0].role == "untrusted" else source
                explanation = (f"{_cap(source)} named {dest_name} as a destination, and nothing you typed or any "
                               f"trusted content mentions it. This call would send {what} there.")
                severity = "critical"
            else:
                # Show where the untrusted influence came from even though no edge ties it to the call.
                if self.ctx.get("last_untrusted"):
                    path = [self.step(S.CONTENT, self.ctx["last_untrusted"], rel="in the same session",
                                      role="untrusted"), *path]
                explanation = (f"This call would send {what} to {dest_name}. The session holds untrusted content "
                               f"({source}), which can steer the agent, so sensitive data is not allowed to leave.")
                severity = "high"
            # Naming the destination is not the same as asking for this data to go there.
            sources_named = self._sources_named_by_user(carried, uploaded)
            if not injected:
                # A credential used as a credential (-u, an Authorization header) for a destination that
                # is allow-listed, named by the user or named by the project's own secrets file is
                # authentication, with or without a web page earlier in the session.
                env_auth = set((self.call.extra.get("env_auth") if self.call else None) or [])
                auth_only = (bool(uploaded) and not carried
                             and all(u.get("kind") == "env" and u["name"] in env_auth for u in uploaded))
                # ... provided the credential belongs there: the secrets file names the host next to it, or
                # the variable is named after it (GITHUB_TOKEN for api.github.com). An AWS key in the
                # Authorization header of a paste site is not authentication.
                hosts = [d["value"] if d["kind"] == "host" else (_host_id(d["value"]) or ":").split(":", 1)[1]
                         for d in self.targets(S.SENDS_TO) if d["via"] != "suffix" and d["kind"] in ("host", "url")]
                repos = [d["value"] for d in self.targets(S.SENDS_TO) if d["kind"] == "repo"]
                belongs = self._dest_in_secrets_file or all(_stem_match(u["name"], hosts + repos) for u in uploaded)
                if auth_only and belongs and (all_safe or user_named or self._dest_known):
                    return self.finding("TT006", action="allow", severity="info",
                                        title=f"{_cap(what)} authenticates a request to {dest_name}",
                                        explanation=(f"{_cap(what)} is used as a credential (-u or an authorization header) for "
                                                     f"{dest_name}, which you or the project's own files named."),
                                        path=path, query=query, params=params)
                if auth_only and user_named:
                    # A credential for a destination the user named, with nothing that ties the two together:
                    # that is a question for the user, not a refusal.
                    return self.finding("TT001", action="ask", severity=severity,
                                        title=f"{_cap(what)} would be sent to {dest_name}",
                                        explanation=(explanation + f" It is used as a credential for a destination you named, "
                                                     f"but nothing in the project ties it to {dest_name}. Approve it if that "
                                                     "is the service it belongs to."),
                                        path=path, query=query, params=params)
                if user_named and sources_named:
                    pasted = bool(carried) and all(c.get("origin") == "user" for c in carried) and not uploaded
                    own = bool(uploaded) and not carried and all(
                        u.get("kind") == "env" and _stem_match(u["name"], hosts) for u in uploaded)
                    if not (pasted or own):
                        # A mention is not an order: "the credentials are in .env" does not ask for .env to be posted.
                        return self.finding("TT001", action="ask", severity=severity,
                                            title=f"{_cap(what)} would be sent to {dest_name}",
                                            explanation=explanation + " You named this destination and this data yourself, so you can approve it.",
                                            path=path, query=query, params=params)
                if user_named and sources_named:
                    # Nothing goes anywhere the user did not name, and nothing the user did not name goes.
                    return self.finding("TT006", action="allow", severity="info",
                                        title=f"{_cap(what)} would be sent to {dest_name}",
                                        explanation=f"This call would send {what} to {dest_name}. You named both in your prompt.",
                                        path=path, query=query, params=params)
            action = "deny"
            return self.finding("TT001", action=action, severity=severity,
                                title=f"{_cap(what)} would be sent to {dest_name}",
                                explanation=explanation, path=path, query=query, params=params)

        # No untrusted content anywhere upstream: a leak, not an injection.
        # One credential and nothing else: a token in a header, or one variable expanded
        # into the command. A file, the whole environment or copied lines are not that.
        named_vars = [u for u in uploaded if u.get("kind") == "env" and u["name"] != "*"]
        other_uploads = [u for u in uploaded if u not in named_vars]
        carried_secrets = sum(len(set(c.get("hints") or [])) or (1 if c["strong"] else 0) for c in carried)
        copied_lines = any(c["lines"] >= MIN_LINE_CHUNKS for c in carried)
        single_credential = (not other_uploads and not copied_lines
                             and carried_secrets + len(named_vars) == 1)
        if user_named:
            action, severity = "allow", "info"
            tail = "You named this destination in your prompt."
        elif all_safe and single_credential:
            action, severity = "allow", "info"
            tail = "One credential sent to an allow-listed host looks like ordinary authentication."
        elif single_credential and not carried and self._dest_known:
            action, severity = "allow", "info"
            tail = "One credential sent to a host the project's own secrets file names looks like ordinary authentication."
        else:
            action, severity = "ask", "high"
            tail = "No untrusted content is involved, so this may be intended. Approve it if it is."
        return self.finding("TT006", action=action, severity=severity,
                            title=f"{_cap(what)} would be sent to {dest_name}",
                            explanation=f"This call would send {what} to {dest_name}. {tail}",
                            path=path, query=query, params=params)

    def _sources_named_by_user(self, carried, uploaded) -> bool:
        """Did the user's own prompts mention every sensitive thing this call carries?"""
        carried = [c for c in carried if c.get("origin") != "user"]   # typed into the prompt: named by the user
        if not carried and not uploaded:
            return True
        ids = [u["id"] for u in uploaded] + [c["source_id"] for c in carried if c.get("source_id")]
        if not ids or any(c.get("source_id") is None for c in carried):
            return False
        return all(self.provenance(i)["by_user"] for i in ids)

    def _committed_egress(self, primary, committed, dest_name) -> Finding | None:
        """A push after a copy of a sensitive file was written or staged in this session."""
        top = committed[0]
        path = [self.step(S.ENTITY, top["source"], rel=S.DERIVED_FROM, forward=False, role="sensitive")] if top.get("source") else []
        path += [
            self.step(S.ENTITY, top["id"], rel=S.WRITES, forward=False, role="sensitive"),
            self.step(S.TOOL_CALL, top["writer"], rel="in the same session"),
            self.step(S.TOOL_CALL, self.call_id, rel=S.SENDS_TO if primary else None),
        ]
        if primary:
            path.append(self.step(S.ENTITY, primary["id"], role="destination"))
        query = CYPHER["egress.commit"].strip()
        params = {"call": self.call_id, "root": self._root_prefix()}
        origin = f", a copy of {path[0].title}," if top.get("source") else ""
        if self.untrusted_in_session:
            source = self.title_of(S.CONTENT, self.ctx.get("last_untrusted"))
            return self.finding(
                "TT001", action="deny", severity="high",
                title=f"A push to {dest_name} would carry {top['name']}",
                explanation=(f"{_cap(top['name'])}{origin} was written or staged in this session and is not ignored "
                             f"by git, and this call pushes to {dest_name}. The session holds untrusted content "
                             f"({source}), so sensitive data is not allowed to leave this way."),
                path=path, query=query, params=params)
        return self.finding(
            "TT006", action="ask", severity="high",
            title=f"A push to {dest_name} would carry {top['name']}",
            explanation=(f"{_cap(top['name'])}{origin} was written or staged in this session and is not ignored by "
                         f"git, and this call pushes to {dest_name}. Approve it if that is intended."),
            path=path, query=query, params=params)

    # -- TT004 ---------------------------------------------------------------------------

    def steered_read(self) -> list[Finding]:
        if not self.untrusted_in_session:
            return []
        path, query, params = self.run_path("TT004")
        if not path:
            return []
        # A setup guide that mentions .env is not an attack. Text that reads like
        # instructions to the agent and points at a credentials file is.
        pointed = self._injection_score(path[0].node_id) >= LIKELY_INJECTION
        f = self.finding(
            "TT004", action="ask" if pointed else "allow", severity="high" if pointed else "info",
            title=f"{_cap(path[0].title)} pointed the agent at {path[1].title}",
            explanation=(f"{_cap(path[0].title)} mentions {path[1].title}, which holds sensitive data, and the agent "
                         "is now reading it. Nothing you typed asked for that file."),
            path=path, query=query, params=params,
        )
        return [f] if f else []

    # -- TT005 ---------------------------------------------------------------------------

    def persist(self) -> list[Finding]:
        if not self.untrusted_in_session:
            return []
        out: list[Finding] = []
        for w in self.store.run(_Q_PROTECTED_WRITES, {"call": self.call_id}):
            if self._is_guard_file(w["path"]):
                kind = self._settings_change(w["path"])
                if kind in ("guard", "permissions"):
                    continue  # TT010 speaks for the first; the second only adds narrow permission rules
                # Any other change of a settings file (a helper command, an environment variable, the
                # permission mode) persists like an instruction file does: judge it here.
                path, query, params = self.run_path("TT005.context", dest=w["id"])
                if self.ctx.get("last_untrusted"):
                    path = [self.step(S.CONTENT, self.ctx["last_untrusted"], rel="in the same session", role="untrusted"), *path]
                copied = bool(self.store.scalar(_Q_COPIED_FROM, {"call": self.call_id}, None) is not None) and bool(
                    self.run_path("TT005.copy", dest=w["id"])[0])
                f = self.finding(
                    "TT005", action="deny" if (copied or self._injected_refs()) else "ask", severity="high",
                    title=f"{w['name']} would be changed in a session that holds untrusted content",
                    explanation=(f"{w['name']} configures the agent for every later session, and this change is more than a "
                                 "permission rule. This session has read untrusted content. Check that the change is what you asked for."),
                    path=path, query=query, params=params)
                if f:
                    out.append(f)
                continue
            path, query, params = self.run_path("TT005.copy", dest=w["id"])
            if path:
                # Repeating documentation is how a workflow file gets written. Repeating text that
                # reads like instructions to an agent, or that names this file, is how an injection persists.
                top = float(self.store.scalar(_Q_COPIED_FROM, {"call": self.call_id}, 0.0) or 0.0)
                naming = int(self.store.scalar(_Q_NAMED_BY_UNTRUSTED, {"call": self.call_id, "dest": w["id"]}, 0) or 0)
                if top < LIKELY_INJECTION and not naming and not self._injected_refs():
                    path = []
            if path:
                f = self.finding(
                    "TT005", action="ask" if w["by_user"] else "deny", severity="critical",
                    title=f"Text from untrusted content would be written into {w['name']}",
                    explanation=(f"{w['name']} is loaded into future sessions or run automatically. The text being "
                                 f"written repeats {path[0].title}, so whatever that content says would keep "
                                 "steering the agent after this session ends."),
                    path=path, query=query, params=params,
                )
            else:
                path, query, params = self.run_path("TT005.context", dest=w["id"])
                source = self.title_of(S.CONTENT, self.ctx.get("last_untrusted"))
                if self.ctx.get("last_untrusted"):
                    path = [self.step(S.CONTENT, self.ctx["last_untrusted"], rel="in the same session",
                                      role="untrusted"), *path]
                quiet = bool(w["by_user"])
                if not quiet:
                    top = float(self.store.scalar(_Q_INJECTION_LIKE, {"call": self.call_id}, 0.0) or 0.0)
                    naming = int(self.store.scalar(_Q_NAMED_BY_UNTRUSTED, {"call": self.call_id, "dest": w["id"]}, 0) or 0)
                    quiet = top < LIKELY_INJECTION and not naming and not self._injected_refs()
                f = self.finding(
                    "TT005", action="allow" if quiet else "ask",
                    severity="info" if quiet else "high",
                    title=f"{w['name']} would be changed in a session that holds untrusted content",
                    explanation=(f"{w['name']} is loaded into future sessions or run automatically, and this session "
                                 f"has read untrusted content ({source}). Check that the change is what you asked "
                                 "for. After reviewing the file, `tainttrail trust <path>` clears the mark."),
                    path=path, query=query, params=params,
                )
            if f:
                out.append(f)
        return out

    # -- TT007 ---------------------------------------------------------------------------

    def exec_injected(self) -> list[Finding]:
        call = self.call
        if call is None or not self.untrusted_in_session:
            return []
        if call.executes_download:
            sources = [d for d in self.targets(S.FETCHES, S.EXECUTES, S.SENDS_TO) if not d["local"]]
            injected = [
                d for d in sources
                if d["by_untrusted"] and not d["by_trusted"] and not d["trusted"] and not d["by_user"]
                and not self._not_a_stranger(d, sources)
            ]
            injected.sort(key=lambda d: (_SPECIFICITY.get(d["kind"], 9), -len(d["value"])))
            if injected:
                d = injected[0]
                path, query, params = self.run_path("TT007.download", dest=d["id"])
                f = self.finding(
                    "TT007", action="deny",
                    title=f"Code from {_dest_name(d)} would be downloaded and run",
                    explanation=(f"{_cap(path[0].title if path else 'untrusted content')} named {_dest_name(d)}, and "
                                 "this command downloads from it and runs the result. Nothing you typed mentions "
                                 "that source."),
                    path=path, query=query, params=params,
                )
                return [f] if f else []
        saved = [(t, src) for t, src in call.extra.get("derived", []) if _SCRIPT_NAME.search(t)
                 and src.startswith("url:")]
        if saved and not call.executes_download:
            sources = [d for d in self.targets(S.FETCHES) if not d["local"] and d["via"] != "suffix"]
            injected = [d for d in sources if d["by_untrusted"] and not d["by_trusted"] and not d["trusted"]
                        and not d["by_user"] and not self._not_a_stranger(d, self.targets(S.FETCHES))]
            injected.sort(key=lambda d: (_SPECIFICITY.get(d["kind"], 9), -len(d["value"])))
            if injected:
                d = injected[0]
                path, query, params = self.run_path("TT007.download", dest=d["id"])
                name = saved[0][0].rsplit("/", 1)[-1]
                f = self.finding(
                    "TT007", action="ask", severity="high",
                    title=f"A script would be saved from {_dest_name(d)}, which only untrusted content named",
                    explanation=(f"{_cap(path[0].title if path else 'untrusted content')} named {_dest_name(d)}, and "
                                 f"this command saves {name} from there. Running it later will be blocked; decide "
                                 "now whether you want it on disk at all."),
                    path=path, query=query, params=params,
                )
                return [f] if f else []
        if any(a.rel == S.EXECUTES and a.entity.kind == "file" for a in call.actions):
            # Download now, run later: the file on disk still came from where it came from.
            for key in ("TT007.staged", "TT007.staged.host"):
                path, query, params = self.run_path(key)
                if not path:
                    continue
                named = path[1]
                who = self.provenance(named.node_id)
                if who["trusted"] or who["by_trusted"] or who["by_user"] or who["local"]:
                    continue
                file_step = path[-2]
                f = self.finding(
                    "TT007", action="deny",
                    title=f"{_cap(file_step.title)} was downloaded from {named.title} and would now be run",
                    explanation=(f"{_cap(path[0].title)} named {named.title}. An earlier command downloaded "
                                 f"{file_step.title} from there, and this call runs it. Nothing you typed mentions "
                                 "that source."),
                    path=path, query=query, params=params,
                )
                return [f] if f else []
        if call.tool == "Bash" and (call.is_sink or call.executes_download):
            row = self.store.one(_Q_CARRIED_UNTRUSTED, {"call": self.call_id, "kinds": ["line"]})
            if row and row["n"] >= 1:
                path, query, params = self.run_path("TT007.copied")
                # Copying an install command from documentation is ordinary work. Copying it
                # from text that reads like instructions to the agent is not.
                likely = bool(path) and self._injection_score(path[0].node_id) >= LIKELY_INJECTION
                f = self.finding(
                    "TT007", action="ask" if likely else "allow", severity="high" if likely else "info",
                    title="A network command was copied from untrusted content",
                    explanation=(f"This command repeats text from {path[0].title if path else 'untrusted content'} "
                                 "and it reaches the network. Run it only if you would have typed it yourself."),
                    path=path, query=query, params=params,
                )
                return [f] if f else []
        return []

    # -- TT010 ---------------------------------------------------------------------------

    def _is_guard_file(self, path: str) -> bool:
        if self.cfg is None:
            return False
        home = self.cfg.home.as_posix().rstrip("/")
        return path == home or path.startswith(home + "/") or bool(_SETTINGS_FILE.search(path))

    def _injected_refs(self) -> list[dict[str, Any]]:
        """Hosts and links in the written text that only untrusted content named."""
        return [d for d in self.targets(S.REFERENCES)
                if d["kind"] in ("host", "url") and not d["local"] and d["by_untrusted"]
                and not d["by_trusted"] and not d["trusted"] and not d["by_user"]]

    def _settings_change(self, path: str) -> str:
        """What a write does to a settings file: "guard", "permissions" or "other".

        The edit is applied to the file as it is on disk and both versions are parsed. "guard": the
        hook settings differ, or either version does not parse (a file that does not parse registers
        no hook). "permissions": only narrow rules were added to permissions.allow / ask / deny.
        """
        call = self.call
        if call is None or not _SETTINGS_FILE.search(path) or call.tool not in ("Edit", "MultiEdit", "Write"):
            return "guard"
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                before_text = fh.read()
        except OSError:
            before_text = None
        if call.tool == "Write":
            after_text = call.arg_text or ""
        else:
            if before_text is None:
                return "guard"
            after_text = before_text
            for old, new, every in call.extra.get("edits") or []:
                if not old or old not in after_text:
                    return "guard"
                after_text = after_text.replace(old, new) if every else after_text.replace(old, new, 1)
        try:
            before = json.loads(before_text) if before_text is not None else {}
            after = json.loads(after_text)
        except ValueError:
            return "guard"
        if not isinstance(before, dict) or not isinstance(after, dict):
            return "guard"
        if any(before.get(k) != after.get(k) for k in ("hooks", "disableAllHooks")):
            return "guard"
        rest_b = {k: v for k, v in before.items() if k != "permissions"}
        rest_a = {k: v for k, v in after.items() if k != "permissions"}
        pb, pa = before.get("permissions") or {}, after.get("permissions") or {}
        if rest_b != rest_a or not isinstance(pb, dict) or not isinstance(pa, dict):
            return "other"
        if {k: v for k, v in pb.items() if k not in ("allow", "ask", "deny")} != {k: v for k, v in pa.items() if k not in ("allow", "ask", "deny")}:
            return "other"
        if [r for r in pb.get("deny") or [] if r not in (pa.get("deny") or [])]:
            return "other"          # a deny rule was removed
        added = [r for r in pa.get("allow") or [] if r not in (pb.get("allow") or [])]
        narrow = re.compile(r"^[A-Za-z_]+\((?![*:)])[^()]*[A-Za-z0-9][^()]*\)$")
        risky = re.compile(r"^Bash\((?:curl|wget|sh|bash|zsh|python\d*|node|eval|nc|ssh|scp|rm|sudo|env|git push)\b")
        if any(not isinstance(r, str) or not narrow.match(r) or risky.match(r) for r in added):
            return "other"
        return "permissions"

    def _touches_guard(self, path: str) -> bool:
        """Whether a write to a guard file can change the guard.

        Adding ``Bash(npm test)`` to ``permissions.allow`` in ``settings.json`` leaves the hook
        block alone. Anything under the guard's own directory, and any write whose effect cannot
        be read (a shell command), counts.
        """
        call = self.call
        if call is None or not _SETTINGS_FILE.search(path) or call.tool not in ("Edit", "MultiEdit", "Write"):
            return True
        return self._settings_change(path) == "guard"

    def tamper(self) -> list[Finding]:
        call = self.call
        if call is None:
            return []
        targets = [a.entity for a in call.actions if a.rel == S.WRITES and a.entity.kind == "file"
                   and self._is_guard_file(a.entity.value) and self._touches_guard(a.entity.value)]
        by_command = bool(_TAMPER_COMMAND.search(call.arg_text or ""))
        if not targets and not by_command:
            return []
        action = "deny" if self.untrusted_in_session else "ask"
        if targets:
            path, query, params = self.run_path("TT010", dest=targets[0].id)
            what = f"change {targets[0].name}"
        else:
            path, query, params = [self.step(S.TOOL_CALL, self.call_id)], "", {}
            what = "switch the guard off"
        tail = (" The session holds untrusted content, so this is blocked."
                if self.untrusted_in_session else " Approve it only if you asked for it.")
        f = self.finding(
            "TT010", action=action,
            title=f"This call would {what}",
            explanation=(f"This call would {what}, which decides whether TaintTrail keeps watching this agent."
                         + tail),
            path=path, query=query, params=params,
        )
        return [f] if f else []


_SPECIFICITY = {"repo": 0, "email": 1, "mcp": 2, "url": 3, "host": 4}
_GENERIC_VAR = frozenset("api key keys token tokens secret secrets access auth password passwd pwd id client private public "
                         "test prod live dev staging service app user account bearer oauth url host".split())
_VAR_ALIASES = {"gh": "github", "npm": "npmjs", "aws": "amazonaws", "gcp": "googleapis", "pg": "paygate"}


def _stem_match(var: str, places: list[str]) -> bool:
    """Does a variable's name say it belongs to one of these hosts or repositories?

    GITHUB_TOKEN and api.github.com share "github"; PYPI_TOKEN and upload.pypi.org share "pypi".
    AWS_SECRET_ACCESS_KEY and paste.example share nothing.
    """
    stems = [t for t in re.split(r"[^a-z0-9]+", var.lower()) if len(t) >= 2 and t not in _GENERIC_VAR]
    stems += [_VAR_ALIASES[t] for t in stems if t in _VAR_ALIASES]
    labels = [lab for place in places for lab in re.split(r"[^a-z0-9]+", place.lower()) if len(lab) >= 3]
    return any(len(s) >= 3 and (s in lab or lab in s) for s in stems for lab in labels)


def _dest_name(dest: dict[str, Any] | None) -> str:
    """How a destination is named in a sentence: the host for a URL, the value otherwise."""
    if not dest:
        return "an unknown destination"
    if dest["kind"] == "url":
        host = _host_id(dest["value"])
        return _name(host.split(":", 1)[1]) if host else _short_url(dest["value"])
    if dest["kind"] == "mcp":
        return f"the {_name(str(dest['value']).split('/', 1)[0], 40)} MCP server"
    return _name(dest["value"])


def _host_id(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return f"host:{host.lower().rstrip('.')}" if host else None


def _named_by_user(d: dict[str, Any], dests: list[dict[str, Any]]) -> bool:
    if d["by_user"]:
        return True
    if d["kind"] == "url":
        host = _host_id(d["value"])
        return any(x["id"] == host and x["by_user"] for x in dests)
    return False


def path_line(steps: list[PathStep]) -> str:
    """A path on one line: ``web page x -> attacker.example <- call #7 ...``.

    The arrow follows the stored edge; a step joined by shared session context rather
    than an edge is shown with ``~``.
    """
    parts: list[str] = []
    for step in steps:
        parts.append(step.title)
        if step.rel is None:
            continue
        if step.rel.isupper():
            parts.append("->" if step.forward else "<-")
        else:
            parts.append("~")
    return " ".join(parts)


def reverse_path(steps: list[PathStep]) -> list[PathStep]:
    """The same path read from the other end. Each edge moves to the step it now leaves."""
    out: list[PathStep] = []
    n = len(steps)
    for i in range(n - 1, -1, -1):
        before = steps[i - 1] if i > 0 else None
        out.append(replace(steps[i], rel=before.rel if before else None,
                           forward=(not before.forward) if before else True))
    return out


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _describe_payload(carried: list[dict[str, Any]], uploaded: list[dict[str, Any]]) -> str:
    """What the call carries, in words. Never the data itself."""
    if uploaded:
        names = []
        for u in uploaded:
            name = u["name"] or u["id"]
            if u.get("kind") == "env":
                names.append("the process environment" if name == "*" else f"${name}")
            else:
                names.append(f"the contents of {name}")
        return names[0] if len(names) == 1 else f"{names[0]} and {len(names) - 1} more"
    top = carried[0]
    source = top.get("source") or "sensitive content"
    if top["strong"]:
        # One secret can match through several fingerprints (the value and its parts);
        # count kinds of secret, not fingerprints.
        n = len(set(top.get("hints") or [])) or 1
        return f"{n} secret{'s' if n != 1 else ''} from {source}"
    return f"text copied from {source}"


def evaluate_pre(store: Store, cfg: Config, call_id: str, call: CallAnalysis | None) -> list[Finding]:
    """Judge a recorded tool call before it runs."""
    ev = _Eval(store, cfg, call_id, call)
    if not ev.ctx:
        return []
    findings = [*ev.tamper(), *ev.egress(), *ev.steered_read(), *ev.persist(), *ev.exec_injected()]
    return [f for f in findings if f is not None]


def evaluate_post(store: Store, cfg: Config, call_id: str, content_id: str,
                  content: ContentAnalysis | None) -> list[Finding]:
    """Look at what a tool returned. These findings inform; they never block."""
    ev = _Eval(store, cfg, call_id, None)
    out: list[Finding] = []
    node, extra = ev.describe(S.CONTENT, content_id)
    props = node["props"]
    title = node_title(node, extra)

    if props.get("untrusted") and float(props.get("injection_score") or 0.0) >= INJECTION_WARN_SCORE:
        markers = ", ".join(props.get("injection_markers") or []) or "instruction-like phrasing"
        f = ev.finding(
            "TT009", action="allow",
            title=f"{_cap(title)} reads like instructions aimed at the agent",
            explanation=(f"{_cap(title)} is untrusted and contains {markers}. The agent has been told to treat it "
                         "as data. Calls that follow are checked against it."),
            path=[ev.step(S.CONTENT, content_id, role="untrusted")],
            target_id=content_id, target_label=S.CONTENT,
        )
        if f:
            out.append(f)

    path, query, params = ev.run_path("TT008", content=content_id)
    if path:
        f = ev.finding(
            "TT008", action="allow",
            title=f"{_cap(path[1].title)} was written by an earlier session under untrusted influence",
            explanation=(f"{_cap(path[1].title)} was written in another session while that session held "
                         f"{path[2].title}. What it says is treated as untrusted here too."),
            path=reverse_path(path), query=query, params=params,
            target_id=content_id, target_label=S.CONTENT,
        )
        if f:
            out.append(f)
    return out


def explain_path(store: Store, call_id: str) -> list[PathStep]:
    """The shortest chain of evidence from any untrusted content of the session to a call."""
    ev = _Eval(store, None, call_id, None)
    if not ev.ctx:
        return []
    row = store.one(CYPHER["explain"].strip(), {"call": call_id, "session": ev.ctx["sid"]})
    return ev.steps_from_path(row["p"]) if row and row.get("p") else []
