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

import re
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

from . import schema as S
from .config import Config
from .model import CallAnalysis, ContentAnalysis, Finding, PathStep
from .store import Store

# One fingerprint of a secret or a long token is evidence on its own. Lines of text
# repeat by coincidence, so it takes several.
MIN_LINE_CHUNKS = 3
INJECTION_WARN_SCORE = 0.5


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
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END, u.seq
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
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END
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
ORDER BY CASE k.kind WHEN 'secret' THEN 0 WHEN 'token' THEN 1 ELSE 2 END
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
    "TT002": """
MATCH (c:ToolCall {id: $call})
MATCH (u:Content {session_id: c.session_id, untrusted: true}) WHERE u.seq < c.seq
MATCH (s:Content {session_id: c.session_id, sensitive: true}) WHERE s.seq < c.seq
RETURN u, c, s
ORDER BY u.seq DESC, s.seq DESC
LIMIT 1""",
    # untrusted content -> sensitive file <- call
    "TT004": """
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(f:Entity {sensitive: true})<-[:READS]-(c:ToolCall {id: $call})
WHERE u.session_id = c.session_id AND u.seq < c.seq
  AND NOT EXISTS {
    MATCH (t:Content)-[:MENTIONS]->(f)
    WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false
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

_Q_CONTEXT = """
MATCH (c:ToolCall {id: $call})
OPTIONAL MATCH (u:Content {session_id: c.session_id, untrusted: true}) WHERE u.seq < c.seq
WITH c, u ORDER BY u.seq DESC
WITH c, collect(u.id) AS us
OPTIONAL MATCH (x:Content {session_id: c.session_id, sensitive: true}) WHERE x.seq < c.seq
WITH c, us, x ORDER BY x.seq DESC
RETURN c.session_id AS sid, c.seq AS seq, c.ts AS ts, c.tool AS tool,
       us[0] AS last_untrusted, size(us) AS n_untrusted,
       collect(x.id)[0] AS last_sensitive, count(x) AS n_sensitive
"""

# Where a call sends, fetches or executes, and who named each place earlier in the session.
_Q_TARGETS = """
MATCH (c:ToolCall {id: $call})-[r]->(d:Entity)
WHERE type(r) IN $rels
RETURN DISTINCT d.id AS id, d.kind AS kind, d.value AS value, d.name AS name,
  coalesce(d.local, false) AS local, coalesce(d.trusted, false) AS trusted,
  EXISTS { MATCH (u:Content {untrusted: true})-[:MENTIONS]->(d)
           WHERE u.session_id = c.session_id AND u.seq < c.seq } AS by_untrusted,
  EXISTS { MATCH (t:Content)-[:MENTIONS]->(d)
           WHERE t.session_id = c.session_id AND t.seq < c.seq AND coalesce(t.untrusted, false) = false } AS by_trusted,
  EXISTS { MATCH (q:Content {origin: 'user'})-[:MENTIONS]->(d)
           WHERE q.session_id = c.session_id AND q.seq < c.seq } AS by_user
ORDER BY id
"""

_Q_CARRIED_SENSITIVE = """
MATCH (c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(p:Content {sensitive: true})
WITH p, collect(DISTINCT k) AS ks
OPTIONAL MATCH (p)-[:FROM]->(src:Entity)
RETURN p.id AS content, src.name AS source,
       size([k IN ks WHERE k.kind IN ['secret', 'token']]) AS strong,
       size([k IN ks WHERE k.kind = 'line']) AS lines,
       [k IN ks WHERE k.kind = 'secret' | k.hint] AS hints
ORDER BY strong DESC, lines DESC
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

_TAMPER_COMMAND = re.compile(r"TAINTTRAIL_DISABLE|tainttrail\s+uninstall|-m\s+tainttrail\s+uninstall")
_SETTINGS_FILE = re.compile(r"/\.claude/settings(\.local)?\.json$")


# -- titles ------------------------------------------------------------------------------


def _short_url(url: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", url)


def content_title(props: dict[str, Any], src_kind: str | None = None, src_value: str | None = None,
                  src_name: str | None = None, tool: str | None = None) -> str:
    origin = props.get("origin")
    if origin == "user":
        return "your prompt"
    if origin == "memory":
        return f"{src_name or 'an instruction file'}, loaded at session start"
    if src_kind == "url" and src_value:
        return f"web page {_short_url(src_value)}"
    if src_kind == "file" and src_name:
        return f"contents of {src_name}"
    if src_kind == "host" and src_value:
        return f"response from {src_value}"
    if src_value:
        return str(src_value)
    if tool:
        return f"output of {tool}"
    return "tool output"


def node_title(node: dict[str, Any], extra: dict[str, Any] | None = None) -> str:
    """A short human description of a node as returned by ``store.to_plain``."""
    labels = node.get("labels") or []
    p = node.get("props") or {}
    extra = extra or {}
    if S.CONTENT in labels:
        return content_title(p, extra.get("src_kind"), extra.get("src_value"), extra.get("src_name"), extra.get("tool"))
    if S.TOOL_CALL in labels:
        return f"call #{p.get('num') or p.get('seq') or '?'}  {p.get('summary') or p.get('tool') or ''}".rstrip()
    if S.ENTITY in labels:
        kind, value = p.get("kind"), str(p.get("value") or "")
        if kind == "file":
            return f"file {p.get('name') or value}"
        if kind == "url":
            return _short_url(value)
        if kind == "env":
            return "the process environment" if value == "*" else f"${value}"
        if kind == "repo":
            return f"repository {value}"
        return value
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
        self._described: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}

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

    def title_of(self, label: str, node_id: str | None) -> str:
        if not node_id:
            return "untrusted content"
        node, extra = self.describe(label, node_id)
        return node_title(node, extra)

    # -- the egress ladder: TT001, TT006, TT003, TT002 ----------------------------------

    def egress(self) -> list[Finding]:
        call = self.call
        if call is None or not call.is_sink:
            return []
        dests = self.targets(S.SENDS_TO)
        external = [d for d in dests if not d["local"]]
        if dests and not external:
            return []  # everything stays on this machine or the local network
        safe_ids = {d["id"] for d in external if d["trusted"] or d["by_user"]}
        for d in external:  # a URL is as safe as its host
            if d["kind"] == "url" and d["id"] not in safe_ids:
                host = _host_id(d["value"])
                if host in safe_ids:
                    safe_ids.add(d["id"])
        all_safe = bool(external) and all(d["id"] in safe_ids for d in external)
        if not external and call.extra.get("dest_trusted"):
            all_safe = True
        user_named = bool(external) and all(_named_by_user(d, external) for d in external)
        injected = [
            d for d in external
            if d["by_untrusted"] and not d["by_trusted"] and not d["trusted"] and not d["by_user"]
        ]
        injected.sort(key=lambda d: _SPECIFICITY.get(d["kind"], 9))

        carried = [
            r for r in self.store.run(_Q_CARRIED_SENSITIVE, {"call": self.call_id})
            if r["strong"] >= 1 or r["lines"] >= MIN_LINE_CHUNKS
        ]
        uploaded = self.store.run(_Q_UPLOADED_SENSITIVE, {"call": self.call_id})
        primary = (injected or external or [None])[0]
        dest_name = primary["value"] if primary else "an unknown destination"

        if carried or uploaded:
            what = _describe_payload(carried, uploaded)
            f = self._sensitive_egress(primary, injected, carried, uploaded, what, dest_name,
                                       user_named, all_safe)
            return [f] if f else []

        payload = bool(call.extra.get("carries_payload", True))
        followed = bool(self.store.scalar(_Q_FOLLOWED_LINK, {"call": self.call_id}, 0))
        if injected and payload and not followed:
            d = injected[0]
            path, query, params = self.run_path("TT003", dest=d["id"])
            source = path[0].title if path else "untrusted content"
            sev = "high" if self.sensitive_in_session else "medium"
            more = " Sensitive data has also been read in this session." if self.sensitive_in_session else ""
            f = self.finding(
                "TT003", action="ask", severity=sev,
                title=f"Data would go to {d['value']}, which only untrusted content named",
                explanation=(f"{_cap(source)} named {d['value']}. Nothing you typed and no trusted content "
                             f"mentions it, and this call sends data there.{more}"),
                path=path, query=query, params=params,
            )
            return [f] if f else []

        if self.untrusted_in_session and self.sensitive_in_session and payload and not all_safe and not followed:
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
                             f"data to {dest_name}. No copy of the sensitive data was found in it, so this is a "
                             "precaution, not proof."),
                path=path, query=CYPHER["TT002"].strip(), params={"call": self.call_id},
            )
            return [f] if f else []
        return []

    def _sensitive_egress(self, primary, injected, carried, uploaded, what, dest_name,
                          user_named, all_safe) -> Finding | None:
        dest_id = primary["id"] if primary else None
        use_upload = bool(uploaded) and not carried
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
            action = "ask" if (user_named and not injected) else "deny"
            if action == "ask":
                explanation += " You named this destination yourself, so you can approve it."
            return self.finding("TT001", action=action, severity=severity,
                                title=f"{_cap(what)} would be sent to {dest_name}",
                                explanation=explanation, path=path, query=query, params=params)

        # No untrusted content anywhere upstream: a leak, not an injection.
        single_credential = (not uploaded and len(carried) == 1 and carried[0]["strong"] == 1
                             and carried[0]["lines"] == 0)
        if user_named:
            action, severity = "allow", "info"
            tail = "You named this destination in your prompt."
        elif all_safe and single_credential:
            action, severity = "allow", "info"
            tail = "One credential sent to an allow-listed host looks like ordinary authentication."
        else:
            action, severity = "ask", "high"
            tail = "No untrusted content is involved, so this may be intended. Approve it if it is."
        return self.finding("TT006", action=action, severity=severity,
                            title=f"{_cap(what)} would be sent to {dest_name}",
                            explanation=f"This call would send {what} to {dest_name}. {tail}",
                            path=path, query=query, params=params)

    # -- TT004 ---------------------------------------------------------------------------

    def steered_read(self) -> list[Finding]:
        if not self.untrusted_in_session:
            return []
        path, query, params = self.run_path("TT004")
        if not path:
            return []
        f = self.finding(
            "TT004", action="ask",
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
                continue  # TT010 speaks for these
            path, query, params = self.run_path("TT005.copy", dest=w["id"])
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
                f = self.finding(
                    "TT005", action="allow" if w["by_user"] else "ask",
                    severity="info" if w["by_user"] else "high",
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
            ]
            injected.sort(key=lambda d: _SPECIFICITY.get(d["kind"], 9))
            if injected:
                d = injected[0]
                path, query, params = self.run_path("TT007.download", dest=d["id"])
                f = self.finding(
                    "TT007", action="deny",
                    title=f"Code from {d['value']} would be downloaded and run",
                    explanation=(f"{_cap(path[0].title if path else 'untrusted content')} named {d['value']}, and "
                                 "this command downloads from it and runs the result. Nothing you typed mentions "
                                 "that source."),
                    path=path, query=query, params=params,
                )
                return [f] if f else []
        if call.tool == "Bash" and (call.is_sink or call.executes_download):
            row = self.store.one(_Q_CARRIED_UNTRUSTED, {"call": self.call_id, "kinds": ["line"]})
            if row and row["n"] >= 1:
                path, query, params = self.run_path("TT007.copied")
                f = self.finding(
                    "TT007", action="ask", severity="high",
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

    def tamper(self) -> list[Finding]:
        call = self.call
        if call is None:
            return []
        targets = [a.entity for a in call.actions if a.rel == S.WRITES and a.entity.kind == "file"
                   and self._is_guard_file(a.entity.value)]
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
        names = [u["name"] or u["id"] for u in uploaded]
        names = ["the process environment" if n in ("*", "env:*") else n for n in names]
        head = names[0] if len(names) == 1 else f"{names[0]} and {len(names) - 1} more"
        return f"the contents of {head}" if not head.startswith("the ") else head
    top = carried[0]
    source = top.get("source") or "sensitive content"
    if top["strong"]:
        n = top["strong"]
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
