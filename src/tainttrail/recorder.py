"""Writes hook events into the graph.

The recorder knows the shape of the graph and nothing about policy. It turns a prompt,
a tool call or a tool result into nodes and evidence edges; ``rules.py`` then asks
questions of what is there.
"""

from __future__ import annotations

import configparser
import json
import os
import re
from dataclasses import asdict
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import schema as S
from .config import Config
from .model import CallAnalysis, ContentAnalysis, EntityRef, Finding, HookEvent, ToolLabels
from .store import Store

_SECRETISH_ENV = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH", re.I)

# A file copied from untrusted content is tainted once this many distinct fingerprints
# of that content appear in what was written. One shared line is a coincidence.
COPY_TAINT_MIN_CHUNKS = 3
COPY_TAINT_MIN_INJECTION = 0.3

# Labels a user or a model set by hand outrank the built-in tables.
_STICKY_LABEL_SOURCES = ("user", "llm", "introspect")


def parse_tool_name(name: str) -> tuple[str, str]:
    """``mcp__github__get_issue`` -> ``("github", "get_issue")``; ``Read`` -> ``("builtin", "Read")``."""
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    return "builtin", name


class Recorder:
    def __init__(self, store: Store, cfg: Config) -> None:
        self.store = store
        self.cfg = cfg

    # -- sessions ---------------------------------------------------------------------

    def ensure_session(self, event: HookEvent) -> None:
        """Create the session on first sight. Hooks can be installed mid-session."""
        if self.store.one("MATCH (s:Session {id: $id}) RETURN s.id AS id", {"id": event.session_id}):
            return
        self.store.write(
            """
            MERGE (s:Session {id: $id})
            ON CREATE SET s.agent_kind = $agent_kind, s.cwd = $cwd, s.started_at = $ts,
                          s.last_seq = 0, s.mode = $mode
            MERGE (a:Agent {id: $agent_kind})
            ON CREATE SET a.kind = $agent_kind, a.name = $agent_kind
            MERGE (s)-[:BY]->(a)
            """,
            {"id": event.session_id, "agent_kind": event.agent_kind, "cwd": event.cwd,
             "ts": event.ts, "mode": self.cfg.mode},
        )

    def session_start(self, event: HookEvent) -> list[str]:
        """Create the session, trust the project's git remotes, inherit tainted memory.

        Returns the ids of the ``Content`` nodes that stand for instruction files the
        harness loads by itself and that an earlier session wrote under the influence
        of untrusted content.
        """
        self.ensure_session(event)
        self._trust_git_remotes(event)
        return self._inherit_memory(event)

    def next_seq(self, session_id: str) -> int:
        seq = self.store.scalar(
            "MATCH (s:Session {id: $id}) SET s.last_seq = coalesce(s.last_seq, 0) + 1 RETURN s.last_seq",
            {"id": session_id},
        )
        if seq is None:
            raise LookupError(f"unknown session {session_id}")
        return int(seq)

    def _trust_git_remotes(self, event: HookEvent) -> None:
        """Remotes that exist when the session starts are destinations the user chose.

        A remote added later, during the session, gets no such trust.
        """
        refs = git_remote_repos(self.cfg.root)
        if not refs:
            return
        self._merge_entities(refs, event.ts)
        self.store.write(
            "UNWIND $ids AS id MATCH (e:Entity {id: id}) SET e.trusted = true, e.trust_reason = 'git remote'",
            {"ids": [r.id for r in refs]},
        )

    def _inherit_memory(self, event: HookEvent) -> list[str]:
        strengths = ["copy", "context"] if self.cfg.mode == "strict" else ["copy"]
        rows = self.store.run(
            """
            MATCH (e:Entity {kind: 'file'})-[t:TAINTED_BY]->(u:Content)
            WHERE coalesce(e.protected, false) AND t.strength IN $strengths
            RETURN e.id AS eid, e.value AS path, e.name AS name, collect(u.id)[0] AS source
            ORDER BY path
            """,
            {"strengths": strengths},
        )
        root = self.cfg.root.as_posix().rstrip("/") + "/"
        home_claude = os.path.expanduser("~/.claude/")
        created: list[str] = []
        n = 0
        for row in rows:
            path = row["path"] or ""
            if not (path.startswith(root) or path.startswith(home_claude)):
                continue
            if not is_instruction_file(path) or not os.path.exists(path):
                continue
            n += 1
            cid = f"{event.session_id}:memory:{n}"
            self.store.write(
                """
                MATCH (s:Session {id: $sid})
                MATCH (e:Entity {id: $eid})
                MERGE (c:Content {id: $cid})
                ON CREATE SET c.session_id = $sid, c.seq = 0, c.ts = $ts, c.origin = 'memory',
                              c.untrusted = true, c.sensitive = false, c.reasons = $reasons,
                              c.injection_score = 0.0, c.bytes = 0, c.sha = '', c.excerpt = $excerpt
                MERGE (s)-[:RECEIVED]->(c)
                MERGE (c)-[:FROM]->(e)
                """,
                {"sid": event.session_id, "eid": row["eid"], "cid": cid, "ts": event.ts,
                 "reasons": [f"inherited:{row['name']}"],
                 "excerpt": f"{row['name']} was written by an earlier session that held untrusted content"},
            )
            created.append(cid)
        return created

    # -- tools --------------------------------------------------------------------------

    def tool_labels(self, agent_kind: str, tool_name: str) -> ToolLabels:
        """Capabilities of a tool: labels set by hand win, otherwise the classifier's."""
        tool_id = f"{agent_kind}::{tool_name}"
        row = self.store.one("MATCH (t:Tool {id: $id}) RETURN properties(t) AS p", {"id": tool_id})
        if row and row["p"].get("label_source") in _STICKY_LABEL_SOURCES:
            return ToolLabels.from_props(row["p"])
        from .classify import classify_tool  # imported late: classify loads a data file

        labels = classify_tool(tool_name)
        if not row:
            self.ensure_tool(agent_kind, tool_name, labels)
        return labels

    def ensure_tool(self, agent_kind: str, tool_name: str, labels: ToolLabels) -> str:
        tool_id = f"{agent_kind}::{tool_name}"
        server, _ = parse_tool_name(tool_name)
        self.store.write(
            """
            MERGE (t:Tool {id: $id})
            ON CREATE SET t.name = $name, t.server = $server, t.agent_kind = $agent_kind,
                          t.observed = true, t.permission = 'default', t += $labels
            WITH t
            UNWIND $caps AS cap
            MATCH (k:Capability {name: cap})
            MERGE (t)-[r:HAS_CAPABILITY]->(k)
            ON CREATE SET r.source = $source, r.confidence = $confidence
            """,
            {"id": tool_id, "name": tool_name, "server": server, "agent_kind": agent_kind,
             "labels": labels.to_props(), "caps": labels.capabilities(),
             "source": labels.source, "confidence": float(labels.confidence)},
        )
        return tool_id

    # -- prompts ---------------------------------------------------------------------------

    def record_prompt(self, event: HookEvent, analysis: ContentAnalysis) -> str:
        self.ensure_session(event)
        seq = self.next_seq(event.session_id)
        cid = f"{event.session_id}:prompt:{seq}"
        self._write_content(cid, event, seq, analysis)
        self.store.write(
            "MATCH (s:Session {id: $sid}) MATCH (c:Content {id: $cid}) MERGE (s)-[:RECEIVED]->(c)",
            {"sid": event.session_id, "cid": cid},
        )
        return cid

    # -- tool calls ------------------------------------------------------------------------

    def call_id(self, event: HookEvent) -> str | None:
        """The id a call gets when the harness names it; None when it must be allocated."""
        return f"{event.session_id}:{event.tool_use_id}" if event.tool_use_id else None

    def find_call(self, event: HookEvent) -> str | None:
        """The recorded call a post-tool event belongs to, or None if none was recorded."""
        cid = self.call_id(event)
        if cid:
            row = self.store.one("MATCH (c:ToolCall {id: $id}) RETURN c.id AS id", {"id": cid})
            return row["id"] if row else None
        row = self.store.one(
            """
            MATCH (c:ToolCall {session_id: $sid})
            WHERE c.status = 'pending' AND c.tool = $tool AND c.input_sha = $sha
            RETURN c.id AS id ORDER BY c.seq DESC LIMIT 1
            """,
            {"sid": event.session_id, "tool": event.tool_name, "sha": self._input_sha(event)},
        )
        return row["id"] if row else None

    def record_call(self, event: HookEvent, analysis: CallAnalysis, carried: Iterable[str] | None = None) -> str:
        """Write a tool call and everything its arguments say about it. Idempotent per id.

        ``carried`` are the candidate fingerprints of the argument text; by default they
        are computed here. Only fingerprints that already exist as ``Chunk`` nodes become
        ``CARRIES`` edges, so arguments never add fingerprints of their own.
        """
        self.ensure_session(event)
        existing = self.call_id(event)
        if existing and self.store.one("MATCH (c:ToolCall {id: $id}) RETURN c.id AS id", {"id": existing}):
            return existing
        if carried is None:
            from .extract import carried_fingerprints

            carried = carried_fingerprints(analysis.arg_text, self.cfg.key()) if analysis.arg_text else []
        carried = list(dict.fromkeys(carried))

        with self.store.transaction():
            seq = self.next_seq(event.session_id)
            cid = existing or f"{event.session_id}:{seq}"
            # ``seq`` orders everything in the session; ``num`` counts tool calls only and
            # is what people see ("call #3").
            num = int(self.store.scalar(
                "MATCH (s:Session {id: $id}) SET s.calls = coalesce(s.calls, 0) + 1 RETURN s.calls",
                {"id": event.session_id},
            ))
            tool_id = self.ensure_tool(event.agent_kind, event.tool_name, analysis.labels)
            self.store.write(
                """
                MATCH (s:Session {id: $sid})
                CREATE (c:ToolCall {id: $id})
                SET c += $props
                MERGE (s)-[:RAN]->(c)
                WITH s, c
                MATCH (t:Tool {id: $tool_id})
                MERGE (c)-[:INVOKES]->(t)
                WITH s, c
                OPTIONAL MATCH (prev:ToolCall {id: s.last_call})
                FOREACH (p IN CASE WHEN prev IS NULL THEN [] ELSE [prev] END | MERGE (p)-[:NEXT]->(c))
                SET s.last_call = c.id
                """,
                {"sid": event.session_id, "id": cid, "tool_id": tool_id, "props": {
                    "session_id": event.session_id, "seq": seq, "num": num, "ts": event.ts,
                    "tool": event.tool_name, "agent": event.agent or "main",
                    "summary": analysis.summary[:400], "status": "pending", "decision": "allow",
                    "is_sink": bool(analysis.is_sink), "sink_kind": analysis.sink_kind,
                    "executes_download": bool(analysis.executes_download),
                    "encodes": bool(analysis.encodes), "env_dump": bool(analysis.env_dump),
                    "carries_payload": bool(analysis.extra.get("carries_payload", analysis.is_sink)),
                    "input_sha": self._input_sha(event),
                }},
            )
            self._write_actions(cid, analysis, event.ts)
            if carried:
                self.store.write(
                    """
                    MATCH (c:ToolCall {id: $id})
                    MATCH (k:Chunk) WHERE k.id IN $ids
                    MERGE (c)-[:CARRIES]->(k)
                    """,
                    {"id": cid, "ids": carried},
                )
            self._write_derived(cid, analysis, event.ts)
            # A file the call writes holds what the call carries.
            self.store.write(
                """
                MATCH (c:ToolCall {id: $id})-[:WRITES]->(f:Entity)
                MATCH (c)-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(p:Content {sensitive: true})
                WITH f, sum(CASE WHEN k.kind IN ['secret', 'token'] THEN 1 ELSE 0 END) AS strong,
                     sum(CASE WHEN k.kind = 'line' THEN 1 ELSE 0 END) AS lines
                WHERE strong >= 1 OR lines >= $min_lines
                SET f.sensitive = true
                """,
                {"id": cid, "min_lines": COPY_TAINT_MIN_CHUNKS},
            )
        return cid

    def set_decision(self, call_id: str, action: str) -> None:
        self.store.write(
            """
            MATCH (c:ToolCall {id: $id})
            SET c.decision = $action,
                c.status = CASE WHEN $action = 'deny' THEN 'blocked' ELSE c.status END
            """,
            {"id": call_id, "action": action},
        )

    def _write_actions(self, cid: str, analysis: CallAnalysis, ts: int) -> None:
        actions = [a for a in analysis.actions if a.rel in S.ACTION_RELS]
        self._merge_entities([a.entity for a in actions] + list(analysis.destinations), ts)
        by_rel: dict[str, list[dict[str, Any]]] = {}
        for a in actions:
            by_rel.setdefault(a.rel, []).append({"eid": a.entity.id, "props": _edge_props(a.props)})
        have_sends = {r["eid"] for r in by_rel.get(S.SENDS_TO, [])}
        for dest in analysis.destinations:
            if dest.id not in have_sends:
                by_rel.setdefault(S.SENDS_TO, []).append({"eid": dest.id, "props": {}})
                have_sends.add(dest.id)
        for rel, rows in by_rel.items():
            # rel comes from the fixed ACTION_RELS tuple, never from input.
            self.store.write(
                f"""
                MATCH (c:ToolCall {{id: $id}})
                UNWIND $rows AS row
                MATCH (e:Entity {{id: row.eid}})
                MERGE (c)-[r:{rel}]->(e)
                SET r += row.props
                """,
                {"id": cid, "rows": rows},
            )

    def _write_derived(self, cid: str, analysis: CallAnalysis, ts: int) -> None:
        pairs = [
            {"t": t, "s": s}
            for t, s in analysis.extra.get("derived", [])
            if isinstance(t, str) and isinstance(s, str) and t != s
        ]
        if not pairs:
            return
        refs = [_ref_from_id(x) for p in pairs for x in (p["t"], p["s"])]
        self._merge_entities([r for r in refs if r is not None], ts)
        self.store.write(
            """
            UNWIND $pairs AS p
            MATCH (t:Entity {id: p.t})
            MATCH (s:Entity {id: p.s})
            MERGE (t)-[d:DERIVED_FROM]->(s)
            SET d.call = $id,
                t.sensitive = coalesce(t.sensitive, false) OR coalesce(s.sensitive, false),
                t.untrusted = coalesce(t.untrusted, false) OR coalesce(s.untrusted, false)
                              OR s.kind IN ['url', 'host']
            """,
            {"pairs": pairs, "id": cid},
        )

    # -- tool results ----------------------------------------------------------------------

    def record_result(self, event: HookEvent, call_id: str, content: ContentAnalysis) -> str:
        """Write what a tool returned, then propagate what the finished call implies."""
        self.ensure_session(event)
        with self.store.transaction():
            seq = self.next_seq(event.session_id)
            cid = f"{call_id}:out"
            self._write_content(cid, event, seq, content)
            self.store.write(
                """
                MATCH (c:ToolCall {id: $call})
                MATCH (o:Content {id: $cid})
                MERGE (c)-[:RETURNED]->(o)
                SET c.status = CASE WHEN c.status = 'blocked' THEN 'blocked' ELSE $status END
                """,
                {"call": call_id, "cid": cid, "status": "failed" if event.failed else "done"},
            )
            if content.sensitive and content.source is not None and content.source.kind == "file":
                self.store.write(
                    "MATCH (e:Entity {id: $id}) SET e.sensitive = true", {"id": content.source.id}
                )
            if not event.failed:
                self._taint_written_files(call_id)
        return cid

    def _taint_written_files(self, call_id: str) -> None:
        # Copy taint: the written text repeats fingerprints of untrusted content.
        self.store.write(
            """
            MATCH (c:ToolCall {id: $id})-[:WRITES]->(f:Entity)
            MATCH (c)-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(u:Content {untrusted: true})
            WITH f, u, count(DISTINCT k) AS n
            WHERE n >= $min_chunks OR coalesce(u.injection_score, 0.0) >= $min_injection
                  OR coalesce(f.protected, false)
            MERGE (f)-[t:TAINTED_BY]->(u)
            SET t.strength = 'copy', t.call = $id, t.chunks = n, f.untrusted = true
            """,
            {"id": call_id, "min_chunks": COPY_TAINT_MIN_CHUNKS, "min_injection": COPY_TAINT_MIN_INJECTION},
        )
        # Context taint: an instruction file written while the session held untrusted
        # content, with no verbatim copy to point at.
        self.store.write(
            """
            MATCH (c:ToolCall {id: $id})-[:WRITES]->(f:Entity {protected: true})
            WHERE NOT EXISTS { MATCH (f)-[x:TAINTED_BY]->(:Content) WHERE x.call = $id }
            MATCH (u:Content {session_id: c.session_id, untrusted: true})
            WHERE u.seq < c.seq
            WITH f, u ORDER BY u.seq DESC
            WITH f, collect(u)[0] AS last
            MERGE (f)-[t:TAINTED_BY]->(last)
            ON CREATE SET t.strength = 'context', t.call = $id
            """,
            {"id": call_id},
        )

    def tainted_sources(self, entity_ids: Iterable[str]) -> set[str]:
        """Which of these entities hold content a third party could have written."""
        ids = list(dict.fromkeys(entity_ids))
        if not ids:
            return set()
        rows = self.store.run(
            "MATCH (e:Entity) WHERE e.id IN $ids AND coalesce(e.untrusted, false) RETURN e.id AS id",
            {"ids": ids},
        )
        return {r["id"] for r in rows}

    def trust_entity(self, entity_id: str) -> bool:
        """A human reviewed this file: forget its taint. Returns False if it is unknown."""
        row = self.store.one("MATCH (e:Entity {id: $id}) RETURN e.id AS id", {"id": entity_id})
        if not row:
            return False
        self.store.write(
            "MATCH (e:Entity {id: $id}) OPTIONAL MATCH (e)-[t:TAINTED_BY]->() DELETE t SET e.untrusted = false",
            {"id": entity_id},
        )
        return True

    # -- findings --------------------------------------------------------------------------

    def record_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            if f.target_label not in (S.TOOL_CALL, S.CONTENT):
                raise ValueError(f"a finding cannot flag a {f.target_label}")
            self.store.write(
                f"""
                MERGE (f:Finding {{id: $id}})
                SET f += $props
                WITH f
                MATCH (t:{f.target_label} {{id: $target}})
                MERGE (f)-[:FLAGS]->(t)
                """,
                {"id": f.id, "target": f.target_id, "props": {
                    "rule": f.rule, "name": f.name, "severity": f.severity, "action": f.action,
                    "title": f.title, "explanation": f.explanation, "session_id": f.session_id,
                    "target_id": f.target_id, "target_label": f.target_label, "ts": f.ts,
                    "intended": f.intended or f.action, "query": f.query,
                    "params_json": json.dumps(f.params, sort_keys=True),
                    "path_json": json.dumps([asdict(step) for step in f.path]),
                }},
            )
            by_label: dict[str, list[dict[str, Any]]] = {}
            for ord_, step in enumerate(f.path):
                if step.label in S.NODE_LABELS:
                    by_label.setdefault(step.label, []).append({"id": step.node_id, "ord": ord_})
            for label, rows in by_label.items():
                self.store.write(
                    f"""
                    MATCH (f:Finding {{id: $id}})
                    UNWIND $rows AS row
                    MATCH (n:{label} {{id: row.id}})
                    MERGE (f)-[e:EVIDENCE {{ord: row.ord}}]->(n)
                    """,
                    {"id": f.id, "rows": rows},
                )

    # -- shared pieces ---------------------------------------------------------------------

    def _write_content(self, cid: str, event: HookEvent, seq: int, a: ContentAnalysis) -> None:
        self.store.write(
            "MERGE (c:Content {id: $id}) SET c += $props",
            {"id": cid, "props": {
                "session_id": event.session_id, "seq": seq, "ts": event.ts, "origin": a.origin,
                "untrusted": bool(a.untrusted), "sensitive": bool(a.sensitive),
                "reasons": [str(r) for r in a.reasons], "injection_score": float(a.injection_score),
                "injection_markers": [str(m) for m in a.injection_markers],
                "bytes": int(a.text_bytes), "sha": a.sha,
                # Sensitive text is never excerpted; the keyed hash is all that is kept.
                "excerpt": "" if a.sensitive else a.excerpt[:400],
            }},
        )
        mentions = list(dict.fromkeys(a.mentions))[: self.cfg.max_entities]
        refs = mentions + ([a.source] if a.source is not None else [])
        self._merge_entities(refs, event.ts)
        if mentions:
            self.store.write(
                """
                MATCH (c:Content {id: $cid})
                UNWIND $ids AS eid
                MATCH (e:Entity {id: eid})
                MERGE (c)-[:MENTIONS]->(e)
                """,
                {"cid": cid, "ids": [m.id for m in mentions]},
            )
        if a.source is not None:
            self.store.write(
                "MATCH (c:Content {id: $cid}) MATCH (e:Entity {id: $eid}) MERGE (c)-[:FROM]->(e)",
                {"cid": cid, "eid": a.source.id},
            )
        chunks = a.chunks[: self.cfg.max_chunks]
        if chunks:
            self.store.write(
                """
                MATCH (c:Content {id: $cid})
                UNWIND $chunks AS ch
                MERGE (k:Chunk {id: ch.id})
                ON CREATE SET k.kind = ch.kind, k.hint = ch.hint, k.length = ch.length
                ON MATCH SET k.kind = CASE WHEN ch.kind = 'secret' THEN 'secret' ELSE k.kind END,
                             k.hint = CASE WHEN ch.kind = 'secret' AND ch.hint <> '' THEN ch.hint ELSE k.hint END
                MERGE (c)-[:HAS_CHUNK]->(k)
                """,
                {"cid": cid, "chunks": [
                    {"id": c.id, "kind": c.kind, "hint": c.hint, "length": int(c.length)} for c in chunks
                ]},
            )

    def entity_row(self, ref: EntityRef) -> dict[str, Any]:
        """Node properties for an entity, with the flags the project's config gives it."""
        row: dict[str, Any] = {
            "id": ref.id, "kind": ref.kind, "value": ref.value, "name": ref.name,
            "sensitive": False, "protected": False, "untrusted": False, "trusted": False, "local": False,
        }
        cfg = self.cfg
        if ref.kind == "file":
            row["sensitive"] = cfg.is_sensitive_path(ref.value)
            row["protected"] = cfg.is_protected_path(ref.value)
            row["untrusted"] = cfg.is_untrusted_path(ref.value)
            row["local"] = True
        elif ref.kind in ("host", "url"):
            host = ref.value if ref.kind == "host" else (_url_host(ref.value) or "")
            row["trusted"] = bool(host) and cfg.is_trusted_host(host)
            row["local"] = bool(host) and cfg.is_local_host(host)
        elif ref.kind == "env":
            row["sensitive"] = ref.value == "*" or bool(_SECRETISH_ENV.search(ref.value))
            row["local"] = True
        return row

    def _merge_entities(self, refs: Iterable[EntityRef], ts: int) -> None:
        rows: dict[str, dict[str, Any]] = {}
        pairs: list[dict[str, str]] = []
        for ref in refs:
            if ref.kind not in S.ENTITY_KINDS or not ref.value:
                continue
            rows.setdefault(ref.id, self.entity_row(ref))
            if ref.kind == "url":
                host = _url_host(ref.value)
                if host:
                    host_ref = EntityRef("host", host)
                    rows.setdefault(host_ref.id, self.entity_row(host_ref))
                    pairs.append({"url": ref.id, "host": host_ref.id})
        if not rows:
            return
        self.store.write(
            """
            UNWIND $rows AS r
            MERGE (e:Entity {id: r.id})
            ON CREATE SET e.kind = r.kind, e.value = r.value, e.name = r.name, e.first_seen = $ts,
                          e.sensitive = r.sensitive, e.protected = r.protected,
                          e.untrusted = r.untrusted, e.trusted = r.trusted, e.local = r.local
            ON MATCH SET e.sensitive = coalesce(e.sensitive, false) OR r.sensitive,
                         e.protected = coalesce(e.protected, false) OR r.protected,
                         e.untrusted = coalesce(e.untrusted, false) OR r.untrusted
            """,
            {"rows": list(rows.values()), "ts": ts},
        )
        if pairs:
            self.store.write(
                """
                UNWIND $pairs AS p
                MATCH (u:Entity {id: p.url})
                MATCH (h:Entity {id: p.host})
                MERGE (u)-[:ON_HOST]->(h)
                """,
                {"pairs": pairs},
            )

    def _input_sha(self, event: HookEvent) -> str:
        import hashlib
        import hmac

        text = json.dumps(event.tool_input, sort_keys=True, default=str)
        return hmac.new(self.cfg.key(), text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]


# -- helpers -------------------------------------------------------------------------------

_INSTRUCTION_NAMES = {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules"}


def is_instruction_file(path: str) -> bool:
    """Files an agent harness loads into the context by itself, without a tool call."""
    name = path.rsplit("/", 1)[-1]
    return name in _INSTRUCTION_NAMES or "/.claude/" in path or "/.cursor/rules/" in path


def _url_host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _ref_from_id(entity_id: str) -> EntityRef | None:
    kind, sep, value = entity_id.partition(":")
    if not sep or kind not in S.ENTITY_KINDS or not value:
        return None
    return EntityRef(kind, value)


def _edge_props(props: dict[str, Any]) -> dict[str, Any]:
    """Relationship properties must be scalars or lists of scalars."""
    out: dict[str, Any] = {}
    for k, v in props.items():
        if isinstance(v, (str, int, float, bool)):
            out[str(k)] = v
        elif isinstance(v, (list, tuple)) and all(isinstance(x, (str, int, float, bool)) for x in v):
            out[str(k)] = list(v)
    return out


_GIT_URL = re.compile(
    r"""^(?:
        (?:https?|ssh|git)://(?:[^@/\s]+@)?(?P<h1>[^/:\s]+)(?::\d+)?/(?P<p1>[^\s]+)   # scheme://[user@]host[:port]/path
      | (?:[^@/\s]+@)?(?P<h2>[^/:\s]+):(?P<p2>[^\s]+)                                # [user@]host:path
    )$""",
    re.X,
)


def repo_ref_from_git_url(url: str) -> EntityRef | None:
    """``git@github.com:Owner/Name.git`` -> ``repo:github.com/owner/name``."""
    m = _GIT_URL.match(url.strip())
    if not m:
        return None
    host = (m.group("h1") or m.group("h2") or "").lower().rstrip(".")
    path = (m.group("p1") or m.group("p2") or "").strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not host or "." not in host or not path or "/" not in path:
        return None
    return EntityRef("repo", f"{host}/{path.lower()}")


def git_remote_repos(root: os.PathLike[str] | str) -> list[EntityRef]:
    """The repositories the project's git remotes point at, read from ``.git/config``."""
    config_path = os.path.join(os.fspath(root), ".git", "config")
    parser = configparser.RawConfigParser(strict=False)
    try:
        with open(config_path, encoding="utf-8", errors="replace") as fh:
            # git indents keys with tabs; configparser treats leading whitespace as continuation.
            parser.read_string("\n".join(line.strip() for line in fh))
    except (OSError, configparser.Error):
        return []
    refs: list[EntityRef] = []
    for section in parser.sections():
        if not section.startswith("remote "):
            continue
        for key in ("url", "pushurl"):
            if parser.has_option(section, key):
                ref = repo_ref_from_git_url(parser.get(section, key))
                if ref is not None and ref not in refs:
                    refs.append(ref)
    return refs
