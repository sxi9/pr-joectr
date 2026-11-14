from __future__ import annotations

import re

from sim import HOST_EVIL, SECRET, Sim, attack_session
from tainttrail import report, schema as S
from tainttrail.config import Config
from tainttrail.model import Action, EntityRef, PathStep
from tainttrail.store import Store

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def test_timeline_lists_prompts_calls_and_verdicts(store: Store, cfg: Config):
    attack_session(store, cfg)
    rows = report.timeline(store, "s1")
    assert [r["kind"] for r in rows] == ["prompt", "call", "call", "call"]
    assert [r["seq"] for r in rows] == sorted(r["seq"] for r in rows)
    assert [r["num"] for r in rows] == [None, 1, 2, 3], "calls are numbered 1..n for people; prompts are not"
    fetch, read, curl = rows[1:]
    assert (fetch["untrusted"], fetch["sensitive"]) == (True, False)
    assert (read["untrusted"], read["sensitive"]) == (False, True)
    assert curl["decision"] == "deny" and curl["rules"] == ["TT001"]
    text = report.render_timeline(rows)
    lines = text.splitlines()
    assert "untrusted" in lines[2] and "sensitive" in lines[3]
    assert lines[4].rstrip().endswith("DENIED TT001")
    assert "WebFetch" in lines[2] and "curl -d" in lines[4]
    assert ANSI.search(text) is None
    assert ANSI.search(report.render_timeline(rows, color=True))


def test_findings_can_be_filtered_and_fetched(store: Store, cfg: Config):
    attack_session(store, cfg)
    all_rows = report.findings(store)
    assert {f["rule"] for f in all_rows} == {"TT001", "TT009"}
    assert [f["rule"] for f in report.findings(store, blocking_only=True)] == ["TT001"]
    assert [f["rule"] for f in report.findings(store, min_severity="high")] == ["TT001"]
    assert report.findings(store, session_id="other") == []
    last = report.get_finding(store, "last")
    assert last["rule"] == "TT001" and isinstance(last["path"][0], PathStep)
    assert report.get_finding(store, last["id"])["id"] == last["id"]
    assert report.get_finding(store, "tt001")["id"] == last["id"]
    assert report.get_finding(store, ":TT001")["id"] == last["id"]
    assert report.get_finding(store, "nope") is None
    table = report.render_findings(all_rows)
    assert "DENIED" in table and last["id"] in table


def test_finding_renders_path_explanation_and_query(store: Store, cfg: Config):
    attack_session(store, cfg)
    text = report.render_finding(report.get_finding(store, "last"))
    assert "TT001 exfil.confirmed  critical  DENIED" in text
    assert "1 secret from .env would be sent to attacker.example" in text
    diagram = text.split("\nPath\n", 1)[1].split("Cypher that found it")[0]
    order = [diagram.index(s) for s in ("web page docs.example.test/setup", "MENTIONS", "attacker.example",
                                        "SENDS_TO", "call         #3  Bash", "CARRIES", "fingerprint of a secret", "HAS_CHUNK",
                                        "contents of .env")]
    assert order == sorted(order), "the path reads from the untrusted source to the sensitive data"
    assert "DENIED" in diagram
    assert "Cypher that found it" in text and "MATCH p = (u:Content {untrusted: true})" in text


def test_arrows_follow_the_stored_edge_direction():
    steps = [PathStep("a", "Content", "page", rel="MENTIONS", forward=True, role="untrusted"),
             PathStep("b", "Entity", "host", rel="SENDS_TO", forward=False, role="destination"),
             PathStep("c", "ToolCall", "call #3  Bash: curl", rel="in the same session", role="call"),
             PathStep("d", "Content", "secrets", role="sensitive")]
    lines = [ln.strip() for ln in report.render_path(steps, decision="deny").splitlines()]
    i = lines.index("untrusted    page")
    assert lines[i + 1].endswith("MENTIONS") and lines[i + 2] in ("▼", "v")
    j = lines.index("destination  host")
    assert lines[j + 1] in ("▲", "^") and lines[j + 2].endswith("SENDS_TO")
    k = next(n for n, ln in enumerate(lines) if ln.startswith("call"))
    assert lines[k] == "call         #3  Bash: curl   DENIED" and lines[k + 1].endswith("in the same session")
    assert report.render_path([]).strip() == "(no path recorded)"


def test_monitor_mode_says_what_would_have_happened(store: Store, cfg: Config):
    cfg.mode = "monitor"
    attack_session(store, cfg)
    f = report.get_finding(store, "last")
    assert (f["action"], f["intended"]) == ("allow", "deny")
    assert "would be DENIED (monitor mode)" in report.render_finding(f)
    assert "DENIED*" in report.render_findings([f])
    assert "noted TT001" in report.render_timeline(report.timeline(store, "s1"))


def test_sessions_status_and_resolution(store: Store, cfg: Config):
    assert report.resolve_session(store, None) is None
    assert report.render_sessions([]) == "No sessions recorded yet."
    attack_session(store, cfg, session="abc-111")
    other = Sim(store, cfg, session="abd-222")
    other.n = 50
    other.start()
    other.call("Read", Action(S.READS, EntityRef("file", f"{cfg.root.as_posix()}/README.md")))
    assert report.resolve_session(store, "last") == "abd-222"
    assert report.resolve_session(store, "abc") == "abc-111"
    assert report.resolve_session(store, "ab") is None, "ambiguous prefix"
    st = report.status(store)
    assert (st["sessions"], st["calls"], st["denied"], st["untrusted"], st["sensitive"]) == (2, 4, 1, 1, 1)
    table = report.render_sessions(report.sessions(store))
    assert "abc-111" in table and "abd-222" in table


def test_color_respects_no_color_and_force_color(monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("CLICOLOR_FORCE", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert report.use_color() is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert report.use_color() is True
    assert report.paint("x", "red", color=False) == "x"
    assert report.paint("x", "red") == "\x1b[31mx\x1b[0m"
