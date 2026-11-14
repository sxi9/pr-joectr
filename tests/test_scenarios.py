"""Every packaged scenario, replayed through the Claude Code adapter into a real store."""

from __future__ import annotations

import json

import pytest

from tainttrail import report
from tainttrail.config import load_config
from tainttrail.scenarios import list_scenarios, load_scenario, replay, wrap_response
from tainttrail.store import open_store

SCENARIOS = list_scenarios()
ATTACKS = [s for s in SCENARIOS if s["group"] == "attack"]
BENIGN = [s for s in SCENARIOS if s["group"] == "benign"]
GAPS = [s for s in SCENARIOS if s["group"] == "known_gaps"]
VARIANTS = [s for s in SCENARIOS if s["group"] == "variant"]
ORDINARY = [s for s in SCENARIOS if s["group"] == "ordinary"]
# The one ordinary session the guard still asks about (a deploy summary posted to Slack after a
# documentation page and a read of .env). Kept visible in the data and here, not tuned away.
STILL_ASKED = {"p51-long-mixed-deploy-and-notify"}


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("TAINTTRAIL_KEY", "scenario-test-key-not-a-secret")


def test_the_suite_has_the_expected_shape():
    assert len(ATTACKS) >= 15 and len(BENIGN) >= 10 and len(GAPS) >= 3
    assert len(VARIANTS) == 11 and len(ORDINARY) == 64
    ids = [s["id"] for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    for s in SCENARIOS:
        assert s["title"] and s["story"] and s["sessions"]


def test_scenarios_use_only_reserved_hosts_and_canaries():
    """Nothing in the fixtures may look like a real target or a real credential."""
    import re

    # What a replay acts on: the steps and the fixture files. Citations under "inspired_by" are prose.
    text = json.dumps([{"sessions": s["sessions"], "files": s.get("files")} for s in SCENARIOS])
    hosts = {h.lower().rstrip(".") for h in re.findall(r"https?://([A-Za-z0-9.-]+)", text)}
    # Real hosts a developer workflow names. Replay contacts nothing, so naming them is harmless.
    everyday = {"github.com", "api.github.com", "raw.githubusercontent.com", "docs.python.org", "pypi.org",
                "files.pythonhosted.org", "registry.npmjs.org", "localhost", "127.0.0.1", "gist.github.com",
                "nodejs.org"}
    for host in hosts:
        reserved = host.endswith((".example", ".test", ".invalid", ".example.com", ".example.org")) or host in (
            "example.com", "example.org")
        assert reserved or host in everyday or "." not in host, f"{host} is neither reserved nor an everyday host"
    assert "AKIAIOSFODNN7EXAMPLE" in text, "the documented example key is the canary"
    assert not re.search(r"\bAKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}\b", text)
    assert not re.search(r"\bgh[pousr]_[A-Za-z0-9]{36}\b", text)


@pytest.mark.parametrize("scenario", ATTACKS, ids=[s["id"] for s in ATTACKS])
def test_attacks_are_stopped_and_nothing_leaks(scenario, tmp_path):
    result = replay(scenario, tmp_path / "project")
    failed = [(s.index, s.tool, s.expect, s.action, s.rules) for s in result.steps if not s.ok]
    assert not failed, failed
    assert result.leaked == [], "a canary left without so much as a prompt"
    assert result.blocked_at is not None or result.asked_at, "the attack met no resistance"


@pytest.mark.parametrize("scenario", BENIGN, ids=[s["id"] for s in BENIGN])
def test_ordinary_work_is_left_alone(scenario, tmp_path):
    result = replay(scenario, tmp_path / "project")
    interrupted = [(s.index, s.tool, s.action, s.rules, s.reason[:120]) for s in result.steps if s.action != "allow"]
    assert interrupted == []


@pytest.mark.parametrize("scenario", VARIANTS, ids=[s["id"] for s in VARIANTS])
def test_attacks_at_the_edges_of_the_precision_fixes_are_still_stopped(scenario, tmp_path):
    """Each narrowing that removed a false alarm has an attack written against it."""
    result = replay(scenario, tmp_path / "project")
    assert result.ok, [(s.index, s.tool, s.expect, s.action, s.rules) for s in result.steps if not s.ok]
    assert result.blocked_at is not None or result.asked_at, "the attack met no resistance"


@pytest.mark.parametrize("scenario", ORDINARY, ids=[s["id"] for s in ORDINARY])
def test_a_reviewers_ordinary_sessions_run_without_a_question(scenario, tmp_path):
    """64 multi-step sessions written to find false alarms. Half of them used to be interrupted."""
    result = replay(scenario, tmp_path / "project")
    interrupted = [(s.index, s.tool, s.action, s.rules, s.reason[:120]) for s in result.steps if s.action != "allow"]
    if scenario["id"] in STILL_ASKED:
        assert [(i[2], i[3]) for i in interrupted] == [("ask", ["TT002"])]
    else:
        assert interrupted == []


@pytest.mark.parametrize("scenario", GAPS, ids=[s["id"] for s in GAPS])
def test_harder_cases_at_least_prompt(scenario, tmp_path):
    result = replay(scenario, tmp_path / "project")
    assert result.ok, [(s.index, s.tool, s.expect, s.action, s.rules) for s in result.steps if not s.ok]
    assert result.leaked == []


def test_without_the_guard_the_same_attack_leaks(tmp_path):
    scenario = load_scenario("a02")
    off = replay(scenario, tmp_path / "off", guard=False)
    assert off.blocked_at is None and off.asked_at == []
    assert off.leaked == ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "canary-4c1d9e7a2b6f4083a5d1"]
    on = replay(scenario, tmp_path / "on")
    assert on.blocked_at == 4 and on.leaked == [] and len(on.held) == 3
    # monitor mode still recorded what it would have done
    with open_store(load_config(tmp_path / "off"), read_only=True) as store:
        finding = report.get_finding(store, "last")
    assert (finding["rule"], finding["action"], finding["intended"]) == ("TT001", "allow", "deny")


def test_the_cross_session_attack_is_one_path(tmp_path):
    result = replay(load_scenario("a06"), tmp_path / "project")
    assert result.blocked_at is not None
    with open_store(load_config(tmp_path / "project"), read_only=True) as store:
        finding = report.get_finding(store, "last")
        sessions = {r["id"] for r in report.sessions(store)}
    assert finding["rule"] == "TT001" and len(sessions) == 2
    assert finding["path"][0].role == "untrusted", "the path starts at what the other agent wrote down"
    assert "research.md" in finding["explanation"]


def test_replay_goes_through_the_real_adapter_and_never_says_allow(tmp_path, monkeypatch):
    from tainttrail.hooks import claude_code

    seen = []
    original = claude_code.render

    def spy(event_name, decision, **kw):
        out = original(event_name, decision, **kw)
        seen.append(out)
        return out

    monkeypatch.setattr(claude_code, "render", spy)
    replay(load_scenario("a02"), tmp_path / "project")
    assert seen, "the adapter was not used"
    decisions = [o["hookSpecificOutput"].get("permissionDecision") for o in seen if o and "hookSpecificOutput" in o]
    assert "deny" in decisions and "allow" not in decisions


def test_no_secret_value_reaches_the_graph_or_the_log(tmp_path):
    result = replay(load_scenario("a02"), tmp_path / "project")
    cfg = load_config(result.root)
    with open_store(cfg, read_only=True) as store:
        dump = json.dumps(store.run("MATCH (n) RETURN properties(n) AS p")) + json.dumps(
            store.run("MATCH ()-[r]->() RETURN properties(r) AS p"))
    log = cfg.log_path.read_text() if cfg.log_path.exists() else ""
    for canary in ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "canary-4c1d9e7a2b6f4083a5d1"):
        assert canary not in dump and canary not in log


def test_load_scenario_by_prefix_and_file(tmp_path):
    assert load_scenario("a02")["id"].startswith("a02-")
    assert load_scenario("a03")["id"].startswith("a03-"), "a03 means a03, not a03b"
    with pytest.raises(LookupError):
        load_scenario("zz")
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({"id": "custom", "title": "t", "story": "s", "sessions": []}))
    assert load_scenario(str(path))["group"] == "custom"


def test_wrap_response_matches_claude_code_shapes():
    assert wrap_response("Read", {"file_path": "/x"}, "a\nb\n")["file"] == {
        "filePath": "/x", "content": "a\nb\n", "numLines": 2, "startLine": 1, "totalLines": 2}
    assert wrap_response("Bash", {}, "out")["stdout"] == "out"
    assert wrap_response("WebFetch", {"url": "https://x.test"}, "page")["result"] == "page"
    assert wrap_response("mcp__github__issue_read", {}, "body") == [{"type": "text", "text": "body"}]
    assert wrap_response("Bash", {}, {"stdout": "kept"}) == {"stdout": "kept"}
