"""Toxic paths, their scores and the fix advisor.

Two kinds of graph are used: capability maps written by a real scan of fixture
configuration files (shared with ``test_scan``), and small maps built by hand so that
the expected answer can be worked out independently of the code under test.
"""

from __future__ import annotations

import itertools
import json
import time
from pathlib import Path

import pytest

from test_scan import (  # noqa: F401
    CANARIES, claude_github, claude_trio, cli, dirs, do_scan, graph_text, secret_laden_project, settings, tool, write,
)
from tainttrail import paths, schema as S
from tainttrail.config import Config
from tainttrail.paths import Candidate, ToolFacts
from tainttrail.store import Store

CAPS = {"U": S.CAP_UNTRUSTED_INPUT, "P": S.CAP_PRIVATE_DATA, "S": S.CAP_EXTERNAL_SINK,
        "W": S.CAP_LOCAL_WRITE, "X": S.CAP_CODE_EXEC}


def node(name: str, server: str, caps: str, **props) -> dict:
    """One tool for ``build``: ``caps`` is a string of U P S W X."""
    return {"name": name, "server": server, "caps": [CAPS[c] for c in caps], "props": props}


def build(store: Store, tools: list[dict], *, agent: str = "claude-code", mode: str = "",
          disabled: tuple[str, ...] = ()) -> None:
    """Write a capability map by hand: one agent, its servers, tools and capability edges."""
    store.write("MERGE (a:Agent {id: $id}) SET a.kind = $id, a.name = $id, a.permission_mode = $mode",
                {"id": agent, "mode": mode})
    for server in sorted({t["server"] for t in tools}):
        store.write(
            "MATCH (a:Agent {id: $agent}) CREATE (s:Server {id: $id, name: $name, transport: $transport, "
            "enabled: $enabled}) CREATE (a)-[:CONNECTS]->(s)",
            {"agent": agent, "id": f"{agent}/{server}", "name": server, "enabled": server not in disabled,
             "transport": "builtin" if server == "builtin" else "stdio"})
    for t in tools:
        builtin = t["server"] == "builtin"
        name = t["name"] if builtin else f"mcp__{t['server']}__{t['name']}"
        props = {"name": name, "server": t["server"], "tool": t["name"], "kind": "other" if builtin else "mcp",
                 "gate": "open", "permission": "default", "label_source": "catalog", "label_confidence": 0.9,
                 "sink_scope": "public" if S.CAP_EXTERNAL_SINK in t["caps"] else "",
                 "source_scope": "public" if S.CAP_UNTRUSTED_INPUT in t["caps"] else "",
                 **{cap: cap in t["caps"] for cap in S.CAPABILITIES}, **t["props"]}
        store.write(
            "MATCH (s:Server {id: $sid}) CREATE (t:Tool {id: $id}) SET t += $props CREATE (s)-[:PROVIDES]->(t) "
            "WITH t UNWIND $caps AS cap MATCH (k:Capability {name: cap}) CREATE (t)-[:HAS_CAPABILITY]->(k)",
            {"sid": f"{agent}/{t['server']}", "id": f"{agent}::{name}", "props": props, "caps": t["caps"]})


def tid(server: str, name: str, agent: str = "claude-code") -> str:
    return f"{agent}::{name}" if server == "builtin" else f"{agent}::mcp__{server}__{name}"


# The un-factored form of the question: one row per path. Fine for a small map, and
# written independently of the query under test.
PLAIN_JOIN = """
MATCH (a:Agent {id: $agent})-[:CONNECTS]->(ss:Server)-[:PROVIDES]->(src:Tool)-[:HAS_CAPABILITY]->(:Capability {name: 'untrusted_input'})
WHERE ss.enabled AND src.gate <> 'deny'
MATCH (a)-[:CONNECTS]->(ds:Server)-[:PROVIDES]->(dat:Tool)-[:HAS_CAPABILITY]->(:Capability {name: 'private_data'})
WHERE ds.enabled AND dat.gate <> 'deny'
MATCH (a)-[:CONNECTS]->(ks:Server)-[:PROVIDES]->(snk:Tool)-[:HAS_CAPABILITY]->(:Capability {name: 'external_sink'})
WHERE ks.enabled AND snk.gate <> 'deny'
RETURN src.id AS source, dat.id AS data, snk.id AS sink, snk.gate AS gate
"""


def plain_paths(store: Store, agent: str = "claude-code") -> dict[tuple[str, str, str], str]:
    return {(r["source"], r["data"], r["sink"]): r["gate"] for r in store.run(PLAIN_JOIN, {"agent": agent})}


def expand(report: paths.PathReport) -> set[tuple[str, str, str]]:
    return {triple for f in report.families for triple in itertools.product(f.sources, f.data, f.sinks)}


# -- finding paths -----------------------------------------------------------------------------------


def test_the_github_server_alone_completes_a_path_and_that_is_called_out(dirs):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        report = paths.find_paths(store, limit=3)
        group = next(g for g in report.groups if (g.source_server, g.data_server, g.sink_server) == ("github",) * 3)
        assert group.single_server and group.open == group.paths == group.sources * group.data * group.sinks
        top = group.top
        assert top.single_server and not top.builtin_only and top.status == "open"
        assert {top.source_server, top.data_server, top.sink_server} == {"github"}
        assert all(name.startswith("mcp__github__") for name in (top.source, top.data, top.sink))
        assert "All three legs are on the one server github: the classic single-server path." in top.sentence
        assert "runs without asking anyone" in top.sentence
        assert top.score >= 90 and paths.severity(top.score) == "critical"
        # The same legs spread over two servers score lower: one server giving all three is the worst case.
        mixed = next(g for g in report.groups
                     if (g.source_server, g.data_server, g.sink_server) == ("github", "github", "built-in"))
        assert mixed.top.components["single_server"] == 0 and top.components["single_server"] == 10
        # Every listed path is backed by stored chains: agent -> server -> tool -> capability, three times.
        chains = paths.witness(store, top)
        for leg, tool_id in (("source", top.source_id), ("data", top.data_id), ("sink", top.sink_id)):
            ids = [n["id"] for n in chains[leg]["nodes"]]
            assert ids[0] == "claude-code" and ids[1] == "claude-code/github" and ids[2] == tool_id
        assert report.to_dict()["paths"][0]["query"].startswith("MATCH source = (a:Agent {id: $agent})")


def test_the_factored_query_finds_exactly_the_paths_a_plain_join_finds(dirs):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__fetch"], ask=["mcp__slack__slack_reply_to_thread"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        plain = plain_paths(store)
        report = paths.find_paths(store)
        assert 500 < len(plain) < 20_000, "big enough to mean something, small enough to enumerate"
        assert expand(report) == set(plain)
        assert report.total == len(plain) == sum(g.paths for g in report.groups)
        assert report.open == sum(gate == "open" for gate in plain.values())
        assert report.gated == report.total - report.open > 0
        servers = {(g.source_server, g.data_server, g.sink_server) for g in report.groups}
        assert ("fetch", "filesystem", "slack") in servers and ("built-in", "built-in", "built-in") in servers
        cross = next(g for g in report.groups if (g.source_server, g.data_server, g.sink_server) == ("fetch", "filesystem", "slack"))
        assert not cross.single_server and "Servers: fetch -> filesystem -> slack." in cross.top.sentence


def test_deny_removes_a_leg_and_ask_gates_the_sink(dirs):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__filesystem", "WebFetch"],
                deny=["mcp__fetch", "mcp__filesystem__read_file"], ask=["mcp__slack__slack_post_message"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        report = paths.find_paths(store, limit=2000)
        found = expand(report)
        used = {tool_id for triple in found for tool_id in triple}
        assert "claude-code::mcp__fetch__fetch" not in used, "a denied tool is on no path, as source or as sink"
        assert "claude-code::mcp__filesystem__read_file" not in used
        assert "claude-code::mcp__filesystem__read_text_file" in used
        post, reply = "claude-code::mcp__slack__slack_post_message", "claude-code::mcp__slack__slack_reply_to_thread"
        gated = [p for p in report.paths if p.sink_id == post]
        opened = [p for p in report.paths if p.sink_id == reply]
        assert gated and all(p.status == "gated" and "gated by approval" in p.sentence for p in gated)
        assert opened and all(p.status == "open" for p in opened)
        assert max(p.score for p in gated) < max(p.score for p in opened), "an approval on the way out lowers the score"
        assert report.open == len([t for t in found if t[2] not in (post, "claude-code::Bash")])
        only_gated = paths.find_paths(store, limit=50, status="gated")
        assert only_gated.paths and {p.status for p in only_gated.paths} == {"gated"}
        strong = paths.find_paths(store, limit=50, min_score=80)
        assert strong.paths and min(p.score for p in strong.paths) >= 80


def test_paths_do_not_cross_agents_and_a_disabled_server_gives_no_leg(mem):
    build(mem, [node("fetch", "web", "U"), node("Read", "builtin", "P", kind="read")], agent="claude-code")
    build(mem, [node("post", "chat", "S")], agent="cursor")
    assert paths.find_paths(mem).total == 0, "a source on one agent and a sink on another do not combine"
    build(mem, [node("mail", "smtp", "S"), node("note", "off", "S")], agent="windsurf", disabled=("off",))
    build(mem, [node("page", "web2", "U"), node("vault", "secrets", "P"), node("send", "out", "S")], agent="gemini-cli",
          disabled=("out",))
    report = paths.find_paths(mem)
    assert report.total == 0
    mem.write("MATCH (s:Server {id: 'gemini-cli/out'}) SET s.enabled = true")
    report = paths.find_paths(mem)
    assert (report.total, [a["id"] for a in report.agents if a["paths"]]) == (1, ["gemini-cli"])
    assert paths.find_paths(mem, agent="cursor").total == 0


def test_a_map_that_only_carries_permission_is_read_the_obvious_way(mem):
    build(mem, [node("page", "web", "U", gate=None), node("vault", "kv", "P", gate=None),
                node("allowed", "out", "S", gate=None, permission="allow"),
                node("asks", "out", "S", gate=None, permission="default"),
                node("denied", "out", "S", gate=None, permission="deny")])
    report = paths.find_paths(mem)
    assert (report.total, report.open, report.gated) == (2, 1, 1)
    assert {p.sink: p.status for p in report.paths} == {"mcp__out__allowed": "open", "mcp__out__asks": "gated"}


# -- scoring -------------------------------------------------------------------------------------------


def facts(name: str, caps: str, *, server: str = "srv", **kw) -> ToolFacts:
    values = dict(
        id=f"claude-code::{name}", name=name, agent="claude-code", server_id=f"claude-code/{server}", server=server,
        server_key=server, tool=name, builtin=server == "builtin", enabled=True, kind="mcp", gate="open",
        gate_data="", permission="default", capabilities=frozenset(CAPS[c] for c in caps), confidence=0.9,
        label_source="catalog", source_scope="public", sink_scope="public", catalog_id="", risk_flags=(),
        open_partial=(), calls=0)
    values.update(kw)
    values["gate_data"] = values["gate_data"] or values["gate"]
    return ToolFacts(**values)


def test_a_score_is_the_sum_of_its_parts_and_every_part_has_a_reason():
    path = paths.make_path(facts("read_issue", "U"), facts("read_repo", "P"), facts("open_pr", "S"))
    assert set(path.components) == set(paths.WEIGHTS) == set(path.why)
    assert path.components == {"exposure": 15.0, "data": 9.6, "sink": 13.0, "unattended": 45.0,
                               "confidence": 4.5, "single_server": 10.0}
    assert path.score == 97 == int(sum(path.components.values()) + 0.5)
    assert sum(paths.WEIGHTS.values()) == 100
    for name, value in path.components.items():
        assert 0 <= value <= paths.WEIGHTS[name], name
        assert path.why[name], name
    assert path.why["exposure"].startswith("anyone on the internet")
    assert path.why["confidence"] == "labels: catalog 0.9, catalog 0.9, catalog 0.9"


@pytest.mark.parametrize("worse,better,part", [
    (dict(source=dict(source_scope="local")), dict(source=dict(source_scope="org")), "exposure"),
    (dict(source=dict(source_scope="org")), dict(source=dict(source_scope="public")), "exposure"),
    (dict(sink=dict(sink_scope="private")), dict(sink=dict(sink_scope="org")), "sink"),
    (dict(sink=dict(sink_scope="org")), dict(sink=dict(sink_scope="public")), "sink"),
    (dict(data=dict(tool="list_branches")), dict(data=dict(tool="get_file_contents")), "data"),
    (dict(data=dict()), dict(data=dict(kind="shell")), "data"),
    (dict(sink=dict(gate="ask")), dict(sink=dict(gate="open")), "unattended"),
    (dict(source=dict(gate="ask")), dict(source=dict(gate="open")), "unattended"),
    (dict(data=dict(gate="ask", kind="shell")), dict(data=dict(gate="ask", gate_data="open", kind="shell")), "unattended"),
    (dict(sink=dict(confidence=0.3, label_source="heuristic")), dict(sink=dict(confidence=0.9)), "confidence"),
    (dict(sink=dict(server="other")), dict(sink=dict()), "single_server"),
])
def test_each_part_of_the_score_moves_the_way_it_should(worse, better, part):
    def score(overrides):
        legs = {role: facts(role, caps, **overrides.get(role, {}))
                for role, caps in (("source", "U"), ("data", "P"), ("sink", "S"))}
        return paths.make_path(legs["source"], legs["data"], legs["sink"])

    low, high = score(worse), score(better)
    assert low.components[part] < high.components[part]
    assert low.score < high.score
    assert {k: v for k, v in low.components.items() if k != part} == {k: v for k, v in high.components.items() if k != part}


def test_scores_stay_between_0_and_100_and_a_shell_alone_is_the_maximum():
    shell = facts("Bash", "UPSX", server="builtin", kind="shell", confidence=1.0, label_source="builtin")
    top = paths.make_path(shell, shell, shell)
    assert top.score == 100 and top.builtin_only and not top.single_server
    assert "built-in tools are enough" in top.sentence
    weakest = paths.make_path(
        facts("a", "U", source_scope="local", gate="ask", confidence=0.0, server="one"),
        facts("list_b", "P", gate="ask", confidence=0.0, server="two"),
        facts("c", "S", sink_scope="private", gate="ask", confidence=0.0, server="three"))
    assert 0 < weakest.score < 20 and weakest.status == "gated"
    assert weakest.why["unattended"] == "every leg waits for a person's approval"


def test_the_listed_paths_are_the_best_ones_of_the_whole_product(dirs):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__fetch"], ask=["mcp__slack__slack_reply_to_thread"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        report = paths.find_paths(store, limit=40)
        every = sorted((paths.make_path(report.facts[s], report.facts[d], report.facts[k])
                        for s, d, k in expand(report)), key=lambda p: -p.score)
        assert [p.score for p in report.paths] == [p.score for p in every[:40]]
        assert all(p.key in expand(report) for p in report.paths)
        assert len({p.key for p in report.paths}) == 40, "no path is listed twice"
        assert report.top_score == every[0].score
        for wanted in ("open", "gated"):
            listed = paths.best_paths(report.families, report.facts, limit=15, status=wanted)
            assert [p.score for p in listed] == [p.score for p in every if p.status == wanted][:15]
        floor = every[len(every) // 3].score
        above = paths.best_paths(report.families, report.facts, limit=10 ** 6, min_score=floor)
        assert len(above) == sum(p.score >= floor for p in every)


def test_tools_that_sessions_really_used_are_shown_first_among_equals(mem):
    build(mem, [node("alpha", "srv", "U"), node("beta", "srv", "U"), node("data", "srv", "P"), node("send", "srv", "S")])
    assert paths.find_paths(mem).paths[0].source == "mcp__srv__alpha"
    mem.write("MATCH (t:Tool {id: $id}) CREATE (:ToolCall {id: 'c1'})-[:INVOKES]->(t)", {"id": tid("srv", "beta")})
    assert paths.find_paths(mem).paths[0].source == "mcp__srv__beta"


# -- what-if ---------------------------------------------------------------------------------------------


def test_what_if_by_parameter_and_by_rehearsal_agree_and_neither_changes_the_graph(dirs):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__fetch", "mcp__filesystem"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        before = graph_text(store)
        deny = ["claude-code::mcp__fetch__fetch", "claude-code::mcp__filesystem__read_file"]
        ask = ["claude-code::mcp__slack__slack_post_message"]
        simulated = paths.simulate(store, deny=deny, ask=ask)
        changes = [paths.Change("claude-code", "deny", "tool", i, i, (i,), 1.0, "") for i in deny] + \
                  [paths.Change("claude-code", "ask", "tool", i, i, (i,), 1.0, "") for i in ask]
        rehearsed = paths.rehearse(store, changes)
        assert simulated["open_before"] == rehearsed["live_before"] > simulated["open_after"] == rehearsed["live_after"] > 0
        assert simulated["paths_after"] == rehearsed["total_after"] < simulated["paths_before"]
        assert simulated["broken"] == rehearsed["broken"]
        assert graph_text(store) == before
        # ... and both agree with applying the change for real.
        with store.transaction():
            paths.apply_changes(store, changes, source="test")
        assert paths.live_paths(store) == (rehearsed["live_after"], rehearsed["total_after"])
        assert tool(store, "mcp__slack__slack_post_message")["gate"] == "ask"
        assert tool(store, "mcp__fetch__fetch")["permission_source"] == "test"


def test_deny_wins_when_a_tool_is_both_asked_and_denied(mem):
    build(mem, [node("page", "web", "U"), node("vault", "kv", "P"), node("send", "out", "S", permission="deny", gate="deny"),
                node("post", "out", "S")])
    send, post = tid("out", "send"), tid("out", "post")
    change = lambda action, i: paths.Change("claude-code", action, "tool", i, i, (i,), 1.0, "")  # noqa: E731
    with mem.transaction():
        paths.apply_changes(mem, [change("ask", send), change("deny", post), change("ask", post)])
    assert mem.scalar("MATCH (t:Tool {id: $id}) RETURN t.permission", {"id": send}) == "deny", "ask never loosens a deny"
    assert mem.scalar("MATCH (t:Tool {id: $id}) RETURN t.permission", {"id": post}) == "deny"


# -- baselines ---------------------------------------------------------------------------------------------


def test_new_paths_are_exactly_the_ones_the_baseline_does_not_cover(dirs, tmp_path):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__fetch"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        first = paths.find_paths(store)
        old_paths, old_open = expand(first), {k for k, gate in plain_paths(store).items() if gate == "open"}
        assert paths.new_paths(first, None)[0] == first.total, "with no baseline everything is new"
        baseline_file = tmp_path / "state" / "baseline.json"
        paths.save_baseline(baseline_file, first)
        baseline = paths.load_baseline(baseline_file)
        assert paths.new_paths(first, baseline) == (0, [])

        # A new server arrives and a sink stops asking.
        write(project / ".mcp.json", {"mcpServers": {
            "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(project)]},
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}})
        write(project / ".claude" / "settings.json", settings(allow=["mcp__fetch", "mcp__slack__slack_post_message"]))
        do_scan(store, home, project)
        second = paths.find_paths(store)
        now = plain_paths(store)
        appeared = set(now) - old_paths
        reopened = {k for k, gate in now.items() if gate == "open" and k in old_paths and k not in old_open}
        assert reopened, "the fixture really re-opens a known path"
        count, worst = paths.new_paths(second, baseline, limit=5)
        assert count == len(appeared) + len(reopened)
        assert worst and all(p.key in appeared | reopened for p in worst)
        strict_floor = paths.new_paths(second, baseline, limit=5, min_score=101)
        assert strict_floor[0] == count and strict_floor[1] == []


def test_a_baseline_that_is_missing_or_broken_is_told_apart(tmp_path):
    assert paths.load_baseline(tmp_path / "absent.json") is None
    for text in ("{not json", '{"format": "something-else", "agents": {}}', "[]"):
        write(tmp_path / "bad.json", text=text)
        with pytest.raises(ValueError):
            paths.load_baseline(tmp_path / "bad.json")


# -- the hitting-set solver ------------------------------------------------------------------------------


def brute_force(weights: list[int], candidates: list[Candidate]) -> float | None:
    """The cheapest cover found by trying every subset. Only for a handful of candidates."""
    assert len(candidates) <= 12
    need = sum(1 << i for i, w in enumerate(weights) if w > 0)
    best = None
    for size in range(len(candidates) + 1):
        for combo in itertools.combinations(candidates, size):
            covered = 0
            for candidate in combo:
                covered |= candidate.covers
            if covered & need == need:
                cost = sum(c.cost for c in combo)
                best = cost if best is None else min(best, cost)
    return best


def cand(cost: float, covers: int, label: str = "") -> Candidate:
    return Candidate((), cost, covers, label)


def test_exact_search_finds_the_minimum_where_the_greedy_choice_does_not():
    # Two sources (bits 0-2 and 3-5) and three sinks, each sink on one path of each source.
    candidates = [cand(1.0, 0b000111, "cheap source"), cand(12.0, 0b111000, "dear source"),
                  cand(4.1, 0b001001, "sink 1"), cand(4.1, 0b010010, "sink 2"), cand(4.1, 0b100100, "sink 3")]
    weights = [1] * 6
    exact = paths.solve(weights, candidates, method="exact")
    greedy = paths.solve(weights, candidates, method="greedy")
    assert [candidates[i].label for i in exact.chosen] == ["sink 1", "sink 2", "sink 3"]
    assert exact.cost == pytest.approx(12.3) and brute_force(weights, candidates) == pytest.approx(12.3)
    assert [candidates[i].label for i in greedy.chosen] == ["cheap source", "dear source"], \
        "greedy takes the bargain first and is then stuck with it"
    assert greedy.cost == pytest.approx(13.0) and greedy.cost > exact.cost
    assert (exact.method, greedy.method, exact.complete, greedy.complete) == ("exact", "greedy", True, True)
    assert paths.solve(weights, candidates).method == "exact", "few candidates: the default is exhaustive"
    assert paths.solve(weights, candidates, exact_limit=3).method == "greedy"


def test_exact_search_agrees_with_trying_every_subset():
    import random

    rng = random.Random(20261114)
    for _ in range(200):
        n_families, n_candidates = rng.randint(1, 8), rng.randint(1, 8)
        candidates = [cand(round(rng.uniform(0.5, 6.0), 2), rng.getrandbits(n_families)) for _ in range(n_candidates)]
        weights = [rng.randint(0, 3) for _ in range(n_families)]
        truth = brute_force(weights, candidates)
        found = paths.solve(weights, candidates, method="exact")
        greedy = paths.solve(weights, candidates, method="greedy")
        if truth is None:
            assert not found.complete and not greedy.complete
            continue
        assert found.complete and found.cost == pytest.approx(truth)
        assert sum(candidates[i].cost for i in found.chosen) == pytest.approx(truth)
        assert greedy.complete and greedy.cost >= truth - 1e-9
        for solution in (found, greedy):
            covered = 0
            for i in solution.chosen:
                covered |= candidates[i].covers
            assert all(covered >> f & 1 for f, w in enumerate(weights) if w > 0)


def test_solver_edge_cases():
    assert paths.solve([], []) == paths.Solution([], 0.0, "none", True, 0)
    assert paths.solve([0, 0], [cand(1.0, 0b11)]).method == "none", "families without live paths need nothing"
    # A dominated candidate (covers no more, costs no less) is never considered or chosen.
    solution = paths.solve([1, 1], [cand(5.0, 0b01, "dominated"), cand(2.0, 0b11, "better"), cand(2.0, 0b11, "twin")])
    assert (solution.chosen, solution.considered) == ([1], 1)
    stuck = paths.solve([1, 1], [cand(1.0, 0b01)])
    assert stuck.complete is False and stuck.chosen == [0], "what can be broken still is"
    with pytest.raises(ValueError):
        paths.solve([1], [cand(1.0, 1)], method="fastest")


# -- the fix advisor on a map ------------------------------------------------------------------------------


def greedy_trap(store: Store) -> None:
    """Two sources of unequal cost, one data tool, seven sinks: gating the sinks is cheapest (7),
    but the cheap source (3) is the best bargain at the start, and after it the dear one (6)."""
    tools = [node("feed", "feeds", "U"), node("lookup", "search", "U", kind="search"),
             node("Read", "builtin", "P", kind="read")]
    tools += [node(f"send{i}", "outbox", "S") for i in range(1, 8)]
    # Harmless tools make a rule on a whole server cost more than rules on the tools that matter.
    tools += [node(f"noop{i}", server, "") for server in ("feeds", "search") for i in range(1, 4)]
    tools += [node(f"noop{i}", "outbox", "") for i in range(1, 11)]
    build(store, tools)


def test_the_fix_is_minimal_where_the_greedy_choice_is_not(mem):
    greedy_trap(mem)
    before = graph_text(mem)
    assert paths.find_paths(mem).open == 14

    proposal = paths.propose_fix(mem)
    assert (proposal.method, proposal.cost) == ("exact", 7.0)
    assert sorted(c.rule for c in proposal.changes) == [f"mcp__outbox__send{i}" for i in range(1, 8)]
    assert {(c.action, c.scope) for c in proposal.changes} == {("ask", "tool")}
    assert (proposal.live_before, proposal.live_after, proposal.broken) == (14, 0, 14)
    assert proposal.settings() == {"permissions": {"ask": [f"mcp__outbox__send{i}" for i in range(1, 8)]}}

    # Independent check of "minimal": no subset of the candidate changes is cheaper.
    instance = paths.build_instance("claude-code", paths.path_families(mem, "claude-code"),
                                    paths.tool_facts(mem, "claude-code"))
    assert sum(instance.weights) == 14 and len(instance.candidates) <= 12
    assert brute_force(instance.weights, instance.candidates) == pytest.approx(7.0)

    greedy = paths.propose_fix(mem, method="greedy")
    assert (greedy.method, greedy.cost) == ("greedy", 9.0)
    assert sorted((c.action, c.rule) for c in greedy.changes) == [("deny", "mcp__feeds__feed"), ("deny", "mcp__search__lookup")]
    assert (greedy.live_after, greedy.broken) == (0, 14), "greedy also breaks everything, it just costs more"
    assert graph_text(mem) == before, "proposing and rehearsing leave the stored map untouched"


def test_reported_counts_come_from_the_query_not_from_the_solver(mem, monkeypatch):
    greedy_trap(mem)
    # A solver that claims complete success while choosing nothing.
    monkeypatch.setattr(paths, "solve", lambda weights, candidates, **kw: paths.Solution([], 0.0, "exact", True, 0))
    proposal = paths.propose_fix(mem)
    assert (proposal.live_before, proposal.live_after, proposal.broken) == (14, 14, 0)
    text = paths.render_fix(proposal, target="settings.json")
    assert "breaks 0 of 14 paths" in text and "14 paths remain." in text

    # A solver that picks one candidate only: the count is whatever that really breaks.
    monkeypatch.setattr(paths, "solve", lambda weights, candidates, **kw: paths.Solution([0], 1.0, "exact", True, 1))
    proposal = paths.propose_fix(mem)
    kept = set(plain_paths(mem))
    with mem.rehearsal():
        paths.apply_changes(mem, proposal.changes)
        left = {k for k, gate in plain_paths(mem).items() if gate == "open"}
    assert proposal.live_after == len(left) and proposal.broken == len(kept) - len(left) > 0


def test_an_allowed_command_pattern_is_fixed_by_asking_for_that_pattern_only(dirs):
    home, project = dirs
    claude_github(home, project, allow=["Bash(curl:*)", "Bash(git status)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        proposal = paths.propose_fix(store)
        [change] = proposal.changes
        assert (change.action, change.scope, change.rule, change.cost) == ("ask", "pattern", "Bash(curl:*)", 3.0)
        assert proposal.settings() == {"permissions": {"ask": ["Bash(curl:*)"]}}
        assert proposal.live_before > 0 and proposal.live_after == 0
        with store.transaction():
            paths.apply_changes(store, proposal.changes, source="settings.json")
        bash = tool(store, "Bash")
        assert (bash["permission"], bash["gate"], bash["gate_data"], bash["open_partial"]) == ("default", "ask", "open", [])
        assert "ask Bash(curl:*)" in bash["permission_partial"]
        assert paths.find_paths(store).open == 0


def test_default_prompts_count_as_gates_and_strict_asks_for_explicit_rules(dirs):
    home, project = dirs
    claude_github(home, project)        # no allow rules: every sink asks because of the permission mode
    with Store(":memory:") as store:
        do_scan(store, home, project)
        relaxed = paths.propose_fix(store)
        assert relaxed.live_before == 0 and relaxed.changes == [] and relaxed.total_before > 1000
        text = paths.render_fix(relaxed, target="x")
        assert "Nothing to fix" in text and "--strict" in text
        strict = paths.propose_fix(store, strict=True)
        assert strict.live_before == relaxed.total_before, "no sink is held by an explicit rule yet"
        assert strict.method == "exact" and strict.live_after == 0
        rules = strict.settings()["permissions"]
        assert "Bash" in rules["ask"] and "WebFetch" in rules["ask"] and "mcp__github__create_issue" in rules["ask"]
        assert all(c.scope != "pattern" for c in strict.changes)


def test_one_rule_for_a_server_is_chosen_when_it_is_the_cheaper_way(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    write(project / ".claude" / "settings.json", settings(allow=["mcp__fetch"]))
    with Store(":memory:") as store:
        do_scan(store, home, project)
        proposal = paths.propose_fix(store)
        [change] = proposal.changes
        assert (change.action, change.scope, change.target, change.rule) == ("ask", "server", "fetch", "mcp__fetch")
        assert change.cost == 0.75 and proposal.live_after == 0


def test_denying_a_core_tool_costs_more_than_gating_a_sink(mem):
    build(mem, [node("Bash", "builtin", "UPSX", kind="shell", gate="open"), node("Read", "builtin", "P", kind="read"),
                node("page", "web", "U"), node("send", "out", "S"), node("noop1", "out", ""), node("noop2", "out", "")])
    known = paths.tool_facts(mem, "claude-code")
    bash, read, send = known["claude-code::Bash"], known["claude-code::Read"], known[tid("out", "send")]
    assert paths.tool_use(bash) > paths.tool_use(read) > paths.tool_use(send) == 1.0
    assert paths.DENY_COST * paths.tool_use(read) > paths.ASK_COST * paths.tool_use(bash) > paths.ASK_COST * paths.tool_use(send)
    # A tool that sessions called often is dearer to take away.
    mem.write("MATCH (t:Tool {id: $id}) UNWIND range(1, 15) AS i CREATE (:ToolCall {id: 'c' + toString(i)})-[:INVOKES]->(t)",
              {"id": tid("out", "send")})
    assert paths.tool_use(paths.tool_facts(mem, "claude-code")[tid("out", "send")]) == 3.0
    proposal = paths.propose_fix(mem)
    assert {(c.action, c.rule) for c in proposal.changes} == {("ask", "Bash"), ("ask", "mcp__out__send")}
    assert proposal.live_after == 0


def test_many_servers_fall_back_to_greedy_and_say_so(mem):
    tools = []
    for i in range(8):
        tools += [node("read_page", f"srv{i}", "U"), node("read_vault", f"srv{i}", "P"), node("send", f"srv{i}", "S"),
                  node("noop", f"srv{i}", "")]
    build(mem, tools)
    proposal = paths.propose_fix(mem)
    [fix] = proposal.agents
    assert fix.method == "greedy" and fix.candidates > paths.EXACT_LIMIT
    assert (proposal.live_before, proposal.live_after) == (512, 0)
    assert "greedy choice among" in paths.render_fix(proposal, target="x")
    assert "not a proven minimum" in paths.render_fix(proposal, target="x")
    exact = paths.propose_fix(mem, exact_limit=64)
    assert exact.method == "exact" and exact.cost <= proposal.cost and exact.live_after == 0
    assert exact.cost == 8.0, "gating the eight sinks is the cheapest way"


def test_other_agents_get_rules_in_their_own_syntax_but_no_file_is_written_for_them(mem):
    build(mem, [node("page", "web", "U"), node("vault", "kv", "P"), node("send", "out", "S"), node("noop", "out", "")],
          agent="cursor")
    proposal = paths.propose_fix(mem)
    assert [(c.agent, c.action, c.rule) for c in proposal.changes] == [("cursor", "ask", "Mcp(out:send)")]
    assert proposal.settings("claude-code") == {"permissions": {}}
    text = paths.render_fix(proposal, target="settings.json")
    assert "cursor: TaintTrail does not edit this agent's settings" in text
    assert "require approval for Mcp(out:send)" in text
    assert "Apply it with" not in text


def test_a_large_map_is_handled_without_enumerating_its_paths(mem):
    tools = [node(f"{role}{i}", f"srv{s}", caps) for s in range(10) for i in range(20)
             for role, caps in (("src", "U"), ("dat", "P"), ("snk", "S"))]
    build(mem, tools)
    started = time.monotonic()
    report = paths.find_paths(mem, limit=25)
    proposal = paths.propose_fix(mem)
    assert time.monotonic() - started < 20
    assert report.total == report.open == 200 ** 3 and len(report.groups) == 1000 and len(report.paths) == 25
    assert (proposal.live_before, proposal.live_after, len(proposal.changes)) == (8_000_000, 0, 200)


# -- writing the rules into a settings file -----------------------------------------------------------------

HOOKS = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "python -m tainttrail hook claude-code"}]}]}


def test_merging_rules_is_idempotent_backs_up_once_and_keeps_everything_else(tmp_path):
    path = write(tmp_path / ".claude" / "settings.json", {
        "hooks": HOOKS, "permissions": {"allow": ["Bash(npm run *)"], "ask": ["mcp__github__create_issue"],
                                        "defaultMode": "acceptEdits"},
        "env": {"FOO": "bar"}, "zzz": [1, 2, 3]})
    path.chmod(0o600)
    original = path.read_text()
    snippet = {"permissions": {"ask": ["mcp__github__create_issue", "mcp__github__push_files"], "deny": ["WebFetch"]}}

    first = paths.apply_settings(path, snippet)
    assert first.changed and first.added == ["ask mcp__github__push_files", "deny WebFetch"]
    assert first.backup == str(path) + ".bak" and Path(first.backup).read_text() == original
    data = json.loads(path.read_text())
    assert list(data) == ["hooks", "permissions", "env", "zzz"], "key order is kept"
    assert (data["hooks"], data["env"], data["zzz"]) == (HOOKS, {"FOO": "bar"}, [1, 2, 3])
    assert data["permissions"] == {"allow": ["Bash(npm run *)"], "defaultMode": "acceptEdits",
                                   "ask": ["mcp__github__create_issue", "mcp__github__push_files"], "deny": ["WebFetch"]}
    assert path.stat().st_mode & 0o777 == 0o600 and path.read_text().endswith("}\n")
    assert [p.name for p in path.parent.iterdir()] and not list(path.parent.glob("*.tmp")), "no temporary file is left"

    after = path.read_text()
    second = paths.apply_settings(path, snippet)
    assert (second.changed, second.added, second.backup) == (False, [], None) and path.read_text() == after

    third = paths.apply_settings(path, {"permissions": {"deny": ["Bash"]}})
    assert third.changed and third.backup is None, "the backup is made once"
    assert Path(str(path) + ".bak").read_text() == original, "and still holds the file as it first was"


def test_a_missing_settings_file_is_created_and_an_empty_change_writes_nothing(tmp_path):
    path = tmp_path / "new" / ".claude" / "settings.json"
    assert paths.apply_settings(path, {"permissions": {}}).changed is False and not path.exists()
    result = paths.apply_settings(path, {"permissions": {"ask": ["mcp__fetch"]}})
    assert result.changed and result.backup is None
    assert json.loads(path.read_text()) == {"permissions": {"ask": ["mcp__fetch"]}}
    empty = write(tmp_path / "empty.json", text="")
    assert paths.apply_settings(empty, {"permissions": {"deny": ["WebFetch"]}}).changed
    assert json.loads(empty.read_text()) == {"permissions": {"deny": ["WebFetch"]}}


@pytest.mark.parametrize("content", [
    '{"permissions": {"ask": ["x"]',                    # cut off
    '["a", "list"]',
    '{"permissions": ["not", "an", "object"]}',
    '{"permissions": {"ask": "mcp__github"}}',
    '{"permissions": {"ask": [], "deny": {"a": 1}}}',
])
def test_a_settings_file_that_cannot_be_merged_safely_is_left_untouched(tmp_path, content):
    path = write(tmp_path / "settings.json", text=content)
    with pytest.raises(paths.FixError, match="left untouched"):
        paths.apply_settings(path, {"permissions": {"ask": ["mcp__fetch"], "deny": ["WebFetch"]}})
    assert path.read_text() == content and not Path(str(path) + ".bak").exists()


def test_settings_snippet_drops_an_ask_rule_that_a_deny_rule_already_covers():
    change = lambda action, rule: paths.Change("claude-code", action, "tool", rule, rule, (rule,), 1.0, "")  # noqa: E731
    snippet = paths.settings_snippet([change("ask", "b"), change("deny", "a"), change("ask", "a"), change("ask", "b")])
    assert snippet == {"permissions": {"ask": ["b"], "deny": ["a"]}}
    assert paths.settings_snippet([]) == {"permissions": {}}


# -- commands ---------------------------------------------------------------------------------------------------


def scan_cli(cfg: Config, home: Path, project: Path) -> int:
    from tainttrail import scan

    return cli(scan.cmd_scan, scan.add_scan_arguments, cfg, "--home", home, "--path", project, "--json")


def paths_cli(cfg: Config, *argv: str) -> int:
    return cli(paths.cmd_paths, paths.add_paths_arguments, cfg, *argv)


def fix_cli(cfg: Config, *argv: str) -> int:
    return cli(paths.cmd_fix, paths.add_fix_arguments, cfg, *argv)


def test_commands_say_what_to_do_when_nothing_was_scanned(cfg, capsys):
    assert paths_cli(cfg) == 1
    assert "Run `tainttrail scan` first" in capsys.readouterr().err
    assert fix_cli(cfg) == 1
    assert "Run `tainttrail scan` first" in capsys.readouterr().err
    assert not cfg.db_path.exists(), "asking does not create a graph"


def test_paths_command_lists_groups_explains_scores_and_gates_ci(dirs, cfg, capsys):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"])
    scan_cli(cfg, home, project)
    capsys.readouterr()

    assert paths_cli(cfg) == 0
    out = capsys.readouterr().out
    for expected in ("TaintTrail paths", "Claude Code:", "open", "gated by approval",
                     "github -> github -> github   single server: all three legs",
                     "97 = exposure 15 + data 9.6 + sink 13 + unattended 45 + confidence 4.5 + single server 10",
                     "the classic single-server path", "`tainttrail fix` proposes"):
        assert expected in out, expected
    assert "\x1b[" not in out

    assert paths_cli(cfg, "--json", "--limit", "3") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["total"] > report["open"] > 0 and report["top_score"] == 97 and len(report["paths"]) == 3
    assert report["gate"] == {"failed": False, "reason": ""}
    assert set(report["paths"][0]) >= {"source", "data", "sink", "source_server", "score", "components", "why",
                                       "sentence", "status", "single_server", "query", "params"}

    assert paths_cli(cfg, "--show-query") == 0
    shown = capsys.readouterr().out
    assert "MATCH (a:Agent {id: $agent})" in shown and "UNWIND source_legs AS src" in shown
    assert paths_cli(cfg, "--status", "gated", "--min-score", "40") == 0
    assert "Paths matching the filter" in capsys.readouterr().out
    assert paths_cli(cfg, "--limit", "-1") == 2
    capsys.readouterr()

    # --max-score N: fail when a path scores N or more.
    assert paths_cli(cfg, "--max-score", "98") == 0
    assert paths_cli(cfg, "--max-score", "97") == 3
    captured = capsys.readouterr().out
    assert "FAILED: a path scores 97, at or above the limit of 97." in captured
    assert paths_cli(cfg, "--max-score", "50", "--json") == 3
    assert json.loads(capsys.readouterr().out)["gate"]["failed"] is True
    assert paths_cli(cfg, "--agent", "cursor", "--max-score", "1") == 1, "a gate with nothing to judge does not pass"
    assert "no scan of agent cursor is in the graph" in capsys.readouterr().err
    assert paths_cli(cfg, "--agent", "cursor") == 0, "without a gate it is only an empty report"
    capsys.readouterr()


def test_fail_on_new_compares_with_the_accepted_baseline(dirs, cfg, tmp_path, capsys):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__fetch"])
    scan_cli(cfg, home, project)
    baseline = tmp_path / "ci" / "baseline.json"
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline) == 3
    out = capsys.readouterr().out
    assert "there is no baseline yet" in out and "tainttrail paths --accept" in out
    assert paths_cli(cfg, "--accept", "--baseline", baseline) == 0
    assert "as reviewed" in capsys.readouterr().out and baseline.exists()
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline) == 0

    # The default baseline lives next to the graph.
    assert paths_cli(cfg, "--accept") == 0 and (cfg.home / "paths-baseline.json").exists()
    assert paths_cli(cfg, "--fail-on-new") == 0
    capsys.readouterr()

    write(project / ".claude" / "settings.json", settings(allow=["mcp__fetch", "mcp__slack__slack_post_message"]))
    scan_cli(cfg, home, project)
    capsys.readouterr()
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline, "--json") == 3
    report = json.loads(capsys.readouterr().out)
    assert report["new"]["count"] > 0 and report["gate"]["failed"]
    assert all(p["sink"] == "mcp__slack__slack_post_message" for p in report["new"]["paths"])
    # Together: fail only when a new path reaches the score.
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline, "--max-score", "100") == 0
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline, "--max-score", "60") == 3
    capsys.readouterr()
    write(baseline, text="{broken")
    assert paths_cli(cfg, "--fail-on-new", "--baseline", baseline) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_fix_command_proposes_applies_and_the_next_scan_agrees(dirs, cfg, capsys):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github", "Bash(curl:*)"])
    target = project / ".claude" / "settings.json"
    data = json.loads(target.read_text())
    data["hooks"] = HOOKS
    write(target, data)
    original = target.read_text()
    scan_cli(cfg, home, project)
    capsys.readouterr()

    assert fix_cli(cfg) == 0
    out = capsys.readouterr().out
    for expected in ("TaintTrail fix", "open paths (the sink runs unasked)", "exhaustive search over",
                     "no cheaper set exists", "ask   Bash(curl:*)", "ask   mcp__github__create_pull_request",
                     "Checked on a rehearsal of the graph: breaks", f"Rules for {target}", '"ask": [',
                     "Apply it with `tainttrail fix --apply --yes`."):
        assert expected in out, expected
    assert target.read_text() == original, "a proposal changes nothing"

    assert fix_cli(cfg, "--apply") == 2
    assert "Add --yes to confirm" in capsys.readouterr().err and target.read_text() == original

    assert fix_cli(cfg, "--apply", "--yes", "--json") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["applied"]["changed"] and result["applied"]["backup"] == str(target) + ".bak"
    assert result["method"] == "exact" and result["live_before"] > 0 and result["live_after"] == 0
    assert result["broken"] == result["live_before"]
    written = json.loads(target.read_text())
    assert written["hooks"] == HOOKS and written["permissions"]["allow"] == ["mcp__github", "Bash(curl:*)"]
    assert "Bash(curl:*)" in written["permissions"]["ask"] and "mcp__github__push_files" in written["permissions"]["ask"]
    assert Path(str(target) + ".bak").read_text() == original

    # The map was updated with the file ...
    assert paths_cli(cfg, "--json") == 0
    assert json.loads(capsys.readouterr().out)["open"] == 0
    # ... and a fresh scan of the changed file reaches the same conclusion on its own.
    scan_cli(cfg, home, project)
    capsys.readouterr()
    assert paths_cli(cfg, "--json") == 0
    rescanned = json.loads(capsys.readouterr().out)
    assert rescanned["open"] == 0 and rescanned["gated"] == rescanned["total"] > 0
    with Store(cfg.db_path) as store:
        pr = tool(store, "mcp__github__create_pull_request")
        assert (pr["permission"], pr["permission_source"]) == ("ask", str(target))

    # Applying again finds nothing to do and touches nothing.
    after = target.read_text()
    assert fix_cli(cfg, "--apply", "--yes") == 0
    assert "Nothing to fix" in capsys.readouterr().out
    assert target.read_text() == after and Path(str(target) + ".bak").read_text() == original


def test_fix_refuses_a_settings_file_it_cannot_merge_and_bad_options(dirs, cfg, capsys):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"])
    scan_cli(cfg, home, project)
    other = write(project / "elsewhere.json", text='{"permissions": "broken"}')
    assert fix_cli(cfg, "--apply", "--yes", "--settings", other) == 1
    assert "left untouched" in capsys.readouterr().err and other.read_text() == '{"permissions": "broken"}'
    with Store(cfg.db_path) as store:
        assert paths.find_paths(store).open > 0, "a failed apply does not update the map either"
    assert fix_cli(cfg, "--exact-limit", "99") == 2
    capsys.readouterr()
    assert fix_cli(cfg, "--method", "greedy", "--json") == 0
    assert json.loads(capsys.readouterr().out)["method"] == "greedy"
    assert fix_cli(cfg, "--strict", "--settings", project / "strict.json", "--apply", "--yes") == 0
    strict = json.loads((project / "strict.json").read_text())["permissions"]["ask"]
    assert "Bash" in strict and "WebFetch" in strict
    assert "Applied:" in capsys.readouterr().out


def test_an_exhaustive_search_is_refused_when_it_could_not_finish(mem, cfg, capsys):
    candidates = [cand(1.0 + i / 100, 1 << i) for i in range(paths.EXACT_CEILING + 1)]
    weights = [1] * len(candidates)
    with pytest.raises(ValueError, match="too many for an exhaustive search"):
        paths.solve(weights, candidates, method="exact")
    assert paths.solve(weights, candidates, exact_limit=10 ** 6).method == "greedy", "auto never exceeds the ceiling"
    assert paths.solve(weights, candidates[:30], method="exact").cost == pytest.approx(sum(c.cost for c in candidates[:30]))


def test_two_allowed_patterns_on_one_tool_are_both_moved_to_ask(mem):
    build(mem, [node("Bash", "builtin", "UPSX", kind="shell", gate="open", gate_data="open",
                     open_partial=["Bash(curl:*)", "Bash(wget:*)"], permission_partial=["allow Bash(curl:*)", "allow Bash(wget:*)"])])
    proposal = paths.propose_fix(mem)
    assert sorted((c.scope, c.rule, c.cost) for c in proposal.changes) == [
        ("pattern", "Bash(curl:*)", 1.5), ("pattern", "Bash(wget:*)", 1.5)]
    assert (proposal.live_before, proposal.live_after) == (1, 0)
    with mem.transaction():
        paths.apply_changes(mem, proposal.changes)
    props = mem.one("MATCH (t:Tool {id: 'claude-code::Bash'}) RETURN properties(t) AS p")["p"]
    assert props["gate"] == "ask" and props["open_partial"] == [] and props["gate_data"] == "open"
    assert props["permission_partial"] == ["allow Bash(curl:*)", "allow Bash(wget:*)", "ask Bash(curl:*)", "ask Bash(wget:*)"]


def test_an_approval_on_the_way_out_decides_the_severity(dirs):
    """Open paths are critical; the same paths behind an approval are not, so a fix shows in the score."""
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        before = paths.find_paths(store)
        assert paths.severity(before.top_score) == "critical"
        proposal = paths.propose_fix(store)
        with store.transaction():
            paths.apply_changes(store, proposal.changes)
        after = paths.find_paths(store)
        assert after.open == 0 and after.total == before.total
        assert after.top_score <= 60 and paths.severity(after.top_score) in ("medium", "high")
        gated_max = paths.make_path(facts("s", "U"), facts("d", "P", kind="shell"), facts("k", "S", gate="ask"))
        assert gated_max.score == 60, "no path that waits for a person at the sink scores higher than this"


def test_a_ci_gate_does_not_pass_when_only_sessions_were_recorded(cfg, capsys):
    with Store(cfg.db_path) as store:       # a graph exists, but nothing was scanned into it
        store.write("CREATE (:Agent {id: 'claude-code', kind: 'claude-code'})<-[:BY]-(:Session {id: 's1'})")
    assert paths_cli(cfg) == 0
    assert "Run `tainttrail scan` first" in capsys.readouterr().out
    assert paths_cli(cfg, "--max-score", "50") == 1
    assert paths_cli(cfg, "--fail-on-new") == 1
    assert "nothing to judge" in capsys.readouterr().err
    assert fix_cli(cfg) == 0
    assert "Nothing to fix" in capsys.readouterr().out


def test_the_two_queries_agree_on_how_many_tools_stand_on_each_leg(dirs):
    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__fetch"], deny=["mcp__filesystem__read_file"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        rows = store.run(paths.PATH_QUERY, {"agent": "claude-code", "deny": [], "ask": []})
        families = paths.path_families(store, "claude-code")
        assert len(rows) == len(families) > 8
        for row, family in zip(rows, families):
            assert (row["sources"], row["data"], row["sinks"]) == (len(family.sources), len(family.data), len(family.sinks))
            assert (row["open_sinks"], row["unpinned_sinks"]) == (len(family.open_sinks), len(family.unpinned_sinks))
            assert row["paths"] == len(family.sources) * len(family.data) * len(family.sinks)
            assert family.open_sinks <= set(family.sinks) and family.unpinned_sinks <= set(family.sinks)
        # ... and under a what-if as well.
        deny, ask = ["claude-code::mcp__fetch__fetch"], ["claude-code::mcp__slack__slack_post_message"]
        for family in paths.path_families(store, "claude-code", deny=deny, ask=ask):
            assert deny[0] not in family.sources + family.sinks and ask[0] not in family.open_sinks
            assert family.open_paths == len(family.sources) * len(family.data) * len(family.open_sinks)


def test_an_instance_too_large_to_list_is_solved_by_counting(mem, cfg, monkeypatch):
    greedy_trap(mem)
    monkeypatch.setattr(paths, "MAX_FAMILIES", 1)       # pretend the trap is enormous
    instance = paths.build_instance("claude-code", paths.path_families(mem, "claude-code"),
                                    paths.tool_facts(mem, "claude-code"))
    assert instance.explicit is False and instance.weights == []
    proposal = paths.propose_fix(mem)
    assert (proposal.method, proposal.live_before, proposal.live_after) == ("greedy", 14, 0)
    assert proposal.cost == 9.0, "the same greedy answer as on the listed instance"
    assert proposal.agents[0].complete
    with pytest.raises(ValueError, match="too many for an exhaustive search"):
        paths.propose_fix(mem, method="exact")


def test_the_example_path_of_a_group_names_three_different_tools_when_that_costs_nothing(mem):
    build(mem, [node("alpha", "srv", "UPS"), node("beta", "srv", "UPS"), node("gamma", "srv", "UPS")])
    [group] = paths.find_paths(mem).groups
    assert (group.top.source, group.top.data, group.top.sink) == ("mcp__srv__alpha", "mcp__srv__beta", "mcp__srv__gamma")
    assert group.top.score == group.top_score == paths.find_paths(mem).paths[0].score
    # When the same tool really is the best on two legs, it is shown on both.
    mem.write("MATCH (t:Tool {id: $id}) SET t.label_confidence = 0.2", {"id": tid("srv", "beta")})
    mem.write("MATCH (t:Tool {id: $id}) SET t.label_confidence = 0.2", {"id": tid("srv", "gamma")})
    [group] = paths.find_paths(mem).groups
    assert (group.top.source, group.top.data, group.top.sink) == ("mcp__srv__alpha",) * 3


def test_no_command_prints_a_secret_that_sits_in_a_configuration_file(dirs, cfg, capsys):
    from tainttrail import scan

    home, project = dirs
    secret_laden_project(home, project)
    outputs = []
    for run in (
        lambda: cli(scan.cmd_scan, scan.add_scan_arguments, cfg, "--home", home, "--path", project),
        lambda: cli(scan.cmd_scan, scan.add_scan_arguments, cfg, "--home", home, "--path", project, "--json"),
        lambda: cli(scan.cmd_tools, scan.add_tools_arguments, cfg),
        lambda: cli(scan.cmd_tools, scan.add_tools_arguments, cfg, "--json"),
        lambda: paths_cli(cfg, "--limit", "20", "--show-query"),
        lambda: paths_cli(cfg, "--json"),
        lambda: fix_cli(cfg),
        lambda: fix_cli(cfg, "--json"),
        lambda: fix_cli(cfg, "--strict", "--apply", "--yes", "--settings", project / "out" / "settings.json"),
    ):
        assert run() == 0
        captured = capsys.readouterr()
        outputs.append(captured.out + captured.err)
    outputs.append((project / "out" / "settings.json").read_text())
    with Store(cfg.db_path) as store:
        outputs.append(graph_text(store))
    for text in outputs:
        for what, canary in CANARIES.items():
            assert canary not in text, f"the {what} was printed or stored"
    # The shell is open because of an allow rule that holds a token; the fix names the tool, not the rule.
    assert '"Bash"' in outputs[7] and "Bearer" not in outputs[7]
