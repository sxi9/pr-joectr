"""No input may keep a hook busy past its time limit.

A hook that is killed by its timeout leaves the call it guarded unchecked, so a pattern that is
quadratic on some input is a way around the guard: one line of test-runner dots, compact JSON
full of URLs, a page of "<!--". Every compiled pattern is timed on runs of awkward text at two
sizes. A linear pattern takes a millisecond here; the quadratic ones this test was written
after took seconds.
"""

from __future__ import annotations

import re
import time

import pytest

from tainttrail import analyze, bashparse, extract

KEY = b"k" * 32
UNITS = [".", "-", "_", "/", ":", "=", "&", "(", ")", "<", ">", "'", '"', "`", "$", ";", "|", "a", "A", "0", " ", "\n",
         "a.", "a/", "a-", "a b ", "x@", "@x.", "a.b.c/", "http://", "https://a/", "https://a.b/?", "a=b&", "$(", "<a>",
         "<!--", "-->", "%41", "token", "secret send ", "password=", "api_key: ", "<!--AI ", "ignore all ", "eyJaaaaaaaa-",
         "AKIA", "-----BEGIN PRIVATE KEY-----", "send the ", "you must ", "https://x.test/<", "https://x.test/a?b=<",
         "git@github.com:a/b ", "./a ", "~/a ", "${A} ", "A=1\n", "\\n", "](http://a)", "user:pass@", "www.", "a@b.c ",
         "Authorization: Bearer ", "--password ", "?key=", "bearer "]


def texts(n: int) -> list[tuple[str, str]]:
    out = [(f"run of {u!r}", (u * (n // len(u) + 1))[:n]) for u in UNITS]
    out += [(f"lines of {u!r}", ((u * 40 + "\n") * (n // (len(u) * 40 + 1) + 1))[:n]) for u in UNITS if len(u) > 1]
    out.append(("test-runner dots", "." * n + "\n" + "-" * 70 + "\nRan 9 tests in 1.2s\n\nOK\n"))
    out.append(("url then brackets", "see https://docs.example.test/a" + ")" * n))
    unit = '{"id":12345,"name":"widget","url":"https://api.example.test/v1/items/12345","token_count":17,"ok":true},'
    out.append(("compact json", "[" + (unit * (n // len(unit) + 1))[:n] + "]"))
    return out


def patterns() -> list[tuple[str, "re.Pattern[str]"]]:
    found = []
    for module in (extract, bashparse, analyze):
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern):
                found.append((f"{module.__name__}.{name}", value))
            elif isinstance(value, (tuple, list)) and value and isinstance(value[0], tuple):
                found += [(f"{module.__name__}.{name}[{item[0]}]", x) for item in value for x in item if isinstance(x, re.Pattern)]
    return found


def spent(pattern: "re.Pattern[str]", text: str) -> float:
    started = time.perf_counter()
    for _ in pattern.finditer(text):
        pass
    return time.perf_counter() - started


def test_every_pattern_is_linear_on_awkward_input():
    small, large = texts(3_000), texts(12_000)
    slow = []
    for name, pattern in patterns():
        for (label, a), (_, b) in zip(small, large):
            first = spent(pattern, a)
            if first > 0.08:            # already far too slow; do not try the larger size
                slow.append((name, label, first))
                continue
            second = spent(pattern, b)
            if second > 0.25:
                slow.append((name, label, second))
    assert slow == [], sorted(slow, key=lambda x: -x[2])[:8]


@pytest.mark.parametrize("label, text", texts(48_000), ids=[t[0] for t in texts(48_000)])
def test_scanning_a_tool_result_stays_within_budget(label, text):
    started = time.perf_counter()
    extract.find_secrets(text)
    extract.injection_score(text)
    extract.extract_entities(text, cwd="/project")
    extract.content_chunks(text, KEY)
    extract.redact(text, 240)
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize("command", [
    "cat " + " ".join(f"f{i}.txt" for i in range(6000)),
    "rm " + " ".join(f"build/out/obj_{i}.o" for i in range(3000)),
    "\n".join("x <<A" for _ in range(8000)),
    "echo " + " ".join("$(date)" for _ in range(4000)),
    "curl " + " ".join(f"https://h{i}.example.test/p" for i in range(2000)),
    "echo " + "`date` " * 6000,
    " && ".join(f"git add f{i}" for i in range(4000)),
    "echo " + "(" * 20000 + ")" * 20000,
], ids=["cat-many", "rm-many", "heredocs", "substitutions", "curl-many-urls", "backticks", "git-add-chain", "brackets"])
def test_parsing_a_long_command_stays_within_budget(command):
    started = time.perf_counter()
    bashparse.analyze_bash(command, "/project")
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize("distinct", [False, True], ids=["one repository read many times", "a repository for every read"])
def test_the_cross_repository_rule_does_not_slow_down_with_the_session(mem, distinct):
    """A page can ask for two hundred reads before the write that leaks. The rule that speaks for
    that write once took twenty seconds at that point, and a hook is killed after ten."""
    from tainttrail import rules

    n = 600
    mem.run("CREATE (:ToolCall {id: 'c', session_id: 's', seq: $seq})-[:SENDS_TO]->(:Entity {id: 'repo:q', kind: 'repo', value: 'q'})",
            {"seq": 2 * n + 10})
    if not distinct:
        mem.run("CREATE (:Entity {id: 'repo:p', kind: 'repo', value: 'p'})")
    mem.run("""
        UNWIND range(1, $n) AS i
        CREATE (r:ToolCall {id: 'r' + toString(i), session_id: 's', seq: 2 * i})
        CREATE (s:Content {id: 'k' + toString(i), session_id: 's', seq: 2 * i + 1, sensitive: true, untrusted: true})
        CREATE (r)-[:RETURNED]->(s)
        WITH r, i
        MERGE (p:Entity {id: CASE WHEN $distinct THEN 'repo:p' + toString(i) ELSE 'repo:p' END})
          ON CREATE SET p.kind = 'repo', p.value = 'p' + toString(i)
        CREATE (r)-[:READS]->(p)""", {"n": n, "distinct": distinct})
    best = None
    for _ in range(3):
        started = time.perf_counter()
        rows = mem.run(rules.CYPHER["TT011"].strip(), {"call": "c"})
        took = time.perf_counter() - started
        best = took if best is None else min(best, took)
    assert len(rows) == 1 and rows[0]["r"]["props"]["id"] == f"r{n}", "the latest read of another repository"
    assert rows[0]["u"]["props"]["id"] == f"k{n - 1}", "and the latest untrusted content before it"
    assert best < 0.5, f"{best:.2f} s for one rule at {n} reads"
