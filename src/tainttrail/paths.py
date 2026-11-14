"""Toxic paths in the capability map: finding them, scoring them, and breaking them.

A toxic path is three tools that one agent can use in the same session::

    source   its results can contain text a third party wrote       (untrusted_input)
    data     its results can contain private data                   (private_data)
    sink     its calls can send data where others can read it       (external_sink)

Text from the source can tell the agent to read with the data tool and send with the
sink. No single tool is the problem; the combination is. So the question is a path
question, and it is asked in Cypher over the graph ``tainttrail scan`` wrote::

    (source)<-[:PROVIDES]-(server)<-[:CONNECTS]-(agent)-[:CONNECTS]->(server)-[:PROVIDES]->(data)
                                                (agent)-[:CONNECTS]->(server)-[:PROVIDES]->(sink)

Every source, every data tool and every sink of one agent combine, so the number of
paths is a product and grows quickly (tens of thousands for one busy server). The query
therefore returns the paths in factored form: one row per (source server, data server,
sink server) with the number of tools on each leg and the number of paths, both computed
inside the query. A second query names the tools on each leg; every source x data x sink
combination of a row is a path, and each one can be checked on its own with the witness
query. A third adds the legs up over the servers: one row of totals per agent, which is
what counting and what-if checks use. The rows of the first query grow with the cube of
the number of servers, so past ``MAX_LISTED_FAMILIES`` of them the same paths are handed
out merged per source server instead.

``fix`` then looks for the cheapest set of permission changes that leaves no path open,
and checks its answer by applying it in a transaction that is rolled back
(``Store.rehearsal``) and running the same query again.
"""

from __future__ import annotations

import argparse
import heapq
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import relate

from . import schema as S
from .config import Config
from .store import Store, StoreError, StoreMissing, open_store

# What happens when a tool is called. ``scan`` stores it as ``Tool.gate`` ("open", "ask" or
# "deny"); a graph that only carries ``permission`` is read the obvious way: allow runs,
# deny refuses, anything else asks.
_GATE = "coalesce(t.gate, t.permission, 'ask')"
_RUNS_UNASKED = f"{_GATE} IN ['open', 'allow']"
# One leg of a path: a tool with a capability, on an enabled server of the agent, not refused.
# (The condition is repeated rather than named in a WITH: Relate 1.0 does not see an alias
# introduced by WITH ... WHERE inside a CALL subquery.)
_LEG = (
    "MATCH (a)-[:CONNECTS]->(s:Server)-[:PROVIDES]->(t:Tool)"
    "-[:HAS_CAPABILITY]->(:Capability {{name: '{capability}'}})\n"
    f"  WHERE coalesce(s.enabled, true) AND {_GATE} <> 'deny' AND NOT t.id IN $deny"
)

AGENTS_QUERY = """
MATCH (a:Agent)
WHERE EXISTS { (a)-[:CONNECTS]->(:Server) }
RETURN a.id AS id, coalesce(a.name, a.id) AS name, coalesce(a.permission_mode, '') AS permission_mode
ORDER BY id"""

# The toxic-path query. Parameters: $agent (the Agent it is anchored on), and two lists
# for what-if questions that must not write: $deny (tool ids to treat as denied) and
# $ask (tool ids to treat as asking first). Pass empty lists for the graph as it is.
#
# Each subquery follows one leg from the agent and counts its tools per server; every
# combination of a source leg, a data leg and a sink leg is then a family of paths, and
# the number of paths in it is the product of the three counts. A path is "open" when its
# sink runs without asking anyone, and "unpinned" when no explicit ask rule holds the sink
# (it may still ask today because of the permission mode).
PATH_QUERY = f"""
MATCH (a:Agent {{id: $agent}})
CALL (a) {{
  {_LEG.format(capability=S.CAP_UNTRUSTED_INPUT)}
  WITH s, count(t) AS tools
  RETURN collect({{server: s.id, tools: tools}}) AS source_legs
}}
CALL (a) {{
  {_LEG.format(capability=S.CAP_PRIVATE_DATA)}
  WITH s, count(t) AS tools
  RETURN collect({{server: s.id, tools: tools}}) AS data_legs
}}
CALL (a) {{
  {_LEG.format(capability=S.CAP_EXTERNAL_SINK)}
  WITH s, count(t) AS tools,
       sum(CASE WHEN {_RUNS_UNASKED} AND NOT t.id IN $ask THEN 1 ELSE 0 END) AS open,
       sum(CASE WHEN coalesce(t.permission, 'default') <> 'ask' AND NOT t.id IN $ask THEN 1 ELSE 0 END) AS unpinned
  RETURN collect({{server: s.id, tools: tools, open: open, unpinned: unpinned}}) AS sink_legs
}}
UNWIND source_legs AS src
UNWIND data_legs AS dat
UNWIND sink_legs AS snk
RETURN a.id AS agent, src.server AS source_server, dat.server AS data_server, snk.server AS sink_server,
       src.tools AS sources, dat.tools AS data, snk.tools AS sinks,
       snk.open AS open_sinks, snk.unpinned AS unpinned_sinks,
       src.tools * dat.tools * snk.tools AS paths,
       src.tools * dat.tools * snk.open AS open_paths,
       src.tools * dat.tools * snk.unpinned AS unpinned_paths
ORDER BY open_paths DESC, paths DESC, source_server, data_server, sink_server"""

# The same three legs, added up over the agent's servers: what the rows of the path query
# sum to. Every source combines with every data tool and every sink of the agent, so the
# totals are products of three counts. One row at any size, which is what counting and
# what-if checks need (the path query's rows grow with the cube of the number of servers).
TOTALS_QUERY = f"""
MATCH (a:Agent {{id: $agent}})
CALL (a) {{
  {_LEG.format(capability=S.CAP_UNTRUSTED_INPUT)}
  RETURN count(t) AS sources
}}
CALL (a) {{
  {_LEG.format(capability=S.CAP_PRIVATE_DATA)}
  RETURN count(t) AS data
}}
CALL (a) {{
  {_LEG.format(capability=S.CAP_EXTERNAL_SINK)}
  RETURN count(t) AS sinks,
         sum(CASE WHEN {_RUNS_UNASKED} AND NOT t.id IN $ask THEN 1 ELSE 0 END) AS open_sinks,
         sum(CASE WHEN coalesce(t.permission, 'default') <> 'ask' AND NOT t.id IN $ask THEN 1 ELSE 0 END) AS unpinned_sinks
}}
RETURN a.id AS agent, sources, data, sinks, open_sinks, unpinned_sinks,
       sources * data * sinks AS paths,
       sources * data * open_sinks AS open_paths,
       sources * data * unpinned_sinks AS unpinned_paths"""

# Which tools stand on each leg. Same conditions and parameters as the path query; it
# names the tools that the path query counts.
LEGS_QUERY = f"""
MATCH (a:Agent {{id: $agent}})-[:CONNECTS]->(s:Server)-[:PROVIDES]->(t:Tool)-[:HAS_CAPABILITY]->(c:Capability)
WHERE c.name IN ['{S.CAP_UNTRUSTED_INPUT}', '{S.CAP_PRIVATE_DATA}', '{S.CAP_EXTERNAL_SINK}']
  AND coalesce(s.enabled, true) AND {_GATE} <> 'deny' AND NOT t.id IN $deny
RETURN s.id AS server, c.name AS capability, collect(t.id) AS tools,
       collect(CASE WHEN {_RUNS_UNASKED} AND NOT t.id IN $ask THEN t.id END) AS open,
       collect(CASE WHEN coalesce(t.permission, 'default') <> 'ask' AND NOT t.id IN $ask THEN t.id END) AS unpinned"""

# One path, as three stored chains. Anyone can re-run it against the graph or an export.
WITNESS_QUERY = f"""
MATCH source = (a:Agent {{id: $agent}})-[:CONNECTS]->(:Server)-[:PROVIDES]->(:Tool {{id: $source}})
               -[:HAS_CAPABILITY]->(:Capability {{name: '{S.CAP_UNTRUSTED_INPUT}'}})
MATCH data = (a)-[:CONNECTS]->(:Server)-[:PROVIDES]->(:Tool {{id: $data}})
             -[:HAS_CAPABILITY]->(:Capability {{name: '{S.CAP_PRIVATE_DATA}'}})
MATCH sink = (a)-[:CONNECTS]->(:Server)-[:PROVIDES]->(:Tool {{id: $sink}})
             -[:HAS_CAPABILITY]->(:Capability {{name: '{S.CAP_EXTERNAL_SINK}'}})
RETURN source, data, sink"""

# The facts the score and the cost model need about each tool of an agent.
TOOLS_QUERY = """
MATCH (a:Agent {id: $agent})-[:CONNECTS]->(s:Server)-[:PROVIDES]->(t:Tool)
RETURN t.id AS id, properties(t) AS tool, s.id AS server_id, s.name AS server,
       coalesce(s.transport, '') AS transport, coalesce(s.catalog_id, '') AS catalog_id,
       coalesce(s.risk_flags, []) AS risk_flags, coalesce(s.enabled, true) AS enabled,
       COUNT { (:ToolCall)-[:INVOKES]->(t) } AS calls
ORDER BY id"""


# -- what is known about a tool ------------------------------------------------------------------


@dataclass(frozen=True)
class ToolFacts:
    id: str
    name: str
    agent: str
    server_id: str
    server: str             # the server's name as configured
    server_key: str         # the server part of the tool's name (what a permission rule uses)
    tool: str               # the tool's own name on its server
    builtin: bool
    enabled: bool
    kind: str               # "shell" | "read" | "edit" | "fetch" | "search" | "none" | "mcp" | "other"
    gate: str               # "open" | "ask" | "deny"
    gate_data: str          # gate when the tool only reads; differs for a shell
    permission: str
    capabilities: frozenset[str]
    confidence: float
    label_source: str
    source_scope: str
    sink_scope: str
    catalog_id: str
    risk_flags: tuple[str, ...]
    open_partial: tuple[str, ...]
    calls: int

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


def _gate_of(props: Mapping[str, Any]) -> str:
    gate = props.get("gate")
    if gate in ("open", "ask", "deny"):
        return str(gate)
    return {"deny": "deny", "allow": "open"}.get(str(props.get("permission") or "default"), "ask")


def tool_facts(store: Store, agent: str) -> dict[str, ToolFacts]:
    """Every tool the agent's servers provide, keyed by tool id."""
    facts: dict[str, ToolFacts] = {}
    for row in store.run(TOOLS_QUERY, {"agent": agent}):
        props = row["tool"]
        name = str(props.get("name") or row["id"].split("::", 1)[-1])
        builtin = row["transport"] == "builtin"
        gate = _gate_of(props)
        facts[row["id"]] = ToolFacts(
            id=row["id"], name=name, agent=agent, server_id=row["server_id"], server=str(row["server"] or ""),
            server_key=str(props.get("server") or row["server"] or ""), tool=str(props.get("tool") or name),
            builtin=builtin, enabled=bool(row["enabled"]),
            kind=str(props.get("kind") or ("other" if builtin else "mcp")),
            gate=gate, gate_data=str(props.get("gate_data") or gate),
            permission=str(props.get("permission") or "default"),
            capabilities=frozenset(c for c in S.CAPABILITIES if props.get(c)),
            confidence=float(props.get("label_confidence") or 0.0),
            label_source=str(props.get("label_source") or "default"),
            source_scope=str(props.get("source_scope") or ""), sink_scope=str(props.get("sink_scope") or ""),
            catalog_id=str(row["catalog_id"] or ""), risk_flags=tuple(row["risk_flags"] or ()),
            open_partial=tuple(props.get("open_partial") or ()), calls=int(row["calls"] or 0),
        )
    return facts


# -- scoring -----------------------------------------------------------------------------------------
# 0..100, the sum of six parts. Each part is reported with the reason for its value, so a
# score can always be explained, and each part except the last belongs to one leg, so the
# best path of a product of legs is found without enumerating the product.
#
# Whether anyone is asked before data leaves weighs most: a path whose sink waits for a
# person cannot score above 60, a path that runs on its own starts at 45.

WEIGHTS: dict[str, float] = {
    "exposure": 15.0,       # how easily a third party gets text into the source
    "data": 12.0,           # how sensitive what the data leg reaches is
    "sink": 13.0,           # who can read what the sink sends
    "unattended": 45.0,     # legs that run without a person approving (source 2.5, data 2.5, sink 40)
    "confidence": 5.0,      # how sure the capability labels are
    "single_server": 10.0,  # one server provides all three legs
}
_UNATTENDED = {"source": 2.5, "data": 2.5, "sink": 40.0}
_EXPOSURE = {
    "public": (1.0, "anyone on the internet can plant text there"),
    "org": (0.6, "people and integrations inside your organisation can plant text there"),
    "local": (0.3, "only content that is already on this machine reaches it"),
    "": (0.6, "who can write what it returns is not known"),
}
_SINK = {
    "public": (1.0, "anyone can read what it sends, or it sends to a destination the caller picks"),
    "org": (0.6, "members of your organisation or workspace can read what it sends"),
    "private": (0.3, "what it sends stays inside your own account"),
    "": (0.7, "who can read what it sends is not known"),
}
_NAMES_ONLY = re.compile(r"^(?:list|ls|glob|tree|directory|find|search_files|get_file_info)(?:_|$)|_list$", re.I)


def _data_factor(tool: ToolFacts) -> tuple[float, str]:
    if tool.kind == "shell" or tool.has(S.CAP_CODE_EXEC):
        return 1.0, "it runs commands, so it can read whatever the user can, credentials included"
    names_only = bool(_NAMES_ONLY.search(tool.tool)) and not tool.has(S.CAP_UNTRUSTED_INPUT)
    if tool.kind == "read" or tool.catalog_id in ("filesystem", "desktop-commander"):
        if names_only:
            return 0.5, "it lists file names, not their contents"
        return 1.0, "it reads files on this machine, credentials and keys included"
    if names_only:
        return 0.5, "it returns names and metadata rather than contents"
    if tool.risk_flags:
        return 0.9, f"private data behind the server, widened by {tool.risk_flags[0]}"
    return 0.8, "private data of the account or workspace behind the server"


def _runs_unasked(tool: ToolFacts, role: str) -> bool:
    return (tool.gate_data if role == "data" else tool.gate) == "open"


def leg_points(tool: ToolFacts, role: str) -> tuple[dict[str, float], dict[str, str]]:
    """The score parts one leg contributes, and the reason for each."""
    if role == "source":
        factor, why = _EXPOSURE.get(tool.source_scope, _EXPOSURE[""])
        part = "exposure"
    elif role == "data":
        factor, why = _data_factor(tool)
        part = "data"
    else:
        factor, why = _SINK.get(tool.sink_scope, _SINK[""])
        part = "sink"
    points = {
        part: WEIGHTS[part] * factor,
        "unattended": _UNATTENDED[role] if _runs_unasked(tool, role) else 0.0,
        "confidence": WEIGHTS["confidence"] * max(0.0, min(1.0, tool.confidence)) / 3.0,
    }
    return points, {part: why}


def leg_total(tool: ToolFacts, role: str) -> float:
    return sum(leg_points(tool, role)[0].values())


# -- paths ---------------------------------------------------------------------------------------------

_WHO = {
    "public": "anyone on the internet",
    "org": "people and integrations inside your organisation",
    "local": "whoever put files on this machine",
    "": "a third party",
}
_WHERE = {
    "public": "where anyone can read it",
    "org": "where your organisation can read it",
    "private": "out of this machine, into your own account",
    "": "off this machine",
}


@dataclass
class ToxicPath:
    """One source, one data tool and one sink that an agent can chain."""

    agent: str
    source: str             # tool names, exactly as the agent calls them
    data: str
    sink: str
    source_id: str
    data_id: str
    sink_id: str
    source_server: str      # server names; "built-in" for the agent's own tools
    data_server: str
    sink_server: str
    score: int              # 0..100, the sum of ``components``
    components: dict[str, float]
    why: dict[str, str]     # one reason per component
    status: str             # "open": the sink runs unasked; "gated": the sink asks a person first
    single_server: bool     # all three legs on one MCP server: the classic case
    builtin_only: bool      # the agent's own tools are enough
    sentence: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source_id, self.data_id, self.sink_id)

    @property
    def params(self) -> dict[str, str]:
        return {"agent": self.agent, "source": self.source_id, "data": self.data_id, "sink": self.sink_id}

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent, "source": self.source, "data": self.data, "sink": self.sink,
            "source_id": self.source_id, "data_id": self.data_id, "sink_id": self.sink_id,
            "source_server": self.source_server, "data_server": self.data_server, "sink_server": self.sink_server,
            "score": self.score, "components": dict(self.components), "why": dict(self.why),
            "status": self.status, "single_server": self.single_server, "builtin_only": self.builtin_only,
            "sentence": self.sentence, "query": WITNESS_QUERY.strip(), "params": self.params,
        }


def _server_label(tool: ToolFacts) -> str:
    return "built-in" if tool.builtin else tool.server


def path_score(source: ToolFacts, data: ToolFacts, sink: ToolFacts) -> tuple[int, dict[str, float], dict[str, str]]:
    """``(score, parts, reason for each leg's part)`` of one combination. The score is the sum of the parts."""
    components = {name: 0.0 for name in WEIGHTS}
    why: dict[str, str] = {}
    for tool, role in ((source, "source"), (data, "data"), (sink, "sink")):
        points, reasons = leg_points(tool, role)
        for name, value in points.items():
            components[name] += value
        why.update(reasons)
    same = source.server_id == data.server_id == sink.server_id
    components["single_server"] = WEIGHTS["single_server"] if same else 0.0
    components = {name: round(value, 1) for name, value in components.items()}
    return max(0, min(100, int(sum(components.values()) + 0.5))), components, why


def make_path(source: ToolFacts, data: ToolFacts, sink: ToolFacts) -> ToxicPath:
    """Score one combination and say in plain words what it means."""
    legs = ((source, "source"), (data, "data"), (sink, "sink"))
    score, components, why = path_score(source, data, sink)
    same = source.server_id == data.server_id == sink.server_id
    builtin_only = source.builtin and data.builtin and sink.builtin
    unasked = [role for tool, role in legs if _runs_unasked(tool, role)]
    why["unattended"] = ("no leg waits for a person" if len(unasked) == 3 else
                         f"runs without approval: {', '.join(unasked)}" if unasked else
                         "every leg waits for a person's approval")
    why["confidence"] = "labels: " + ", ".join(f"{t.label_source} {t.confidence:.1f}" for t, _ in legs)
    why["single_server"] = (f"all three legs are provided by {_server_label(source)}" if same
                            else "the legs come from different servers")
    status = "open" if sink.gate == "open" else "gated"

    text = (f"{source.name} can bring in text written by {_WHO.get(source.source_scope, _WHO[''])}; "
            f"{data.name} can read private data; {sink.name} can send it "
            f"{_WHERE.get(sink.sink_scope, _WHERE[''])}.")
    if builtin_only:
        text += " The agent's built-in tools are enough for all three legs."
    elif same:
        text += f" All three legs are on the one server {source.server}: the classic single-server path."
    else:
        text += f" Servers: {_server_label(source)} -> {_server_label(data)} -> {_server_label(sink)}."
    text += (" The sink runs without asking anyone." if status == "open"
             else " The sink asks for approval first, so the path is gated by approval.")
    return ToxicPath(
        agent=source.agent, source=source.name, data=data.name, sink=sink.name,
        source_id=source.id, data_id=data.id, sink_id=sink.id,
        source_server=_server_label(source), data_server=_server_label(data), sink_server=_server_label(sink),
        score=score, components=components, why=why,
        status=status, single_server=same and not builtin_only, builtin_only=builtin_only, sentence=text,
    )


@dataclass
class Family:
    """One row of ``PATH_QUERY``: every source x data x sink combination in it is a path.

    The tool lists come from ``LEGS_QUERY`` and are shared between the families of an
    agent, so they must not be changed in place.
    """

    agent: str
    source_server: str      # server ids
    data_server: str
    sink_server: str
    sources: list[str]      # tool ids
    data: list[str]
    sinks: list[str]
    open_sinks: frozenset[str]
    unpinned_sinks: frozenset[str]
    paths: int              # the three counts are computed by the path query
    open_paths: int
    unpinned_paths: int
    combinations: int = 1   # server triples it stands for; more than one in a merged family
    merged: bool = False


MAX_LISTED_FAMILIES = 40_000        # server triples the path query lists one by one
OTHER_SERVERS = "(other servers)"   # shown in place of a server name in a merged family
ANY_SERVER = "(any server)"
_Leg = tuple[list[str], frozenset[str], frozenset[str]]
_NO_LEG: _Leg = ([], frozenset(), frozenset())


def _merged_families(agent: str, legs: Mapping[tuple[str, str], _Leg]) -> list[Family]:
    """The agent's paths as a few products per source server, for when the server triples are too many to list.

    For a source server ``a`` the paths split three ways: data and sink on ``a`` as well (the
    single-server case), data on ``a`` and the sink elsewhere, and data elsewhere with the
    sink anywhere. The three parts are disjoint and together are every path that starts on
    ``a``, so counting, ranking and the fix advisor work on them as on listed families.
    """
    def servers(capability: str) -> list[str]:
        return sorted(server for server, cap in legs if cap == capability)

    all_data = sorted(i for s in servers(S.CAP_PRIVATE_DATA) for i in legs[(s, S.CAP_PRIVATE_DATA)][0])
    all_sinks = sorted(i for s in servers(S.CAP_EXTERNAL_SINK) for i in legs[(s, S.CAP_EXTERNAL_SINK)][0])
    all_open = frozenset(i for s in servers(S.CAP_EXTERNAL_SINK) for i in legs[(s, S.CAP_EXTERNAL_SINK)][1])
    all_unpinned = frozenset(i for s in servers(S.CAP_EXTERNAL_SINK) for i in legs[(s, S.CAP_EXTERNAL_SINK)][2])
    data_servers, sink_servers = len(servers(S.CAP_PRIVATE_DATA)), len(servers(S.CAP_EXTERNAL_SINK))
    families: list[Family] = []

    def add(source_server: str, data_server: str, sink_server: str, sources: list[str], data: list[str],
            sinks: list[str], open_sinks: frozenset[str], unpinned: frozenset[str], combinations: int) -> None:
        if sources and data and sinks:
            pairs = len(sources) * len(data)
            families.append(Family(agent, source_server, data_server, sink_server, sources, data, sinks,
                                   open_sinks, unpinned, pairs * len(sinks), pairs * len(open_sinks),
                                   pairs * len(unpinned), combinations, True))

    for a in servers(S.CAP_UNTRUSTED_INPUT):
        sources = legs[(a, S.CAP_UNTRUSTED_INPUT)][0]
        own_data = legs.get((a, S.CAP_PRIVATE_DATA), _NO_LEG)[0]
        own_sinks, own_open, own_unpinned = legs.get((a, S.CAP_EXTERNAL_SINK), _NO_LEG)
        if own_data and own_sinks:
            held, kept = set(own_data), set(own_sinks)
            other_data = [i for i in all_data if i not in held]
            other_sinks = [i for i in all_sinks if i not in kept]
            add(a, a, a, sources, own_data, own_sinks, own_open, own_unpinned, 1)
            add(a, a, OTHER_SERVERS, sources, own_data, other_sinks, all_open - own_open,
                all_unpinned - own_unpinned, sink_servers - 1)
            add(a, OTHER_SERVERS, ANY_SERVER, sources, other_data, all_sinks, all_open, all_unpinned,
                (data_servers - 1) * sink_servers)
        elif own_data:
            held = set(own_data)
            add(a, a, ANY_SERVER, sources, own_data, all_sinks, all_open, all_unpinned, sink_servers)
            add(a, OTHER_SERVERS, ANY_SERVER, sources, [i for i in all_data if i not in held], all_sinks, all_open,
                all_unpinned, (data_servers - 1) * sink_servers)
        else:
            add(a, ANY_SERVER, ANY_SERVER, sources, all_data, all_sinks, all_open, all_unpinned,
                data_servers * sink_servers)
    return families


def path_families(store: Store, agent: str, *, deny: Iterable[str] = (), ask: Iterable[str] = (),
                  merged: bool | None = None) -> list[Family]:
    """Run the toxic-path query for one agent. ``deny`` and ``ask`` pose a what-if without writing.

    One family per (source server, data server, sink server) while there are at most
    ``MAX_LISTED_FAMILIES`` of them; beyond that the same paths come back merged per source
    server, because the listing would outgrow what the graph engine builds in one statement.
    ``merged=True`` asks for the merged form at any size: enough for a caller that needs
    the legs and not the server triples.
    """
    params = {"agent": agent, "deny": list(deny), "ask": list(ask)}
    legs: dict[tuple[str, str], _Leg] = {}
    for row in store.run(LEGS_QUERY, params):
        legs[(row["server"], row["capability"])] = (
            sorted(row["tools"]), frozenset(row["open"]), frozenset(row["unpinned"]))
    triples = 1
    for capability in (S.CAP_UNTRUSTED_INPUT, S.CAP_PRIVATE_DATA, S.CAP_EXTERNAL_SINK):
        triples *= sum(1 for _server, cap in legs if cap == capability)
    if merged or (merged is None and triples > MAX_LISTED_FAMILIES):
        return _merged_families(agent, legs)
    families = []
    for row in store.run(PATH_QUERY, params):
        sinks, open_sinks, unpinned_sinks = legs.get((row["sink_server"], S.CAP_EXTERNAL_SINK), _NO_LEG)
        families.append(Family(
            agent=row["agent"], source_server=row["source_server"], data_server=row["data_server"],
            sink_server=row["sink_server"],
            sources=legs.get((row["source_server"], S.CAP_UNTRUSTED_INPUT), _NO_LEG)[0],
            data=legs.get((row["data_server"], S.CAP_PRIVATE_DATA), _NO_LEG)[0],
            sinks=sinks, open_sinks=open_sinks, unpinned_sinks=unpinned_sinks,
            paths=int(row["paths"]), open_paths=int(row["open_paths"]), unpinned_paths=int(row["unpinned_paths"]),
        ))
    return families


class _Ranking:
    """Sorted legs of families, computed once per leg however many families share it."""

    def __init__(self, facts: Mapping[str, ToolFacts], status: str | None = None) -> None:
        self.facts, self.status = facts, status
        self._totals: dict[tuple[str, str], float] = {}
        self._sorted: dict[tuple[int, str, int], list[tuple[float, str]]] = {}

    def total(self, tool_id: str, role: str) -> float:
        key = (tool_id, role)
        if key not in self._totals:
            self._totals[key] = leg_total(self.facts[tool_id], role)
        return self._totals[key]

    def legs(self, family: Family) -> tuple[list[tuple[float, str]], ...]:
        """``(points, tool id)`` lists for the source, data and sink leg, best first.

        Equal points: tools that recorded sessions really called come first, then by name.
        """
        out = []
        for ids, role in ((family.sources, "source"), (family.data, "data"), (family.sinks, "sink")):
            key = (id(ids), role, id(family.open_sinks) if role == "sink" and self.status else 0)
            ranked = self._sorted.get(key)
            if ranked is None:
                if role == "sink" and self.status:
                    ids = [i for i in ids if (i in family.open_sinks) == (self.status == "open")]
                ranked = sorted(((self.total(i, role), i) for i in ids if i in self.facts),
                                key=lambda pair: (-pair[0], -self.facts[pair[1]].calls, pair[1]))
                self._sorted[key] = ranked
            out.append(ranked)
        return tuple(out)


def _spread(a: list[tuple[float, str]], b: list[tuple[float, str]], c: list[tuple[float, str]]) -> tuple[int, int, int]:
    """Positions of a best triple that names three different tools where that costs no points.

    One tool can be source and data leg at once. Shown as an example, a path through
    three tools is easier to read, so among equally scored legs a different tool is taken.
    """
    j = 1 if len(b) > 1 and b[0][1] == a[0][1] and b[1][0] == b[0][0] else 0
    used = {a[0][1], b[j][1]}
    k = next((n for n in range(min(len(c), 8)) if c[n][0] == c[0][0] and c[n][1] not in used), 0)
    return 0, j, k


def best_paths(families: Iterable[Family], facts: Mapping[str, ToolFacts], *, limit: int = 20,
               min_score: int = 0, status: str | None = None) -> list[ToxicPath]:
    """The highest-scoring paths of some families, without enumerating their products.

    A path's score is a sum over its legs plus a constant per family, so within a family
    the best combinations are found by walking three sorted lists with a heap.
    """
    families = list(families)       # the ranking keys on the identity of their lists: keep them alive
    ranking = _Ranking(facts, status)
    ranked: list[tuple[list, list, list, float] | None] = []
    heap: list[tuple[float, int, int, int, int]] = []
    for index, family in enumerate(families):
        a, b, c = ranking.legs(family)
        if not (a and b and c):
            ranked.append(None)
            continue
        same = family.source_server == family.data_server == family.sink_server
        bonus = WEIGHTS["single_server"] if same else 0.0
        ranked.append((a, b, c, bonus))
        heapq.heappush(heap, (-(a[0][0] + b[0][0] + c[0][0] + bonus), index, 0, 0, 0))
    seen = {(index, 0, 0, 0) for index in range(len(ranked))}
    out: list[ToxicPath] = []
    while heap and len(out) < max(0, limit):
        negative, index, i, j, k = heapq.heappop(heap)
        if -negative < min_score - 1:       # rounding can lift a path by less than one point
            break
        a, b, c, bonus = ranked[index]  # type: ignore[misc]
        path = make_path(facts[a[i][1]], facts[b[j][1]], facts[c[k][1]])
        if path.score >= min_score:
            out.append(path)
        for ni, nj, nk in ((i + 1, j, k), (i, j + 1, k), (i, j, k + 1)):
            if ni < len(a) and nj < len(b) and nk < len(c) and (index, ni, nj, nk) not in seen:
                seen.add((index, ni, nj, nk))
                heapq.heappush(heap, (-(a[ni][0] + b[nj][0] + c[nk][0] + bonus), index, ni, nj, nk))
    out.sort(key=lambda p: -p.score)    # stable: equal scores stay in the order the heap gave them
    return out


@dataclass
class PathGroup:
    """The paths that share a (source server, data server, sink server) triple."""

    agent: str
    source_server: str      # names; "built-in" for the agent's own tools
    data_server: str
    sink_server: str
    paths: int
    open: int
    gated: int
    sources: int            # tools on each leg
    data: int
    sinks: int
    single_server: bool     # all three legs on one MCP server
    top_score: int = 0      # the score of its worst path
    legs: tuple[ToolFacts, ToolFacts, ToolFacts] | None = field(default=None, repr=False)
    _top: ToxicPath | None = field(default=None, repr=False)

    @property
    def top(self) -> ToxicPath | None:
        """The group's worst path, spelled out. Built on first use: there can be thousands of groups."""
        if self._top is None and self.legs is not None:
            self._top = make_path(*self.legs)
        return self._top

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent, "source_server": self.source_server, "data_server": self.data_server,
            "sink_server": self.sink_server, "paths": self.paths, "open": self.open, "gated": self.gated,
            "sources": self.sources, "data": self.data, "sinks": self.sinks,
            "single_server": self.single_server, "top_score": self.top_score,
            "top": self.top.to_dict() if self.top else None,
        }


@dataclass
class PathReport:
    agents: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    open: int = 0
    gated: int = 0
    groups: list[PathGroup] = field(default_factory=list)
    paths: list[ToxicPath] = field(default_factory=list)       # the highest-scoring ones, at most ``limit``
    legs: dict[str, dict[str, list[str]]] = field(default_factory=dict)   # agent -> role -> tool ids
    families: list[Family] = field(default_factory=list, repr=False)
    facts: dict[str, ToolFacts] = field(default_factory=dict, repr=False)
    combinations: int = 0       # (source server, data server, sink server) triples that carry a path
    merged: bool = False        # too many triples to list: ``groups`` are per source server instead

    @property
    def top_score(self) -> int:
        return max((g.top_score for g in self.groups), default=0)

    def to_dict(self, groups: int | None = None) -> dict[str, Any]:
        """Plain values for JSON. ``groups`` caps how many server triples are spelled out."""
        shown = self.groups if groups is None else self.groups[:groups]
        return {
            "agents": self.agents, "total": self.total, "open": self.open, "gated": self.gated,
            "top_score": self.top_score, "group_count": len(self.groups),
            "combinations": self.combinations, "merged": self.merged,
            "groups": [g.to_dict() for g in shown],
            "paths": [p.to_dict() for p in self.paths], "query": PATH_QUERY.strip(),
        }


def find_paths(store: Store, *, agent: str | None = None, limit: int = 20, min_score: int = 0,
               status: str | None = None) -> PathReport:
    """Every toxic path in the capability map, grouped by server triple, with the worst ones spelled out."""
    report = PathReport()
    for row in store.run(AGENTS_QUERY):
        if agent and row["id"] != agent:
            continue
        facts = tool_facts(store, row["id"])
        families = path_families(store, row["id"])
        report.facts.update(facts)
        report.families += families
        report.combinations += sum(f.combinations for f in families)
        report.merged = report.merged or any(f.merged for f in families)
        names = {t.server_id: _server_label(t) for t in facts.values()}
        builtin = {t.server_id for t in facts.values() if t.builtin}
        ranking = _Ranking(facts)
        legs: dict[str, set[str]] = {"sources": set(), "data": set(), "sinks": set(), "open_sinks": set()}
        merged: set[int] = set()
        for family in families:
            for role, ids in (("sources", family.sources), ("data", family.data), ("sinks", family.sinks),
                              ("open_sinks", family.open_sinks)):
                if id(ids) not in merged:       # the lists are shared between families
                    merged.add(id(ids))
                    legs[role].update(ids)
            a, b, c = ranking.legs(family)
            best = None
            if a and b and c:
                i, j, k = _spread(a, b, c)
                best = (facts[a[i][1]], facts[b[j][1]], facts[c[k][1]])
            same = family.source_server == family.data_server == family.sink_server
            report.groups.append(PathGroup(
                agent=family.agent, source_server=names.get(family.source_server, family.source_server),
                data_server=names.get(family.data_server, family.data_server),
                sink_server=names.get(family.sink_server, family.sink_server),
                paths=family.paths, open=family.open_paths, gated=family.paths - family.open_paths,
                sources=len(family.sources), data=len(family.data), sinks=len(family.sinks),
                single_server=same and family.source_server not in builtin,
                top_score=path_score(*best)[0] if best else 0, legs=best,
            ))
        paths = sum(f.paths for f in families)
        opened = sum(f.open_paths for f in families)
        report.agents.append({"id": row["id"], "name": row["name"], "permission_mode": row["permission_mode"],
                              "paths": paths, "open": opened, "gated": paths - opened})
        report.legs[row["id"]] = {role: sorted(ids) for role, ids in legs.items()}
        report.total += paths
        report.open += opened
    report.gated = report.total - report.open
    report.groups.sort(key=lambda g: (-g.top_score, -g.open, -g.paths,
                                      g.agent, g.source_server, g.data_server, g.sink_server))
    report.paths = best_paths(report.families, report.facts, limit=limit, min_score=min_score, status=status)
    return report


def count_paths(store: Store, agent: str, *, deny: Iterable[str] = (), ask: Iterable[str] = ()) -> dict[str, int]:
    """The path query's totals for one agent: all paths, open ones, and ones no ask rule holds."""
    row = store.one(TOTALS_QUERY, {"agent": agent, "deny": list(deny), "ask": list(ask)}) or {}
    return {"paths": int(row.get("paths") or 0), "open": int(row.get("open_paths") or 0),
            "unpinned": int(row.get("unpinned_paths") or 0)}


def witness(store: Store, path: ToxicPath) -> dict[str, Any] | None:
    """The stored chains behind one path (three graph paths), or None if it does not exist."""
    return store.one(WITNESS_QUERY, path.params)


def simulate(store: Store, *, deny: Iterable[str] = (), ask: Iterable[str] = (),
             agent: str | None = None) -> dict[str, int]:
    """What would be left if these tools were denied or made to ask? Reads only.

    The same query runs with its what-if parameters, so this works on a read-only store
    (the MCP server's ``simulate_fix`` uses it).
    """
    before = after = before_open = after_open = 0
    deny, ask = list(deny), list(ask)
    for row in store.run(AGENTS_QUERY):
        if agent and row["id"] != agent:
            continue
        now, then = count_paths(store, row["id"]), count_paths(store, row["id"], deny=deny, ask=ask)
        before, before_open = before + now["paths"], before_open + now["open"]
        after, after_open = after + then["paths"], after_open + then["open"]
    return {"paths_before": before, "paths_after": after, "open_before": before_open, "open_after": after_open,
            "broken": before_open - after_open}


# -- baselines: which paths are new ------------------------------------------------------------------
# The reviewed state is kept as the legs of the paths (three sets of tool ids per agent),
# which describes a product of legs exactly and stays small.

BASELINE_FORMAT = "tainttrail-paths-baseline/1"


def baseline_of(report: PathReport, keep: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The report's legs as a baseline. ``keep`` is an earlier baseline whose other agents stay as they are."""
    agents = {**((keep or {}).get("agents") or {}), **report.legs}
    return {"format": BASELINE_FORMAT, "agents": agents}


def _write_atomically(target: Path, text: str, mode: int | None = None) -> None:
    """Write a file by renaming a finished temporary file onto it.

    A reader never sees half a file, and a symbolic link planted at the path is replaced,
    not followed: nothing is ever written through it to wherever it points.
    """
    import tempfile

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def save_baseline(path: str | os.PathLike[str], report: PathReport, *, keep: Mapping[str, Any] | None = None) -> None:
    _write_atomically(Path(path), json.dumps(baseline_of(report, keep), indent=1, sort_keys=True) + "\n")


def load_baseline(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The recorded baseline, None when there is none yet. Raises ValueError for a broken file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"{path} cannot be read ({exc.strerror or type(exc).__name__})") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT or not _baseline_agents_ok(data.get("agents")):
        raise ValueError(f"{path} is not a TaintTrail path baseline")
    return data


def _baseline_agents_ok(agents: Any) -> bool:
    """``{agent: {role: [tool id, ...]}}`` and nothing else: the file may be anybody's by the time CI reads it."""
    return isinstance(agents, dict) and all(
        isinstance(agent, str) and isinstance(legs, dict) and all(
            isinstance(role, str) and isinstance(ids, list) and all(isinstance(i, str) for i in ids)
            for role, ids in legs.items())
        for agent, legs in agents.items())


def new_paths(report: PathReport, baseline: Mapping[str, Any] | None, *, limit: int = 20,
              min_score: int = 0) -> tuple[int, list[ToxicPath]]:
    """How many paths the baseline does not cover, and the highest-scoring of them.

    A path is new when one of its legs was not there before, or when its sink ran only
    after approval before and now runs unasked. With no baseline every path is new.
    """
    known = (baseline or {}).get("agents") or {}
    count = 0
    parts: list[Family] = []
    for family in report.families:
        old = known.get(family.agent) or {}
        old_ids = {role: set(old.get(role) or []) for role in ("sources", "data", "sinks", "open_sinks")}
        s_old = [i for i in family.sources if i in old_ids["sources"]]
        s_new = [i for i in family.sources if i not in old_ids["sources"]]
        d_old = [i for i in family.data if i in old_ids["data"]]
        d_new = [i for i in family.data if i not in old_ids["data"]]
        k_old = [i for i in family.sinks if i in old_ids["sinks"]]
        k_new = [i for i in family.sinks if i not in old_ids["sinks"]]
        reopened = [i for i in k_old if i in family.open_sinks and i not in old_ids["open_sinks"]]
        # A partition of the new combinations: new source; else new data tool; else new sink;
        # else a sink that stopped asking.
        for sources, data, sinks in ((s_new, family.data, family.sinks), (s_old, d_new, family.sinks),
                                     (s_old, d_old, k_new), (s_old, d_old, reopened)):
            size = len(sources) * len(data) * len(sinks)
            if size:
                count += size
                parts.append(Family(family.agent, family.source_server, family.data_server, family.sink_server,
                                    sources, data, sinks, family.open_sinks, family.unpinned_sinks, size, 0, 0))
    return count, best_paths(parts, report.facts, limit=limit, min_score=min_score)


# -- the fix advisor: cost of a change --------------------------------------------------------------
# A change sets a tool, or every tool of a server, to "ask" or to "deny". Asking keeps the
# tool usable; denying removes it, so it costs three times as much. Both scale with how
# much sessions lean on the tool: the shell and the file tools are in almost every turn,
# and tools that recorded sessions called often count for more.

ASK_COST = 1.0
DENY_COST = 3.0
SERVER_FACTOR = 0.75        # one rule for a whole server is simpler, but it also hits its harmless tools
PATTERN_FACTOR = 0.5        # moving one allowed command pattern to "ask" disturbs less than the whole tool
EXACT_LIMIT = 20            # up to this many candidate changes the search is exhaustive
EXACT_CEILING = 40          # beyond this an exhaustive search is refused, whoever asks
_KIND_USE = {"shell": 6.0, "read": 4.0, "edit": 4.0, "fetch": 2.0, "search": 2.0}


def tool_use(tool: ToolFacts) -> float:
    """How much removing or gating this tool disturbs normal work."""
    return _KIND_USE.get(tool.kind, 1.0) + 0.5 * math.log2(1 + max(0, tool.calls))


@dataclass(frozen=True)
class Change:
    """One permission change, in the terms of the agent's own settings."""

    agent: str
    action: str                 # "ask" | "deny"
    scope: str                  # "tool" | "server" | "pattern"
    target: str                 # the tool name, the server name, or the command pattern
    rule: str                   # the rule to add under ``action`` in the agent's settings
    tool_ids: tuple[str, ...]   # the tools it changes in the graph
    cost: float
    why: str                    # what it is in the paths: "sink (public)", "source", ...

    def to_dict(self) -> dict[str, Any]:
        return {"agent": self.agent, "action": self.action, "scope": self.scope, "target": self.target,
                "rule": self.rule, "tools": len(self.tool_ids), "cost": round(self.cost, 2), "why": self.why}


@dataclass
class Candidate:
    """A set of changes that only make sense together, and the path families it breaks."""

    changes: tuple[Change, ...]
    cost: float
    covers: int                 # bit i set: path family i has no open path left
    label: str
    denies: frozenset[str] = frozenset()    # tools it takes off every leg
    asks: frozenset[str] = frozenset()      # tools it stops from sending unasked


def rule_for(tool: ToolFacts) -> str:
    """The permission rule that names exactly this tool in its agent's syntax."""
    if tool.agent == "cursor" and not tool.builtin:
        return f"Mcp({tool.server}:{tool.tool})"
    return tool.name


def server_rule(tool: ToolFacts) -> str:
    """The permission rule that names every tool of this tool's server."""
    if tool.agent == "cursor":
        return f"Mcp({tool.server}:*)"
    return f"mcp__{tool.server_key}"


def _tool_changes(tool: ToolFacts, action: str, why: str, *, strict: bool = False) -> list[Change]:
    """The change that sets one tool to ``action``.

    A shell that sends data unasked only because of allow patterns (``Bash(curl:*)``) is
    gated by putting the same patterns under "ask": ask outranks allow, and every other
    command keeps working as before. A strict fix wants a rule on the whole tool instead.
    """
    if action == "ask" and tool.open_partial and tool.permission == "default" and not strict:
        cost = PATTERN_FACTOR * ASK_COST * tool_use(tool) / len(tool.open_partial)
        return [Change(tool.agent, "ask", "pattern", pattern, pattern, (tool.id,), cost, why)
                for pattern in tool.open_partial]
    cost = (ASK_COST if action == "ask" else DENY_COST) * tool_use(tool)
    return [Change(tool.agent, action, "tool", tool.name, rule_for(tool), (tool.id,), cost, why)]


# -- the fix advisor: a weighted hitting set -----------------------------------------------------------
# Every live path must lose at least one leg. Denying a tool removes every path through
# it; asking on a sink breaks every path that ends there. The cheapest set of changes that
# hits every path is a minimum-weight hitting set.
#
# Paths are a product of legs, so tools that sit on the same server in the same roles are
# interchangeable: any fix that breaks everything either changes all of them or gains
# nothing from changing some. They are bundled into one candidate, which keeps the search
# small enough to be exhaustive on real configurations without giving up minimality.


@dataclass
class Instance:
    """The hitting-set question for one agent."""

    agent: str
    weights: list[int]              # live paths in each path family (a triple of bundles)
    candidates: list[Candidate]
    tool_changes: int = 0           # single-tool changes the bundled candidates stand for
    sources: frozenset[str] = frozenset()   # the live legs, as tool ids
    data: frozenset[str] = frozenset()
    sinks: frozenset[str] = frozenset()
    explicit: bool = True           # False: too many families to list; ``weights`` and ``covers`` are unset


MAX_FAMILIES = 20_000               # above this the families are reasoned about, not listed


def _role_text(tool: ToolFacts, in_s: bool, in_d: bool, in_k: bool) -> str:
    parts = []
    if in_s:
        parts.append(f"source ({tool.source_scope or 'unknown'} input)")
    if in_d:
        parts.append("private data")
    if in_k:
        parts.append(f"sink ({tool.sink_scope or 'unknown'} reach)")
    return ", ".join(parts)


def build_instance(agent: str, families: Iterable[Family], facts: Mapping[str, ToolFacts], *,
                   strict: bool = False) -> Instance:
    """Turn one agent's path families into candidates and the path families each one breaks.

    ``strict`` also counts paths whose sink only asks because of the permission mode: it
    looks for explicit rules, which a change of mode or one "don't ask again" cannot undo.
    """
    sources: set[str] = set()
    data: set[str] = set()
    sinks: set[str] = set()
    merged: set[int] = set()
    for family in families:
        for target, ids in ((sources, family.sources), (data, family.data),
                            (sinks, family.unpinned_sinks if strict else family.open_sinks)):
            if id(ids) not in merged:       # the lists are shared between families
                merged.add(id(ids))
                target.update(i for i in ids if i in facts)
    if not (sources and data and sinks):
        return Instance(agent, [], [])

    bundles: dict[tuple[str, bool, bool, bool], list[str]] = {}
    for tool_id in sorted(sources | data | sinks):
        key = (facts[tool_id].server_id, tool_id in sources, tool_id in data, tool_id in sinks)
        bundles.setdefault(key, []).append(tool_id)
    keys = sorted(bundles)

    candidates: list[Candidate] = []
    tool_changes = 0
    for key in keys:
        _server_id, in_s, in_d, in_k = key
        tools = [facts[i] for i in bundles[key]]
        ids = frozenset(bundles[key])
        what = f"{len(tools)} tool{'s' if len(tools) != 1 else ''} of {_server_label(tools[0])}"
        if in_s or in_d:
            changes = tuple(c for t in tools for c in _tool_changes(t, "deny", _role_text(t, in_s, in_d, in_k)))
            candidates.append(Candidate(changes, sum(c.cost for c in changes), 0, f"deny {what}", denies=ids))
            tool_changes += len(tools)
        if in_k:
            changes = tuple(c for t in tools
                            for c in _tool_changes(t, "ask", _role_text(t, in_s, in_d, in_k), strict=strict))
            candidates.append(Candidate(changes, sum(c.cost for c in changes), 0, f"ask {what}", asks=ids))
            tool_changes += len(tools)
    for server_id in sorted({key[0] for key in keys}):
        members = sorted((t for t in facts.values() if t.server_id == server_id), key=lambda t: t.id)
        if not members or members[0].builtin:
            continue        # there is no rule that names "every built-in tool"
        ids = frozenset(t.id for t in members)
        use = sum(tool_use(t) for t in members)
        name, rule = members[0].server, server_rule(members[0])
        for action, unit in (("deny", DENY_COST), ("ask", ASK_COST)):
            change = Change(agent, action, "server", name, rule, tuple(sorted(ids)), SERVER_FACTOR * unit * use,
                            f"every tool of the server ({len(ids)})")
            candidates.append(Candidate((change,), change.cost, 0, f"{action} server {name}",
                                        denies=ids if action == "deny" else frozenset(),
                                        asks=ids if action == "ask" else frozenset()))

    instance = Instance(agent, [], candidates, tool_changes, frozenset(sources), frozenset(data), frozenset(sinks))
    s_keys, d_keys, k_keys = ([k for k in keys if k[i]] for i in (1, 2, 3))
    if len(s_keys) * len(d_keys) * len(k_keys) > MAX_FAMILIES:
        instance.explicit = False
        return instance
    # List the families (triples of bundles) and mark, for each candidate, the ones it breaks:
    # those with a leg it denies, and those whose sink it makes ask.
    triples = [(s, d, k) for s in s_keys for d in d_keys for k in k_keys]
    instance.weights = [len(bundles[s]) * len(bundles[d]) * len(bundles[k]) for s, d, k in triples]
    for candidate in candidates:
        gone = {key for key in keys if bundles[key][0] in candidate.denies}
        gated = gone | {key for key in keys if bundles[key][0] in candidate.asks}
        mask = 0
        for index, (s, d, k) in enumerate(triples):
            if s in gone or d in gone or k in gated:
                mask |= 1 << index
        candidate.covers = mask
    return instance


def _greedy_product(instance: Instance) -> list[int]:
    """Greedy for an instance too large to list: paths are counted as a product of what is left.

    Open paths = (sources left) x (data tools left) x (sinks still unasked). Each step takes
    the candidate that removes the most paths per unit of cost; candidates that turn out
    to be unnecessary are dropped at the end.
    """
    candidates = instance.candidates

    def remaining(chosen: Iterable[int]) -> tuple[set[str], set[str], set[str]]:
        sources, data, sinks = set(instance.sources), set(instance.data), set(instance.sinks)
        for i in chosen:
            sources -= candidates[i].denies
            data -= candidates[i].denies
            sinks -= candidates[i].denies | candidates[i].asks
        return sources, data, sinks

    chosen: list[int] = []
    sources, data, sinks = remaining(chosen)
    left = set(range(len(candidates)))
    while sources and data and sinks:
        live = len(sources) * len(data) * len(sinks)
        best: tuple[tuple[float, float, int], int] | None = None
        for i in left:
            c = candidates[i]
            after = (len(sources - c.denies) * len(data - c.denies) * len(sinks - c.denies - c.asks))
            if after < live:
                rank = ((live - after) / c.cost, -c.cost, -i)
                if best is None or rank > best[0]:
                    best = (rank, i)
        if best is None:
            break
        chosen.append(best[1])
        left.discard(best[1])
        sources, data, sinks = remaining(chosen)
    for i in sorted(chosen, key=lambda i: (-candidates[i].cost, i)):
        without = [j for j in chosen if j != i]
        if not all(remaining(without)):
            chosen = without
    return chosen


def solve_instance(instance: Instance, *, method: str = "auto", exact_limit: int = EXACT_LIMIT) -> "Solution":
    """A cheapest set of the instance's candidates that leaves no live path."""
    if instance.explicit:
        return solve(instance.weights, instance.candidates, method=method, exact_limit=exact_limit)
    if method == "exact":
        raise ValueError(f"{len(instance.candidates)} candidate changes are too many for an exhaustive search; "
                         "use the greedy method")
    chosen = _greedy_product(instance)
    sources, data, sinks = set(instance.sources), set(instance.data), set(instance.sinks)
    for i in chosen:
        sources -= instance.candidates[i].denies
        data -= instance.candidates[i].denies
        sinks -= instance.candidates[i].denies | instance.candidates[i].asks
    return Solution(chosen, sum(instance.candidates[i].cost for i in chosen), "greedy",
                    not (sources and data and sinks), len(instance.candidates))


@dataclass
class Solution:
    chosen: list[int]       # indices into the candidates that were given
    cost: float
    method: str             # "exact" | "greedy" | "none"
    complete: bool          # every path family is broken
    considered: int         # candidates left after dropping dominated ones


def _bits(mask: int) -> list[int]:
    out = []
    while mask:
        low = mask & -mask
        out.append(low.bit_length() - 1)
        mask ^= low
    return out


def _undominated(candidates: list[Candidate]) -> list[int]:
    """Indices of candidates no other candidate beats (covers at least as much for no more)."""
    keep = []
    for i, c in enumerate(candidates):
        if not c.covers:
            continue
        beaten = False
        for j, d in enumerate(candidates):
            if i != j and d.covers | c.covers == d.covers and d.cost <= c.cost \
                    and (d.covers != c.covers or d.cost < c.cost or j < i):
                beaten = True
                break
        if not beaten:
            keep.append(i)
    return keep


def _greedy(constraints: list[tuple[int, int]], costs: list[float]) -> list[int]:
    """Most paths broken per unit of cost first, then drop whatever turned out unnecessary."""
    chosen = 0
    order: list[int] = []
    while True:
        gains: dict[int, int] = {}
        for mask, weight in constraints:
            if not mask & chosen:
                for i in _bits(mask):
                    gains[i] = gains.get(i, 0) + weight
        if not gains:
            break
        pick = max(gains, key=lambda i: (gains[i] / costs[i], -costs[i], -i))
        chosen |= 1 << pick
        order.append(pick)
    for i in sorted(order, key=lambda i: (-costs[i], i)):
        without = chosen & ~(1 << i)
        if all(mask & without for mask, _ in constraints):
            chosen = without
    return [i for i in order if chosen >> i & 1]


def _exact(constraints: list[int], costs: list[float], upper: tuple[float, list[int]]) -> tuple[float, list[int]]:
    """Branch and bound over "at least one of these candidates" constraints.

    Branching on the constraint with the fewest remaining options, taking option i only
    after options before it are ruled out, visits every minimal hitting set at most once.
    """
    best_cost, best = upper
    eps = 1e-9

    def descend(chosen: int, banned: int, cost: float, picked: list[int]) -> None:
        nonlocal best_cost, best
        options = 0
        fewest = -1
        for mask in constraints:
            if mask & chosen:
                continue
            usable = mask & ~banned
            if not usable:
                return                      # this path family can no longer be broken
            count = usable.bit_count()
            if fewest < 0 or count < fewest:
                options, fewest = usable, count
                if count == 1:
                    break
        if fewest < 0:
            if cost < best_cost - eps or (cost <= best_cost + eps and len(picked) < len(best)):
                best_cost, best = cost, list(picked)
            return
        ordered = sorted(_bits(options), key=lambda i: (costs[i], i))
        if cost + costs[ordered[0]] > best_cost + eps:
            return                          # even the cheapest way on is worse than what we have
        ruled_out = banned
        for i in ordered:
            if cost + costs[i] <= best_cost + eps:
                picked.append(i)
                descend(chosen | 1 << i, ruled_out, cost + costs[i], picked)
                picked.pop()
            ruled_out |= 1 << i

    descend(0, 0, 0.0, [])
    return best_cost, best


def solve(weights: list[int], candidates: list[Candidate], *, method: str = "auto",
          exact_limit: int = EXACT_LIMIT) -> Solution:
    """A cheapest set of candidates that breaks every path family.

    Exhaustive when at most ``exact_limit`` candidates remain after dropping dominated
    ones (the result is then a minimum), greedy beyond that (a good answer, not a proven
    minimum). ``method`` forces one or the other.
    """
    if method not in ("auto", "exact", "greedy"):
        raise ValueError("method must be auto, exact or greedy")
    families = [i for i, weight in enumerate(weights) if weight > 0]
    if not families:
        return Solution([], 0.0, "none", True, 0)
    kept = _undominated(candidates)
    costs = [candidates[i].cost for i in kept]
    # One constraint per path family: the candidates (positions in ``kept``) that break it.
    by_signature: dict[int, int] = {}
    for family in families:
        signature = 0
        for position, i in enumerate(kept):
            if candidates[i].covers >> family & 1:
                signature |= 1 << position
        by_signature[signature] = by_signature.get(signature, 0) + weights[family]
    complete = 0 not in by_signature
    weighted = [(mask, weight) for mask, weight in sorted(by_signature.items()) if mask]
    greedy = _greedy(weighted, costs)
    greedy_cost = sum(costs[i] for i in greedy)
    if method == "exact" and len(kept) > EXACT_CEILING:
        raise ValueError(f"{len(kept)} candidate changes are too many for an exhaustive search "
                         f"(the ceiling is {EXACT_CEILING}); use the greedy method")
    use_exact = method == "exact" or (method == "auto" and len(kept) <= min(exact_limit, EXACT_CEILING))
    if not use_exact:
        return Solution([kept[i] for i in greedy], greedy_cost, "greedy", complete, len(kept))
    # A constraint that contains another is implied by it; only the minimal ones matter.
    masks = sorted({mask for mask, _ in weighted}, key=lambda m: (m.bit_count(), m))
    minimal = [m for m in masks if not any(o != m and o & m == o for o in masks)]
    cost, chosen = _exact(minimal, costs, (greedy_cost, greedy))
    return Solution([kept[i] for i in sorted(chosen)], cost, "exact", complete, len(kept))


# -- the fix advisor: proposing, rehearsing, applying ----------------------------------------------------


@dataclass
class AgentFix:
    agent: str
    changes: list[Change]
    cost: float
    method: str             # "exact": a proven minimum; "greedy": a good answer; "none": nothing to do
    candidates: int         # candidate changes the search looked at
    tool_changes: int       # single-tool changes those candidates stand for
    complete: bool = True


@dataclass
class FixProposal:
    strict: bool
    agents: list[AgentFix] = field(default_factory=list)
    live_before: int = 0    # paths to break, counted by the path query on the graph as it is
    live_after: int = 0     # the same count with the changes applied in a rehearsal
    total_before: int = 0   # all paths, gated ones included
    total_after: int = 0

    @property
    def changes(self) -> list[Change]:
        return [c for a in self.agents for c in a.changes]

    @property
    def broken(self) -> int:
        return self.live_before - self.live_after

    @property
    def cost(self) -> float:
        return sum(a.cost for a in self.agents)

    @property
    def method(self) -> str:
        methods = {a.method for a in self.agents if a.method != "none"}
        return "greedy" if "greedy" in methods else "exact" if methods else "none"

    def settings(self, agent: str = "claude-code") -> dict[str, Any]:
        """The ``permissions`` block to merge into the agent's settings file."""
        return settings_snippet(c for c in self.changes if c.agent == agent)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict": self.strict, "method": self.method, "cost": round(self.cost, 2),
            "live_before": self.live_before, "live_after": self.live_after, "broken": self.broken,
            "total_before": self.total_before, "total_after": self.total_after,
            "agents": [{"agent": a.agent, "method": a.method, "cost": round(a.cost, 2), "candidates": a.candidates,
                        "tool_changes": a.tool_changes, "complete": a.complete,
                        "changes": [c.to_dict() for c in a.changes],
                        "rules": self.settings(a.agent)["permissions"]}
                       for a in self.agents],
            "settings": self.settings(),     # for Claude Code's settings.json; other agents: see "rules"
        }


def settings_snippet(changes: Iterable[Change]) -> dict[str, Any]:
    """``{"permissions": {"ask": [...], "deny": [...]}}`` for a set of changes."""
    rules: dict[str, list[str]] = {"ask": [], "deny": []}
    for change in changes:
        if change.rule not in rules[change.action]:
            rules[change.action].append(change.rule)
    rules["ask"] = [r for r in rules["ask"] if r not in rules["deny"]]      # deny already covers it
    return {"permissions": {kind: sorted(found) for kind, found in rules.items() if found}}


def live_paths(store: Store, *, agent: str | None = None, strict: bool = False) -> tuple[int, int]:
    """``(paths still to break, all paths)``, both counted by the path query."""
    live = total = 0
    for row in store.run(AGENTS_QUERY):
        if agent and row["id"] != agent:
            continue
        counts = count_paths(store, row["id"])
        live += counts["unpinned"] if strict else counts["open"]
        total += counts["paths"]
    return live, total


def apply_changes(store: Store, changes: Iterable[Change], *, source: str = "") -> None:
    """Write permission changes into the capability map.

    Call it inside ``store.rehearsal()`` to try a change, or inside ``store.transaction()``
    once the change is really in the agent's settings. Deny is written last: it outranks ask.
    """
    asked: list[dict[str, str]] = []
    denied: list[dict[str, str]] = []
    patterns: dict[str, list[str]] = {}
    for change in changes:
        for tool_id in change.tool_ids:
            if change.scope == "pattern":
                patterns.setdefault(tool_id, []).append(change.rule)
            else:
                (denied if change.action == "deny" else asked).append({"id": tool_id, "rule": change.rule})
    if patterns:
        store.write(
            "UNWIND $rows AS r MATCH (t:Tool {id: r.id}) WHERE coalesce(t.gate, 'ask') <> 'deny' "
            "SET t.gate = 'ask', t.gate_reason = 'ask rule ' + r.rules[0], t.open_partial = [], "
            "    t.permission_partial = coalesce(t.permission_partial, []) + [x IN r.rules | 'ask ' + x]",
            {"rows": [{"id": tool_id, "rules": found} for tool_id, found in sorted(patterns.items())]})
    if asked:
        store.write(
            "UNWIND $rows AS r MATCH (t:Tool {id: r.id}) WHERE coalesce(t.permission, 'default') <> 'deny' "
            "SET t.permission = 'ask', t.gate = 'ask', t.gate_data = null, t.open_partial = [], "
            "    t.permission_rule = r.rule, t.permission_source = $source, t.gate_reason = 'ask rule ' + r.rule",
            {"rows": asked, "source": source})
    if denied:
        store.write(
            "UNWIND $rows AS r MATCH (t:Tool {id: r.id}) "
            "SET t.permission = 'deny', t.gate = 'deny', t.gate_data = null, t.open_partial = [], "
            "    t.permission_rule = r.rule, t.permission_source = $source, t.gate_reason = 'deny rule ' + r.rule",
            {"rows": denied, "source": source})


def rehearse(store: Store, changes: Iterable[Change], *, agent: str | None = None,
             strict: bool = False) -> dict[str, int]:
    """Apply changes, re-run the path query, and throw the changes away again."""
    changes = list(changes)
    live_before, total_before = live_paths(store, agent=agent, strict=strict)
    with store.rehearsal():
        apply_changes(store, changes)
        live_after, total_after = live_paths(store, agent=agent, strict=strict)
    return {"live_before": live_before, "live_after": live_after, "broken": live_before - live_after,
            "total_before": total_before, "total_after": total_after}


def propose_fix(store: Store, *, agent: str | None = None, strict: bool = False, method: str = "auto",
                exact_limit: int = EXACT_LIMIT) -> FixProposal:
    """The cheapest permission changes that leave no path open, checked against the graph.

    The counts in the result never come from the solver's own bookkeeping: the changes
    are applied inside a rehearsal and the toxic-path query is run again.
    """
    proposal = FixProposal(strict=strict)
    for row in store.run(AGENTS_QUERY):
        if agent and row["id"] != agent:
            continue
        facts = tool_facts(store, row["id"])
        # The advisor reasons about legs, not about server triples: the merged form is all it needs.
        instance = build_instance(row["id"], path_families(store, row["id"], merged=True), facts, strict=strict)
        solution = solve_instance(instance, method=method, exact_limit=exact_limit)
        changes = [c for i in solution.chosen for c in instance.candidates[i].changes]
        changes.sort(key=lambda c: (c.action, c.scope != "server", c.target, c.rule))
        proposal.agents.append(AgentFix(row["id"], changes, solution.cost, solution.method, solution.considered,
                                        instance.tool_changes, solution.complete))
    counts = rehearse(store, proposal.changes, agent=agent, strict=strict)
    proposal.live_before, proposal.live_after = counts["live_before"], counts["live_after"]
    proposal.total_before, proposal.total_after = counts["total_before"], counts["total_after"]
    return proposal


class FixError(RuntimeError):
    """The settings file cannot be changed safely."""


@dataclass
class ApplyResult:
    path: str
    added: list[str]            # "ask RULE" / "deny RULE" entries that were not there before
    backup: str | None          # set when this call created the one-time backup
    changed: bool


def merge_settings(settings: dict[str, Any], snippet: Mapping[str, Any]) -> list[str]:
    """Add the snippet's rules to a settings object in place. Returns what was added.

    Existing rules, their order and every other key stay as they are, and a rule that is
    already present is not added again, so merging twice changes nothing.
    """
    wanted = snippet.get("permissions") or {}
    if not any(wanted.get(kind) for kind in ("ask", "deny")):
        return []
    permissions = settings.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise FixError('"permissions" is not an object')
    added: list[str] = []
    for kind in ("ask", "deny"):
        rules = wanted.get(kind) or []
        if not rules:
            continue
        current = permissions.setdefault(kind, [])
        if not isinstance(current, list):
            raise FixError(f'"permissions.{kind}" is not a list')
        for rule in rules:
            if rule not in current:
                current.append(rule)
                added.append(f"{kind} {rule}")
    return added


def _not_json(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _backup_once(target: Path, mode: int) -> str | None:
    """Keep the file as it is now beside it as ``<name>.bak``, unless something already has that name.

    The backup is created, never opened: a link somebody planted under that name (in a
    cloned repository, say) is left alone, and nothing is written to where it points.
    """
    backup = str(target) + ".bak"
    if os.path.lexists(backup):
        return None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(backup, flags, mode)
    except FileExistsError:
        return None
    with os.fdopen(fd, "wb") as fh:
        fh.write(target.read_bytes())
    os.chmod(backup, mode)
    return backup


def apply_settings(path: str | os.PathLike[str], snippet: Mapping[str, Any]) -> ApplyResult:
    """Merge permission rules into a settings file.

    The file is rewritten only when something is added, the first rewrite leaves the
    original beside it as ``<name>.bak``, and a file that is not a JSON object, or that
    could not be written back as valid JSON, is refused rather than overwritten.
    """
    import stat

    target = Path(os.path.realpath(os.fspath(path)))
    existed = target.exists()
    settings: Any = {}
    if existed:
        try:
            text = target.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            reason = getattr(exc, "strerror", None) or type(exc).__name__
            raise FixError(f"{target} cannot be read ({reason}); it was left untouched") from exc
        if text.strip():
            try:
                settings = json.loads(text, parse_constant=_not_json)     # NaN and Infinity are not JSON
            except (ValueError, RecursionError) as exc:
                raise FixError(f"{target} is not valid JSON; it was left untouched") from exc
        if not isinstance(settings, dict):
            raise FixError(f"{target} does not hold a JSON object; it was left untouched")
    try:
        added = merge_settings(settings, snippet)
    except FixError as exc:
        raise FixError(f"{target}: {exc}; it was left untouched") from exc
    if not added:
        return ApplyResult(str(target), [], None, False)
    try:
        rewritten = json.dumps(settings, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    except (ValueError, RecursionError) as exc:    # 1e999 reads as infinity, which no JSON parser takes back
        raise FixError(f"{target} holds a value that cannot be written back as JSON; it was left untouched") from exc
    try:
        mode = stat.S_IMODE(os.stat(target).st_mode) if existed else None
        backup = _backup_once(target, mode) if mode is not None else None
        _write_atomically(target, rewritten, mode)
    except OSError as exc:
        raise FixError(f"{target} could not be written ({exc.strerror or type(exc).__name__})") from exc
    return ApplyResult(str(target), added, backup, True)


def refuse_link_out_of_project(target: Path) -> None:
    """Refuse to follow ``<project>/.claude/settings.json`` when it is a link that leads elsewhere.

    A cloned repository can ship that path as a symbolic link to any file its reader owns.
    A file named with ``--settings`` is the caller's own choice and is not checked.
    """
    real = os.path.realpath(target)
    expected = os.path.join(os.path.realpath(target.parent.parent), target.parent.name, target.name)
    if real != expected:
        raise FixError(f"{target} is a symbolic link to {real}; it was left untouched. "
                       f"To change that file, name it: --settings {real}")


# -- commands ----------------------------------------------------------------------------------------------

_PART_LABELS = {"exposure": "exposure", "data": "data", "sink": "sink", "unattended": "unattended",
                "confidence": "confidence", "single_server": "single server"}


MAX_SPELLED_OUT = 10_000        # paths one command spells out; each one is a sentence and six numbers
JSON_GROUPS = 1000              # server combinations in the JSON output unless --groups says otherwise


def _engine_message(exc: BaseException) -> str:
    lines = str(exc).strip().splitlines()
    return (lines[0] if lines else type(exc).__name__)[:200]


def severity(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"


def add_paths_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent", metavar="KIND", help="only this agent (for example claude-code)")
    parser.add_argument("--limit", type=int, default=5, metavar="N", help="spell out the N worst paths (default 5)")
    parser.add_argument("--groups", type=int, default=None, metavar="N",
                        help="show the N worst server combinations (default: 12 as text, 1000 as JSON; "
                             "group_count in the JSON says how many there are)")
    parser.add_argument("--min-score", type=int, default=0, metavar="N", help="list only paths scoring at least N")
    parser.add_argument("--status", choices=("open", "gated"),
                        help="list only paths whose sink runs unasked (open) or asks first (gated)")
    parser.add_argument("--max-score", type=int, metavar="N",
                        help="exit with status 3 when a path scores N or more (for CI)")
    parser.add_argument("--fail-on-new", action="store_true",
                        help="exit with status 3 when a path exists that the baseline does not cover")
    parser.add_argument("--baseline", metavar="FILE",
                        help="the reviewed paths (default: paths-baseline.json in the .tainttrail directory)")
    parser.add_argument("--accept", action="store_true", help="record the current paths as reviewed and exit")
    parser.add_argument("--show-query", action="store_true", help="print the Cypher query that finds the paths")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")


def _tolerant_output() -> None:
    """Never let a character the terminal cannot encode abort a report."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def _open_or_explain(cfg: Config, command: str, *, read_only: bool) -> Store | None:
    """Open the project's graph, or say what to do first. Never creates a store."""
    if not Path(cfg.db_path).exists():
        print(f"tainttrail {command}: there is no graph yet at {cfg.db_path}. Run `tainttrail scan` first.",
              file=sys.stderr)
        return None
    try:
        return open_store(cfg, read_only=read_only).open()
    except StoreMissing:
        print(f"tainttrail {command}: there is no graph yet. Run `tainttrail scan` first.", file=sys.stderr)
    except StoreError as exc:
        print(f"tainttrail {command}: {exc}", file=sys.stderr)
    return None


def cmd_paths(args: argparse.Namespace, cfg: Config) -> int:
    from .report import paint, use_color

    _tolerant_output()
    limit, groups = getattr(args, "limit", 5), getattr(args, "groups", None)
    if limit < 0 or (groups is not None and groups < 0):
        print("tainttrail paths: --limit and --groups cannot be negative", file=sys.stderr)
        return 2
    if limit > MAX_SPELLED_OUT:
        print(f"tainttrail paths: --limit cannot be more than {MAX_SPELLED_OUT}", file=sys.stderr)
        return 2
    baseline_path = getattr(args, "baseline", None) or str(cfg.home / "paths-baseline.json")
    store = _open_or_explain(cfg, "paths", read_only=True)
    if store is None:
        return 1
    try:
        with store:
            report = find_paths(store, agent=getattr(args, "agent", None), limit=limit,
                                min_score=getattr(args, "min_score", 0), status=getattr(args, "status", None))
    except StoreError as exc:
        print(f"tainttrail paths: {exc}", file=sys.stderr)
        return 1
    except relate.Error as exc:
        print(f"tainttrail paths: the graph engine refused the query ({_engine_message(exc)})", file=sys.stderr)
        return 1

    if getattr(args, "accept", False):
        try:
            # Accepting one agent's paths must not forget what was accepted for the others.
            keep = load_baseline(baseline_path) if getattr(args, "agent", None) else None
            save_baseline(baseline_path, report, keep=keep)
        except ValueError as exc:
            print(f"tainttrail paths: {exc}. Remove it, or name another file with --baseline.", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"tainttrail paths: {baseline_path} could not be written ({exc.strerror})", file=sys.stderr)
            return 1
        print(f"Recorded {report.total:,} paths as reviewed in {baseline_path}.")
        return 0

    threshold = getattr(args, "max_score", None)
    if (threshold is not None or getattr(args, "fail_on_new", False)) and not report.agents:
        scope = f"agent {args.agent}" if getattr(args, "agent", None) else "any agent"
        print(f"tainttrail paths: no scan of {scope} is in the graph, so there is nothing to judge. "
              "Run `tainttrail scan` first.", file=sys.stderr)
        return 1
    verdict: dict[str, Any] = {"failed": False, "reason": ""}
    fresh: tuple[int, list[ToxicPath]] | None = None
    if getattr(args, "fail_on_new", False):
        try:
            baseline = load_baseline(baseline_path)
        except ValueError as exc:
            print(f"tainttrail paths: {exc}", file=sys.stderr)
            return 1
        fresh = new_paths(report, baseline, limit=max(limit, 1), min_score=threshold or 0)
        if fresh[1]:
            floor = f" scoring {threshold} or more" if threshold is not None else ""
            origin = "" if baseline is not None else f" (there is no baseline yet at {baseline_path})"
            verdict = {"failed": True, "reason": f"{fresh[0]:,} paths are not in the baseline{origin}; "
                                                 f"the worst{floor} scores {fresh[1][0].score}"}
    elif threshold is not None and report.total and report.top_score >= threshold:
        verdict = {"failed": True, "reason": f"a path scores {report.top_score}, at or above the limit of {threshold}"}

    if getattr(args, "json", False):
        out = report.to_dict(JSON_GROUPS if groups is None else groups)
        out["gate"] = verdict
        if fresh is not None:
            out["new"] = {"count": fresh[0], "paths": [p.to_dict() for p in fresh[1]]}
        print(json.dumps(out, indent=1, sort_keys=True))
    else:
        print(render_paths(report, color=use_color(), paint=paint, groups=12 if groups is None else groups,
                           filtered=bool(getattr(args, "status", None) or getattr(args, "min_score", 0)),
                           fresh=fresh, show_query=getattr(args, "show_query", False)), end="")
        if verdict["failed"]:
            print(paint(f"FAILED: {verdict['reason']}.", "bright_red", "bold", color=use_color()))
            if getattr(args, "fail_on_new", False):
                print("Review them, then record them with `tainttrail paths --accept`.")
    return 3 if verdict["failed"] else 0


def _path_lines(path: ToxicPath, paint: Any, color: bool) -> list[str]:
    style = ("bright_red", "bold") if path.status == "open" else ("bright_yellow",)
    tag = "open" if path.status == "open" else "gated by approval"
    parts = " + ".join(f"{_PART_LABELS[name]} {value:g}" for name, value in path.components.items())
    lines = [f"  {path.score:>3}  " + paint(f"{path.source} -> {path.data} -> {path.sink}", "bold", color=color)
             + "   " + paint(tag, *style, color=color)]
    lines.append(f"       {path.sentence}")
    lines.append(paint(f"       {path.score} = {parts}", "dim", color=color))
    return lines


def render_paths(report: PathReport, *, color: bool = False, paint: Any = None, groups: int = 12,
                 filtered: bool = False, fresh: tuple[int, list[ToxicPath]] | None = None,
                 show_query: bool = False) -> str:
    paint = paint or (lambda text, *styles, color=True: text)
    lines = [paint("TaintTrail paths", "bold", color=color),
             paint("  untrusted source -> private data -> a way out, on one agent", "dim", color=color), ""]
    if not report.agents:
        lines.append("No agent in the graph has servers. Run `tainttrail scan` first.")
    for agent in report.agents:
        mode = f"  (permission mode: {agent['permission_mode']})" if agent["permission_mode"] else ""
        lines.append(f"  {agent['name']}: {agent['paths']:,} paths, "
                     + paint(f"{agent['open']:,} open", *(("bright_red", "bold") if agent["open"] else ()), color=color)
                     + f" (the sink runs unasked), {agent['gated']:,} gated by approval{mode}")
    if report.groups:
        lines += ["", paint(f"  {'score':>5} {'paths':>9} {'open':>9}  source server -> data server -> sink server",
                            "dim", color=color)]
        for group in report.groups[:groups]:
            score = group.top.score if group.top else 0
            style = {"critical": ("bright_red", "bold"), "high": ("red",), "medium": ("yellow",)}.get(severity(score), ())
            note = ("   single server: all three legs" if group.single_server else
                    "   built-in tools only" if group.top and group.top.builtin_only else "")
            prefix = f"{group.agent}: " if len(report.agents) > 1 else ""
            lines.append("  " + paint(f"{score:>5}", *style, color=color) + f" {group.paths:>9,} {group.open:>9,}  "
                         f"{prefix}{group.source_server} -> {group.data_server} -> {group.sink_server}"
                         + paint(note, "magenta", color=color))
        if len(report.groups) > groups:
            lines.append(paint(f"  ... and {len(report.groups) - groups} more server combinations (--groups N)",
                               "dim", color=color))
        if report.merged:
            lines.append(paint(f"  {report.combinations:,} server combinations carry a path: too many to list one "
                               "by one, so they are shown per source server", "dim", color=color))
        shown = report.paths if filtered else [g.top for g in report.groups if g.top][: len(report.paths)]
        if shown:
            title = "Paths matching the filter" if filtered else "The worst path of each of those combinations"
            lines += ["", paint(title, "bold", color=color)]
            for path in shown:
                lines += _path_lines(path, paint, color)
    elif report.agents:
        lines += ["", "No toxic path: no agent has an untrusted source, private data and a way out at once."]
    if fresh is not None:
        lines += ["", paint(f"Not in the baseline: {fresh[0]:,} paths", "bold", color=color)]
        for path in fresh[1]:
            lines += _path_lines(path, paint, color)
    if show_query:
        lines += ["", paint("The Cypher query (parameters: $agent, and $deny / $ask lists for what-if questions)",
                            "bold", color=color)]
        lines += ["  " + line for line in PATH_QUERY.strip().splitlines()]
    if report.open:
        lines += ["", "`tainttrail fix` proposes the smallest permission change that leaves no path open."]
    return "\n".join(lines) + "\n"


def add_fix_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent", metavar="KIND", help="only this agent (for example claude-code)")
    parser.add_argument("--strict", action="store_true",
                        help="also pin sinks that only ask because of the permission mode: require an explicit rule")
    parser.add_argument("--method", choices=("auto", "exact", "greedy"), default="auto",
                        help="exact search, greedy, or exact up to --exact-limit candidates (default)")
    parser.add_argument("--exact-limit", type=int, default=EXACT_LIMIT, metavar="N",
                        help=f"search exhaustively up to N candidate changes (default {EXACT_LIMIT})")
    parser.add_argument("--apply", action="store_true",
                        help="merge the Claude Code rules into the settings file (needs --yes)")
    parser.add_argument("--yes", action="store_true", help="confirm --apply")
    parser.add_argument("--settings", metavar="FILE",
                        help="settings file for --apply (default: .claude/settings.json of the scanned project)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")


def _settings_target(store: Store, cfg: Config, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    project = store.scalar("MATCH (a:Agent {id: 'claude-code'}) RETURN a.project")
    return Path(project or cfg.root) / ".claude" / "settings.json"


def cmd_fix(args: argparse.Namespace, cfg: Config) -> int:
    from .report import paint, use_color

    _tolerant_output()
    apply, confirmed = getattr(args, "apply", False), getattr(args, "yes", False)
    exact_limit = getattr(args, "exact_limit", EXACT_LIMIT)
    if exact_limit < 0 or exact_limit > 28:
        print("tainttrail fix: --exact-limit must be between 0 and 28", file=sys.stderr)
        return 2
    store = _open_or_explain(cfg, "fix", read_only=False)   # a rehearsal writes, then rolls back
    if store is None:
        return 1
    applied: ApplyResult | None = None
    try:
        with store:
            proposal = propose_fix(store, agent=getattr(args, "agent", None), strict=getattr(args, "strict", False),
                                   method=getattr(args, "method", "auto"), exact_limit=exact_limit)
            target = _settings_target(store, cfg, getattr(args, "settings", None))
            snippet = proposal.settings("claude-code")
            if apply and not confirmed:
                print(f"tainttrail fix: --apply would change {target}. Add --yes to confirm.", file=sys.stderr)
                return 2
            if apply and snippet["permissions"]:
                if not getattr(args, "settings", None):
                    refuse_link_out_of_project(target)
                applied = apply_settings(target, snippet)
                with store.transaction():   # the settings now say so; make the map agree
                    apply_changes(store, [c for c in proposal.changes if c.agent == "claude-code"],
                                  source=applied.path)
                proposal.live_after, proposal.total_after = live_paths(
                    store, agent=getattr(args, "agent", None), strict=proposal.strict)
    except ValueError as exc:       # an exhaustive search was asked for on too large an instance
        print(f"tainttrail fix: {exc}", file=sys.stderr)
        return 2
    except FixError as exc:
        print(f"tainttrail fix: {exc}", file=sys.stderr)
        return 1
    except StoreError as exc:
        print(f"tainttrail fix: {exc}", file=sys.stderr)
        return 1
    except relate.Error as exc:
        print(f"tainttrail fix: the graph engine refused the query ({_engine_message(exc)})", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        out = proposal.to_dict()
        out["settings_file"] = str(target)
        out["applied"] = None if applied is None else {"path": applied.path, "added": applied.added,
                                                       "backup": applied.backup, "changed": applied.changed}
        print(json.dumps(out, indent=1, sort_keys=True))
    else:
        print(render_fix(proposal, target=str(target), applied=applied, apply_requested=apply,
                         color=use_color(), paint=paint), end="")
    return 0


def render_fix(proposal: FixProposal, *, target: str, applied: ApplyResult | None = None,
               apply_requested: bool = False, color: bool = False, paint: Any = None) -> str:
    paint = paint or (lambda text, *styles, color=True: text)
    kind = "paths whose sink no explicit rule holds" if proposal.strict else "open paths (the sink runs unasked)"
    lines = [paint("TaintTrail fix", "bold", color=color), ""]
    if not proposal.live_before:
        lines.append(f"Nothing to fix: there are no {kind}.")
        if proposal.total_before and not proposal.strict:
            lines.append(f"{proposal.total_before:,} paths exist but every one waits for approval at the sink. "
                         "`tainttrail fix --strict` proposes explicit rules, which a change of permission mode "
                         "cannot undo.")
        return "\n".join(lines) + "\n"
    lines.append(f"{proposal.live_before:,} {kind}.")
    for fix in proposal.agents:
        if not fix.changes:
            continue
        how = (f"exhaustive search over {fix.candidates} candidate changes (they stand for {fix.tool_changes} "
               "single-tool changes): no cheaper set exists" if fix.method == "exact" else
               f"greedy choice among {fix.candidates} candidate changes: a good set, not a proven minimum")
        lines += ["", paint(f"{fix.agent}: {len(fix.changes)} changes, cost {fix.cost:.2f}", "bold", color=color),
                  paint(f"  {how}", "dim", color=color)]
        for change in fix.changes:
            verb = paint(f"{change.action:<5}", *(("bright_yellow",) if change.action == "ask" else ("bright_red",)),
                         color=color)
            lines.append(f"  {verb} {change.rule:<52} {change.why}   cost {change.cost:.2f}")
        if not fix.complete:
            lines.append(paint("  Some paths cannot be broken by any change this tool can express.", "bright_red",
                               color=color))
    lines += ["", f"Checked on a rehearsal of the graph: breaks {proposal.broken:,} of {proposal.live_before:,} paths "
                  f"(the path query found {proposal.live_before:,} before the change and {proposal.live_after:,} after)."]
    if proposal.live_after:
        lines.append(paint(f"{proposal.live_after:,} paths remain.", "bright_red", color=color))
    snippet = proposal.settings("claude-code")
    if snippet["permissions"]:
        lines += ["", paint(f"Rules for {target}", "bold", color=color), json.dumps(snippet, indent=2)]
        if snippet["permissions"].get("ask"):
            lines.append(paint("An ask rule prompts in every permission mode; in headless runs (claude -p) it "
                               "refuses the call.", "dim", color=color))
        if any(c.scope == "pattern" and c.agent == "claude-code" for c in proposal.changes):
            lines.append(paint("Asking for an allowed command pattern makes every command it covers prompt, and an "
                               "ask rule outranks any narrower allow rule. To keep the harmless commands unasked, "
                               "narrow the allow rule itself instead (for example to `git status:*`): that edit is yours "
                               "to make.", "dim", color=color))
    for fix in proposal.agents:
        if fix.agent == "claude-code" or not fix.changes:
            continue
        lines += ["", paint(f"{fix.agent}: TaintTrail does not edit this agent's settings. Make these changes there:",
                            "bold", color=color)]
        lines += [f"  {'require approval for' if c.action == 'ask' else 'deny'} {c.rule}" for c in fix.changes]
        lines.append(paint("  Where the agent has no rule that asks, remove the allow rule that covers the tool, "
                           "or deny it.", "dim", color=color))
    lines.append("")
    if applied is not None:
        if applied.changed:
            lines.append(f"Applied: {len(applied.added)} rules added to {applied.path}."
                         + (f" The previous file is kept as {applied.backup}." if applied.backup else ""))
        else:
            lines.append(f"Nothing to apply: {applied.path} already has these rules.")
    elif apply_requested:
        lines.append("Nothing to apply: no change for Claude Code was proposed.")
    elif snippet["permissions"]:
        lines.append("Apply it with `tainttrail fix --apply --yes`.")
    return "\n".join(lines) + "\n"
