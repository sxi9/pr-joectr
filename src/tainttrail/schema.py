"""The graph model: labels, relationship types, id conventions and the DDL that backs them.

Two layers share one graph.

Capability map (static, written by ``tainttrail scan``)::

    (:Agent)-[:CONNECTS]->(:Server)-[:PROVIDES]->(:Tool)-[:HAS_CAPABILITY]->(:Capability)
    (:Server)-[:HOLDS]->(:Credential)

Session provenance (dynamic, written by the guard on every hook event)::

    (:Session)-[:BY]->(:Agent)
    (:Session)-[:RAN]->(:ToolCall)-[:NEXT]->(:ToolCall)
    (:ToolCall)-[:INVOKES]->(:Tool)
    (:Session)-[:RECEIVED]->(:Content)            user prompts, inherited memory
    (:ToolCall)-[:RETURNED]->(:Content)           tool results
    (:Content)-[:FROM]->(:Entity)                 where the content came from
    (:Content)-[:MENTIONS]->(:Entity)             hosts, URLs, files, e-mail addresses named in it
    (:Content)-[:HAS_CHUNK]->(:Chunk)             keyed fingerprints of its text
    (:ToolCall)-[:READS|WRITES|FETCHES|SENDS_TO|UPLOADS|EXECUTES|REFERENCES]->(:Entity)
    (:ToolCall)-[:CARRIES]->(:Chunk)              the arguments contain this fingerprint
    (:Entity)-[:TAINTED_BY]->(:Content)           a file written under the influence of that content
    (:Entity)-[:DERIVED_FROM]->(:Entity)          a file produced from another file by a shell command
    (:Entity)-[:ON_HOST]->(:Entity)               url -> host
    (:Finding)-[:FLAGS]->(:ToolCall|:Content)
    (:Finding)-[:EVIDENCE {ord}]->(node)          the nodes of the attack path, in order

An attack is a path through this graph, for example::

    (:Content {untrusted})-[:MENTIONS]->(:Entity host)<-[:SENDS_TO]-(:ToolCall)-[:CARRIES]->(:Chunk)<-[:HAS_CHUNK]-(:Content {sensitive})
"""

from __future__ import annotations

SCHEMA_VERSION = 1

# -- node labels ---------------------------------------------------------------
META = "Meta"
AGENT = "Agent"
SERVER = "Server"
TOOL = "Tool"
CAPABILITY = "Capability"
CREDENTIAL = "Credential"
SESSION = "Session"
TOOL_CALL = "ToolCall"
CONTENT = "Content"
ENTITY = "Entity"
CHUNK = "Chunk"
FINDING = "Finding"

NODE_LABELS = (
    META, AGENT, SERVER, TOOL, CAPABILITY, CREDENTIAL,
    SESSION, TOOL_CALL, CONTENT, ENTITY, CHUNK, FINDING,
)

# -- relationship types ----------------------------------------------------------
CONNECTS = "CONNECTS"
PROVIDES = "PROVIDES"
HAS_CAPABILITY = "HAS_CAPABILITY"
HOLDS = "HOLDS"
BY = "BY"
RAN = "RAN"
NEXT = "NEXT"
INVOKES = "INVOKES"
RECEIVED = "RECEIVED"
RETURNED = "RETURNED"
FROM = "FROM"
MENTIONS = "MENTIONS"
HAS_CHUNK = "HAS_CHUNK"
READS = "READS"
WRITES = "WRITES"
FETCHES = "FETCHES"
SENDS_TO = "SENDS_TO"
UPLOADS = "UPLOADS"
EXECUTES = "EXECUTES"
REFERENCES = "REFERENCES"
CARRIES = "CARRIES"
TAINTED_BY = "TAINTED_BY"
DERIVED_FROM = "DERIVED_FROM"
ON_HOST = "ON_HOST"
FLAGS = "FLAGS"
EVIDENCE = "EVIDENCE"

# What a tool call can do to an entity. The analyzers may only emit these.
ACTION_RELS = (READS, WRITES, FETCHES, SENDS_TO, UPLOADS, EXECUTES, REFERENCES)

# Edges a causal chain may travel along, in either direction, when the guard explains
# how untrusted content is connected to a tool call.
PROVENANCE_RELS = (
    RETURNED, RECEIVED, FROM, MENTIONS, HAS_CHUNK, CARRIES, TAINTED_BY, DERIVED_FROM, ON_HOST,
    READS, WRITES, FETCHES, SENDS_TO, UPLOADS, EXECUTES, REFERENCES,
)

# -- capabilities ------------------------------------------------------------------
CAP_UNTRUSTED_INPUT = "untrusted_input"   # results can contain text written by third parties
CAP_PRIVATE_DATA = "private_data"         # results can contain non-public data
CAP_EXTERNAL_SINK = "external_sink"       # calls can send data where third parties can read it
CAP_LOCAL_WRITE = "local_write"           # calls change local files or state
CAP_CODE_EXEC = "code_exec"               # calls run code or commands
CAPABILITIES = (CAP_UNTRUSTED_INPUT, CAP_PRIVATE_DATA, CAP_EXTERNAL_SINK, CAP_LOCAL_WRITE, CAP_CODE_EXEC)

# -- entity kinds -------------------------------------------------------------------
# An entity id is "<kind>:<value>":
#   host:attacker.example            lower-case hostname or IP, no port
#   url:https://host/path            lower-case scheme and host, no query, no fragment
#   file:/abs/posix/path
#   email:someone@example.com
#   repo:github.com/owner/name       lower-case, no ".git"
#   env:AWS_SECRET_ACCESS_KEY
#   mcp:<server>/<object key>        a remote object reached through an MCP server
ENTITY_KINDS = ("host", "url", "file", "email", "repo", "env", "mcp")

SEVERITIES = ("info", "low", "medium", "high", "critical")

_UNIQUE_ID_LABELS = (AGENT, SERVER, TOOL, CREDENTIAL, SESSION, TOOL_CALL, CONTENT, ENTITY, CHUNK, FINDING)

DDL: tuple[str, ...] = (
    f"CREATE CONSTRAINT meta_key IF NOT EXISTS FOR (n:{META}) REQUIRE n.key IS UNIQUE",
    f"CREATE CONSTRAINT capability_name IF NOT EXISTS FOR (n:{CAPABILITY}) REQUIRE n.name IS UNIQUE",
    *(
        f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE"
        for label in _UNIQUE_ID_LABELS
    ),
    f"CREATE INDEX toolcall_session IF NOT EXISTS FOR (n:{TOOL_CALL}) ON (n.session_id)",
    f"CREATE INDEX content_session IF NOT EXISTS FOR (n:{CONTENT}) ON (n.session_id)",
    f"CREATE INDEX finding_session IF NOT EXISTS FOR (n:{FINDING}) ON (n.session_id)",
    f"CREATE INDEX tool_name IF NOT EXISTS FOR (n:{TOOL}) ON (n.name)",
    f"CREATE INDEX entity_kind IF NOT EXISTS FOR (n:{ENTITY}) ON (n.kind)",
)


def ensure_schema(conn) -> bool:
    """Create constraints and indexes once per store. Returns True when it did work."""
    row = conn.execute(f"MATCH (m:{META} {{key: 'schema'}}) RETURN m.version AS v").fetchone()
    if row is not None and row["v"] == SCHEMA_VERSION:
        return False
    for statement in DDL:
        conn.execute(statement)
    conn.execute(
        f"MERGE (m:{META} {{key: 'schema'}}) SET m.version = $v",
        {"v": SCHEMA_VERSION},
    )
    conn.execute(
        f"UNWIND $names AS name MERGE (:{CAPABILITY} {{name: name}})",
        {"names": list(CAPABILITIES)},
    )
    return True


def rel_union(rels: tuple[str, ...] = PROVENANCE_RELS) -> str:
    """``A|B|C`` for use inside a relationship pattern."""
    return "|".join(rels)
