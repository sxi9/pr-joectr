"""Plain data types shared by every module. Nothing here touches the graph."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# -- things in the world ------------------------------------------------------------


@dataclass(frozen=True)
class EntityRef:
    """A named thing a tool call can touch or a piece of content can mention."""

    kind: str   # one of schema.ENTITY_KINDS
    value: str  # already normalised, see schema.py for the conventions

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.value}"

    @property
    def name(self) -> str:
        """Short display form."""
        if self.kind == "file":
            return self.value.rsplit("/", 1)[-1] or self.value
        return self.value


@dataclass(frozen=True)
class ChunkRef:
    """A keyed fingerprint of a piece of text. The text itself is never kept."""

    id: str         # hex HMAC, truncated
    kind: str       # "secret" | "token" | "line"
    hint: str = ""  # which pattern matched, e.g. "aws_access_key_id"; never the value
    length: int = 0


@dataclass
class Action:
    """One effect of a tool call on an entity."""

    rel: str            # one of schema.ACTION_RELS
    entity: EntityRef
    props: dict[str, Any] = field(default_factory=dict)


# -- what a tool can do ---------------------------------------------------------------

CAPABILITY_NAMES = ("untrusted_input", "private_data", "external_sink", "local_write", "code_exec")


@dataclass
class ToolLabels:
    """Security-relevant capabilities of a tool, and where the labels came from."""

    untrusted_input: bool = False
    private_data: bool = False
    external_sink: bool = False
    local_write: bool = False
    code_exec: bool = False
    source: str = "default"     # "builtin" | "catalog" | "heuristic" | "llm" | "user" | "default"
    confidence: float = 0.0
    sink_scope: str | None = None  # "public" | "org" | "private" | None
    notes: str = ""

    def capabilities(self) -> list[str]:
        return [n for n in CAPABILITY_NAMES if getattr(self, n)]

    def to_props(self) -> dict[str, Any]:
        """The properties a ``Tool`` node carries for these labels."""
        props: dict[str, Any] = {n: bool(getattr(self, n)) for n in CAPABILITY_NAMES}
        props.update(
            label_source=self.source,
            label_confidence=float(self.confidence),
            sink_scope=self.sink_scope or "",
            notes=self.notes,
        )
        return props

    @classmethod
    def from_props(cls, props: dict[str, Any]) -> "ToolLabels":
        return cls(
            **{n: bool(props.get(n)) for n in CAPABILITY_NAMES},
            source=str(props.get("label_source") or "default"),
            confidence=float(props.get("label_confidence") or 0.0),
            sink_scope=(props.get("sink_scope") or None),
            notes=str(props.get("notes") or ""),
        )


# -- what one tool call does -------------------------------------------------------------


@dataclass
class CallAnalysis:
    """Everything the guard learns from a tool call *before* it runs."""

    tool: str
    summary: str = ""                       # one line for humans, secrets redacted
    actions: list[Action] = field(default_factory=list)
    # Canonical text of all arguments. Used for fingerprinting and then dropped; it is
    # never written to the graph.
    arg_text: str = ""
    is_sink: bool = False                   # can this call move data off the machine?
    sink_kind: str = ""                     # "http" | "shell-net" | "git" | "dns" | "email" | "mcp" | "search"
    destinations: list[EntityRef] = field(default_factory=list)
    executes_download: bool = False         # runs code it fetches in the same command
    encodes: bool = False                   # applies base64/xxd/gzip/openssl before sending
    env_dump: bool = False                  # prints the process environment
    labels: ToolLabels = field(default_factory=ToolLabels)
    extra: dict[str, Any] = field(default_factory=dict)

    def entities(self, *rels: str) -> list[EntityRef]:
        return [a.entity for a in self.actions if not rels or a.rel in rels]


@dataclass
class ContentAnalysis:
    """Everything the guard learns from text that entered the agent's context."""

    origin: str = "tool"                    # "tool" | "user" | "memory"
    text_bytes: int = 0
    untrusted: bool = False                 # could a third party have written it?
    sensitive: bool = False                 # does it hold private data?
    reasons: list[str] = field(default_factory=list)   # why, e.g. "source:web", "secret:github_token"
    injection_score: float = 0.0            # 0..1, how much it reads like instructions to an agent
    injection_markers: list[str] = field(default_factory=list)
    excerpt: str = ""                       # short and redacted; empty for sensitive content
    sha: str = ""                           # keyed hash of the whole text
    source: EntityRef | None = None         # the file, URL or object it came from
    mentions: list[EntityRef] = field(default_factory=list)
    chunks: list[ChunkRef] = field(default_factory=list)
    preexisting: bool = False               # read from a file last modified before the session began


# -- what the guard concludes ---------------------------------------------------------------


@dataclass
class PathStep:
    """One node of an attack path, with the edge that leads to the next node."""

    node_id: str
    label: str                  # node label, e.g. "Content"
    title: str                  # short human description of the node
    rel: str | None = None      # relationship type to the next step, None on the last step
    forward: bool = True        # True when the stored edge points from this step to the next
    # What the node is in the story: "untrusted" | "sensitive" | "user" | "destination" |
    # "call" | "file" | "fingerprint" | "entity". Renderers colour by it.
    role: str = ""


@dataclass
class Finding:
    rule: str                   # "TT001"
    name: str                   # "exfil.confirmed"
    severity: str               # one of schema.SEVERITIES
    action: str                 # "allow" | "ask" | "deny"
    title: str                  # one line
    explanation: str            # two or three plain sentences
    path: list[PathStep] = field(default_factory=list)
    session_id: str = ""
    target_id: str = ""         # the ToolCall or Content the finding is about
    target_label: str = "ToolCall"
    ts: int = 0
    # What the rule called for before the mode and per-rule overrides were applied. In
    # monitor mode ``action`` is "allow" and this says what would have happened.
    intended: str = ""
    # The Cypher path query that produced ``path``, and its parameters. Anyone can
    # re-run it against the graph (or against an export, in the browser).
    query: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.target_id}:{self.rule}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        return d


_RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Decision:
    """What the harness should do with a tool call."""

    action: str = "allow"                   # the strictest action among the findings
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""                        # shown to the user and to the agent when blocking
    context: str = ""                       # extra text for the agent's context (warnings)
    notice: str = ""                        # a warning for the user about the guard itself

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "Decision":
        action = "allow"
        for f in findings:
            if _RANK.get(f.action, 0) > _RANK[action]:
                action = f.action
        return cls(action=action, findings=list(findings))


# -- what the harness tells the guard ---------------------------------------------------------


@dataclass
class HookEvent:
    """One event from an agent harness, in a harness-neutral shape."""

    kind: str                               # "session_start" | "user_prompt" | "pre_tool" | "post_tool" | "session_end"
    session_id: str
    cwd: str = ""
    ts: int = 0                             # epoch milliseconds
    agent_kind: str = "claude-code"
    agent: str = "main"                     # "main" or a subagent identifier
    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_response: Any = None
    tool_use_id: str = ""
    prompt: str = ""
    failed: bool = False                    # post_tool for a call that errored
    raw: dict[str, Any] = field(default_factory=dict)
