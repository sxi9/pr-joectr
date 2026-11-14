"""What a tool can do, as far as an attack path is concerned.

Three sources, in order of trust:

1. a built-in table for the tools an agent harness ships with;
2. a catalog of well-known MCP servers and their tools, shipped as data;
3. keyword heuristics over a tool's name and description, with honest low confidence.

Labels set by a person (``tainttrail tools set``) or by a model live in the graph and
outrank all of this; see ``Recorder.tool_labels``.
"""

from __future__ import annotations

import functools
import json
import re
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from .model import CAPABILITY_NAMES, ToolLabels


def _b(notes: str = "", **caps: bool) -> ToolLabels:
    return ToolLabels(source="builtin", confidence=1.0, notes=notes, **caps)


# Tools that ship with Claude Code. Several names are kept for older versions.
BUILTIN_TOOLS: dict[str, ToolLabels] = {
    "Read": _b("reads any file the user can read", private_data=True),
    "NotebookRead": _b("reads notebooks", private_data=True),
    "Glob": _b("lists file names", private_data=True),
    "Grep": _b("prints matching lines of files", private_data=True),
    "LS": _b("lists directories", private_data=True),
    "Write": _b("creates or overwrites files", local_write=True),
    "Edit": _b("edits files", local_write=True),
    "MultiEdit": _b("edits files", local_write=True),
    "NotebookEdit": _b("edits notebooks", local_write=True),
    "Bash": ToolLabels(
        untrusted_input=True, private_data=True, external_sink=True, local_write=True, code_exec=True,
        source="builtin", confidence=1.0, sink_scope="public",
        notes="runs any command: can fetch, read, write and send",
    ),
    "BashOutput": _b("output of a background shell", untrusted_input=True, private_data=True),
    "KillShell": _b(),
    "KillBash": _b(),
    "WebFetch": ToolLabels(
        untrusted_input=True, external_sink=True, source="builtin", confidence=1.0, sink_scope="public",
        notes="fetches a URL; a GET can carry data out in its path and query",
    ),
    # The query goes to the search provider, not to a party an attacker controls, so the
    # static map does not count it as a sink. Its results are third-party text.
    "WebSearch": _b("search results are third-party text", untrusted_input=True),
    "Task": _b("starts a sub-agent with the same tools"),
    "Agent": _b("starts a sub-agent with the same tools"),
    "TodoWrite": _b(),
    "TaskCreate": _b(),
    "TaskUpdate": _b(),
    "TaskList": _b(),
    "TaskGet": _b(),
    "ExitPlanMode": _b(),
    "EnterPlanMode": _b(),
    "AskUserQuestion": _b(),
    "Skill": _b(),
    "SlashCommand": _b(),
    "ToolSearch": _b(),
    "ListMcpResourcesTool": _b("lists resources of MCP servers", private_data=True),
    "ReadMcpResourceTool": ToolLabels(
        untrusted_input=True, private_data=True, source="builtin", confidence=0.6,
        notes="reads a resource from an MCP server; what it holds depends on the server",
    ),
}

# Keyword heuristics for tools nobody has described to us. A verb says what the tool
# does; an object says to what. Both must be present for the reading capabilities.
DEFAULT_HEURISTICS: dict[str, Any] = {
    "read_verbs": ["get", "read", "list", "search", "fetch", "find", "query", "browse", "view", "show",
                   "download", "export", "retrieve", "lookup", "scrape", "crawl", "open", "load"],
    "untrusted_objects": ["issue", "comment", "pull", "pr", "review", "discussion", "email", "mail", "message",
                          "inbox", "ticket", "page", "web", "url", "html", "site", "search", "feed", "post",
                          "thread", "channel", "chat", "tweet", "forum", "article", "news", "transcript"],
    "private_objects": ["file", "repo", "repository", "database", "db", "sql", "table", "record", "row",
                        "secret", "env", "credential", "key", "token", "mail", "email", "inbox", "drive",
                        "document", "doc", "sheet", "calendar", "contact", "customer", "user", "account",
                        "invoice", "payment", "log", "note", "memory", "vault", "bucket", "object", "blob"],
    "sink_verbs": ["send", "post", "publish", "comment", "reply", "upload", "share", "notify", "invite",
                   "tweet", "push", "submit", "forward", "broadcast", "email", "mail", "message"],
    "sink_create_objects": ["issue", "comment", "pull", "pr", "review", "gist", "message", "post", "page",
                            "ticket", "discussion", "release", "webhook", "email", "tweet", "snippet", "paste"],
    "http_words": ["http", "request", "webhook", "curl", "url"],
    "write_verbs": ["write", "edit", "create", "delete", "remove", "move", "rename", "mkdir", "append",
                    "save", "update", "patch", "replace"],
    "write_objects": ["file", "directory", "dir", "folder", "path", "note", "memory"],
    "exec_words": ["run", "exec", "execute", "shell", "command", "terminal", "eval", "script", "bash",
                   "python", "deploy", "invoke"],
}

_WORD = re.compile(r"[a-z]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def parse_tool_name(name: str) -> tuple[str | None, str]:
    """``mcp__github__get_issue`` -> ``("github", "get_issue")``; ``Read`` -> ``(None, "Read")``."""
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    return None, name


@functools.lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    """The packaged catalog of well-known MCP servers. Empty if the data file is absent."""
    try:
        text = resources.files("tainttrail").joinpath("data", "mcp_catalog.json").read_text(encoding="utf-8")
        data = json.loads(text)
    except (FileNotFoundError, ModuleNotFoundError, ValueError, OSError):
        return {"servers": [], "heuristics": {}}
    if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
        return {"servers": [], "heuristics": {}}
    return data


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _tokens(text: str) -> list[str]:
    """Lower-case words of a name or sentence, with plain plurals also given in the singular."""
    words: list[str] = []
    for word in _WORD.findall(_CAMEL.sub(" ", text).lower()):
        words.append(word)
        if len(word) > 3 and word.endswith("ies"):
            words.append(word[:-3] + "y")
        elif len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
            words.append(word[:-1])
    return words


def match_server(name: str, command: str = "", args: list[str] | None = None, url: str = "",
                 catalog: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """The catalog entry for an MCP server, found by its package, its URL host or its name.

    A package or host match is strong. A name match is a guess, because people name
    servers freely, so it requires the catalog name to be a whole token of the server's
    name (``github`` matches ``github`` and ``my-github``, not ``githubbish``).
    """
    catalog = catalog or load_catalog()
    haystack = " ".join([command, *(args or [])]).lower()
    host = ""
    if url:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
    name_tokens = set(re.split(r"[^a-z0-9]+", name.lower())) - {""}
    by_name = None
    for server in catalog.get("servers", []):
        match = server.get("match") or {}
        for package in match.get("packages") or []:
            if package and package.lower() in haystack:
                return server
        for h in match.get("url_hosts") or []:
            if host and (host == h.lower() or host.endswith("." + h.lower())):
                return server
        if by_name is None:
            for candidate in [server.get("id"), *(match.get("names") or [])]:
                if not candidate:
                    continue
                c = candidate.lower()
                if _norm(name) == _norm(c) or c in name_tokens:
                    by_name = server
                    break
    return by_name


def _catalog_tool(server: dict[str, Any], tool: str) -> dict[str, Any] | None:
    wanted = _norm(tool)
    for entry in server.get("tools") or []:
        if _norm(str(entry.get("name", ""))) == wanted:
            return entry
    return None


def _heuristics(catalog: dict[str, Any]) -> dict[str, list[str]]:
    merged = {k: list(v) for k, v in DEFAULT_HEURISTICS.items()}
    extra = catalog.get("heuristics") or {}
    # The catalog may add keywords under the capability names themselves.
    for cap, key in (("external_sink", "sink_verbs"), ("code_exec", "exec_words")):
        words = extra.get(cap)
        if isinstance(words, list):
            merged[key] = list(dict.fromkeys([*merged[key], *(str(w).lower() for w in words if _WORD.fullmatch(str(w).lower()))]))
    return merged


# Words of a description that are strong enough to count when the name itself names no
# object: "fetch" described as "fetches a URL from the internet".
_STRONG_UNTRUSTED = frozenset({"url", "web", "website", "internet", "html", "page", "search", "email", "issue",
                               "comment", "inbox", "ticket"})
_STRONG_PRIVATE = frozenset({"database", "sql", "secret", "credential", "password", "file", "repository",
                             "inbox", "drive", "vault", "bucket"})
_CREATE_VERBS = frozenset({"create", "add", "update", "write", "new", "insert", "open", "set", "edit"})
_EXEC_VERBS = frozenset({"run", "exec", "execute", "eval", "invoke", "deploy", "spawn"})
_EXEC_NOUNS = frozenset({"shell", "terminal", "bash", "repl", "python", "sandbox"})


def heuristic_labels(tool: str, description: str = "", catalog: dict[str, Any] | None = None) -> ToolLabels:
    """Labels guessed from the words of a tool's name and description.

    The verb decides: ``list_emails`` reads, ``email_report`` sends. A noun that could
    also be a verb (``post``, ``comment``, ``message``) only counts as one in the verb
    position, which is the first word that is a known verb.
    """
    h = _heuristics(catalog or load_catalog())
    name_words = _tokens(tool)
    name_set = set(name_words)
    desc_set = set(_tokens(description))

    verbs = (set(h["read_verbs"]) | set(h["sink_verbs"]) | set(h["write_verbs"]) | _CREATE_VERBS | _EXEC_VERBS)
    verb = next((w for w in name_words if w in verbs), None)
    reads = verb in h["read_verbs"]

    def named(key: str) -> bool:
        return any(w in name_set for w in h[key])

    labels = ToolLabels(source="heuristic")
    names_an_object = named("untrusted_objects") or named("private_objects")
    if reads:
        labels.untrusted_input = named("untrusted_objects") or (not names_an_object and bool(desc_set & _STRONG_UNTRUSTED))
        labels.private_data = named("private_objects") or (not names_an_object and bool(desc_set & _STRONG_PRIVATE))
    if (
        verb in h["sink_verbs"]
        or (verb in _CREATE_VERBS and named("sink_create_objects"))
        or (not reads and named("http_words"))
    ):
        labels.external_sink = True
    if verb in h["write_verbs"] and named("write_objects"):
        labels.local_write = True
    if verb in _EXEC_VERBS or (name_set & _EXEC_NOUNS):
        labels.code_exec = True
    hits = len(labels.capabilities())
    labels.confidence = 0.5 if hits else 0.0
    labels.notes = ("guessed from the tool's name and description" if hits
                    else "nothing in the name suggests a capability")
    return labels


def classify_tool(name: str, description: str = "", input_schema: dict | None = None,
                  server_hint: str = "", catalog: dict[str, Any] | None = None) -> ToolLabels:
    """Capability labels for a tool as the harness names it.

    ``server_hint`` is anything that helps identify the MCP server (its command line or
    URL); the server name inside ``mcp__server__tool`` is always tried.
    """
    catalog = catalog or load_catalog()
    server, tool = parse_tool_name(name)
    if server is None:
        builtin = BUILTIN_TOOLS.get(tool)
        if builtin is not None:
            return ToolLabels(**{**builtin.__dict__})
        return ToolLabels(source="default", confidence=0.0, notes="unknown built-in tool")

    entry = match_server(server, command=server_hint, url=server_hint if "://" in server_hint else "", catalog=catalog)
    if entry is not None:
        known = _catalog_tool(entry, tool)
        if known is not None:
            return ToolLabels(
                **{cap: bool(known.get(cap)) for cap in CAPABILITY_NAMES},
                source="catalog", confidence=0.9, sink_scope=known.get("sink_scope") or None,
                notes=str(known.get("notes") or f"from the catalog entry for {entry.get('id')}"),
            )
    if input_schema and not description:
        description = " ".join(str(k) for k in (input_schema.get("properties") or {}).keys())
    guess = heuristic_labels(tool, description, catalog)
    if entry is not None and guess.capabilities():
        guess.notes = f"{entry.get('id')} server is in the catalog but this tool is not; " + guess.notes
    return guess
