"""Turns a tool call, and later its result, into the facts the recorder writes down.

``analyze_call`` runs before a tool executes and looks only at its arguments: which
files, hosts and repositories it touches, whether it can move data off the machine, and
the text whose fingerprints may betray copied data. ``analyze_result`` runs afterwards
on what the tool returned: could a third party have written it, does it hold private
data, what does it mention.

Nothing here touches the graph or decides anything.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from . import schema as S
from .bashparse import BashAnalysis, analyze_bash
from .classify import load_catalog, match_server, parse_tool_name
from .config import Config
from .extract import (
    content_chunks, encoded_secret_chunks, extract_entities, file_entity, find_secrets, find_urls, fingerprint, host_entity, host_of,
    injection_score, normalize_url, redact, repo_entity, url_entity,
)
from .model import Action, CallAnalysis, ContentAnalysis, EntityRef, ToolLabels
from .recorder import is_instruction_file

READ_TOOLS = {"Read", "NotebookRead"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SEARCH_TOOLS = {"Glob", "Grep", "LS"}
SUBAGENT_TOOLS = {"Task", "Agent"}

_SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH", re.I)
_URL_KEYS = {"url", "uri", "endpoint", "href", "link", "webhook", "webhook_url", "target_url", "base_url"}
_RECIPIENT_KEYS = {"to", "recipient", "recipients", "cc", "bcc", "email", "channel", "channel_id", "chat_id",
                   "user", "user_id", "thread_ts", "conversation", "room", "team", "assignee"}
_PATH_KEYS = {"path", "paths", "file", "file_path", "filepath", "filename", "source", "destination", "directory",
              "dir", "notebook_path"}
_ID_KEYS = ("owner", "repo", "repository", "project", "number", "issue_number", "pull_number", "id", "key", "name",
            "query", "q", "path", "url", "channel", "ref")
_MENTION = re.compile(r"(?<![\w@])@((?:~|\.{1,2})?/?[\w.-]+(?:/[\w.-]+)*\.?[\w-]*)")
_FORGE_HOST = {"github": "github.com", "gitlab": "gitlab.com"}
# Suffixes that are not themselves a party: nobody "names" co.uk by naming docs.shop.co.uk. This
# is a short stand-in for the public suffix list. It matters for safety, not only for tidiness:
# what the user named extends to parent domains, so a missing entry would let one tenant of a
# shared suffix vouch for all the others.
_PUBLIC_SUFFIXES = frozenset("""
    co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk nhs.uk
    com.au net.au org.au edu.au gov.au id.au  co.nz net.nz org.nz govt.nz ac.nz
    co.jp ne.jp or.jp ac.jp go.jp  co.kr or.kr ne.kr go.kr ac.kr
    co.in net.in org.in gen.in firm.in ind.in ac.in gov.in edu.in
    com.br net.br org.br gov.br edu.br  com.cn net.cn org.cn gov.cn edu.cn
    com.tw org.tw net.tw edu.tw  com.hk org.hk edu.hk  com.sg edu.sg org.sg gov.sg  com.my org.my
    co.id or.id ac.id go.id  co.th in.th ac.th or.th  com.ph com.vn com.pk com.bd
    com.tr org.tr net.tr edu.tr  com.mx org.mx  com.ar com.co com.pe com.ve com.uy com.ec com.bo com.py
    co.za org.za net.za ac.za  com.ng co.ke com.eg com.gh co.tz co.ug  co.il org.il ac.il  com.sa com.qa
    com.ua co.ua  com.pl net.pl org.pl  co.at or.at ac.at  com.es org.es  com.pt com.gr com.cy com.mt
    com.ru org.ru net.ru  co.rs  com.ro  co.hu  com.hr
""".split())
# Domains under which strangers get their own names at any depth (hosting, tunnels, buckets,
# request catchers). A host under one of them has no parent domain worth the name.
_SHARED_BASES = tuple("""
    amazonaws.com amazonaws.com.cn elasticbeanstalk.com awsapprunner.com cloudfront.net
    azurewebsites.net windows.net azureedge.net azurestaticapps.net cloudapp.azure.com trafficmanager.net
    googleapis.com googleusercontent.com appspot.com run.app cloudfunctions.net web.app firebaseapp.com
    github.io githubusercontent.com gitlab.io pages.dev workers.dev r2.dev herokuapp.com vercel.app
    netlify.app onrender.com fly.dev railway.app repl.co replit.dev glitch.me surge.sh deno.dev
    digitaloceanspaces.com ondigitalocean.app supabase.co blogspot.com wordpress.com notion.site
    webflow.io readthedocs.io gitbook.io pythonanywhere.com
    ngrok.io ngrok.app ngrok-free.app ngrok-free.dev trycloudflare.com loca.lt localtunnel.me serveo.net
    duckdns.org nip.io sslip.io pipedream.net webhook.site requestcatcher.com oastify.com interact.sh
""".split())


def parent_domains(host: str) -> list[str]:
    """The domains a host sits under, nearest first, stopping before anything shared or public.

    ``api.eu.vendor.example`` gives ``eu.vendor.example`` and ``vendor.example``;
    ``docs.shop.co.uk`` gives ``shop.co.uk``; ``tenant.github.io`` and an IP address give nothing.
    """
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 3 or labels[-1].isdigit() or ":" in host:
        return []
    if any(host == base or host.endswith("." + base) for base in _SHARED_BASES):
        return []
    out: list[str] = []
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        if parent in _PUBLIC_SUFFIXES:
            break
        out.append(parent)
    return out


# MCP servers that run on this machine and keep what they are given.
_LOCAL_MCP = frozenset({"filesystem", "git", "memory", "sqlite", "time", "sequential-thinking", "desktop-commander"})
# Arguments that identify an object rather than carry free text.
_ID_LIKE = frozenset({"owner", "repo", "repository", "branch", "ref", "sha", "base", "head", "state", "method", "sort",
                      "direction", "path", "id", "number", "issue_number", "pull_number", "page", "per_page", "labels",
                      "assignees", "milestone", "type", "kind", "format", "language", "from_branch", "name"})


# -- arguments -------------------------------------------------------------------------------


def _leaves(value: Any, key: str = "", depth: int = 0) -> Iterable[tuple[str, str]]:
    """Every string in a JSON value, with the key it sits under."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _leaves(v, str(k), depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _leaves(v, key, depth + 1)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield key, str(value)


def _flat_text(value: Any, limit: int) -> str:
    out: list[str] = []
    size = 0
    for _, text in _leaves(value):
        out.append(text)
        size += len(text) + 1
        if size >= limit:
            break
    return "\n".join(out)[:limit]


def _url_room(url: str) -> bool:
    """Whether a URL has room for data the sender chose: a query or a long segment."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    if parts.query or parts.username or parts.password:
        return True
    if any(len(label) >= 20 for label in (parts.hostname or "").split(".")):
        return True
    return any(len(seg) >= 40 for seg in parts.path.split("/"))


class _Builder:
    """Collects actions without duplicates and keeps the strongest per entity."""

    _STRENGTH = {S.REFERENCES: 0, S.READS: 1, S.FETCHES: 1, S.EXECUTES: 2, S.WRITES: 2, S.SENDS_TO: 2, S.UPLOADS: 3}

    def __init__(self) -> None:
        self.actions: dict[tuple[str, str], Action] = {}
        self.destinations: dict[str, EntityRef] = {}

    def add(self, rel: str, ref: EntityRef | None, **props: Any) -> None:
        if ref is None or not ref.value:
            return
        self.actions.setdefault((rel, ref.id), Action(rel, ref, dict(props)))

    def dest(self, ref: EntityRef | None) -> None:
        if ref is not None and ref.value:
            self.destinations.setdefault(ref.id, ref)
            self.add(S.SENDS_TO, ref)

    def host(self, host: str, *, send: bool = True, fetch: bool = False) -> None:
        """A host, and the domains it sits under.

        Untrusted text names ``dns.attacker.example``; the call resolves
        ``<data>.dns.attacker.example``. The parent domains are recorded with
        ``via="suffix"`` so the rules can ask who named any of them.
        """
        ref = host_entity(host)
        if ref is None:
            return
        if fetch:
            self.add(S.FETCHES, ref)
        if send:
            self.dest(ref)
        for name in parent_domains(ref.value):
            parent = EntityRef("host", name)
            rel = S.SENDS_TO if send else S.FETCHES
            self.actions.setdefault((rel, parent.id), Action(rel, parent, {"via": "suffix"}))

    def http(self, url: str, *, send: bool = True, fetch: bool = True) -> None:
        u = url_entity(url)
        if fetch:
            self.add(S.FETCHES, u)
        if send:
            self.dest(u)
            repo = repo_entity(url)
            if repo is not None:
                self.dest(repo)
        self.host(host_of(url) or "", send=send, fetch=fetch)

    def references(self, refs: Iterable[EntityRef]) -> None:
        touched = {entity_id for _, entity_id in self.actions}
        for ref in refs:
            if ref.id not in touched:
                self.add(S.REFERENCES, ref)
                touched.add(ref.id)

    def build(self) -> list[Action]:
        return list(self.actions.values())


def analyze_call(tool_name: str, tool_input: dict, cfg: Config, *, cwd: str, labels: ToolLabels) -> CallAnalysis:
    """What a tool call would do, read from its arguments alone."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    b = _Builder()
    call = CallAnalysis(tool=tool_name, labels=labels)
    limit = cfg.max_content_bytes
    server, tool = parse_tool_name(tool_name)

    if server is not None:
        _analyze_mcp(call, b, server, tool, tool_input, cfg, cwd, labels, limit)
    elif tool in READ_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        ref = file_entity(path, cwd) if path else None
        b.add(S.READS, ref)
        call.summary = f"{tool} {ref.name if ref else ''}".strip()
    elif tool in WRITE_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        ref = file_entity(path, cwd) if path else None
        b.add(S.WRITES, ref)
        pieces = [tool_input.get("content"), tool_input.get("new_string"), tool_input.get("new_source")]
        pieces += [e.get("new_string") for e in _as_list(tool_input.get("edits")) if isinstance(e, dict)]
        call.arg_text = "\n".join(str(p) for p in pieces if isinstance(p, str))[:limit]
        olds = [tool_input.get("old_string")] + [e.get("old_string") for e in _as_list(tool_input.get("edits")) if isinstance(e, dict)]
        call.extra["old_text"] = "\n".join(str(p) for p in olds if isinstance(p, str))[:limit]
        call.summary = f"{tool} {ref.name if ref else ''}".strip()
    elif tool in SEARCH_TOOLS:
        root = str(tool_input.get("path") or cwd)
        b.add(S.READS, file_entity(root, cwd))
        pattern = str(tool_input.get("pattern") or tool_input.get("glob") or "")
        call.arg_text = pattern
        call.summary = f"{tool} {pattern}".strip()[:120]
    elif tool == "WebFetch":
        url = str(tool_input.get("url") or "")
        if url and "://" not in url:
            url = "https://" + url
        b.http(url)
        call.is_sink, call.sink_kind = True, "http"
        call.extra["carries_payload"] = _url_room(url)
        call.arg_text = url
        call.summary = "WebFetch " + (normalize_url(url) or url).split("://", 1)[-1][:120]
    elif tool == "WebSearch":
        query = str(tool_input.get("query") or "")
        call.is_sink, call.sink_kind = True, "search"
        call.extra["dest_trusted"] = True     # the query goes to the search provider
        call.extra["carries_payload"] = True
        call.arg_text = query
        call.summary = f"WebSearch {query!r}"[:120]
    elif tool == "Bash":
        _analyze_bash(call, b, str(tool_input.get("command") or ""), cfg, cwd)
    elif tool in SUBAGENT_TOOLS:
        call.arg_text = str(tool_input.get("prompt") or "")[:limit]
        call.summary = f"{tool}: {tool_input.get('description') or tool_input.get('subagent_type') or 'sub-agent'}"[:120]
    else:
        call.arg_text = _flat_text(tool_input, limit)
        call.summary = tool

    if call.arg_text:
        b.references(extract_entities(call.arg_text, cwd=cwd, limit=cfg.max_entities))
    call.actions = b.build()
    call.destinations = list(b.destinations.values())
    call.summary = redact(call.summary, 200) if call.summary else tool_name
    return call


def _analyze_bash(call: CallAnalysis, b: _Builder, command: str, cfg: Config, cwd: str) -> None:
    ba = analyze_bash(command, cwd)
    call.extra["bash"] = ba
    for path in ba.reads:
        b.add(S.READS, file_entity(path, cwd))
    for path in ba.writes:
        b.add(S.WRITES, file_entity(path, cwd))
    for path in ba.deletes:
        b.add(S.WRITES, file_entity(path, cwd), op="delete")
    for path in ba.uploads:
        b.add(S.UPLOADS, file_entity(path, cwd))
    for name in ba.env_uploads:
        b.add(S.UPLOADS, EntityRef("env", name))
    if ba.env_uploaded:
        b.add(S.UPLOADS, EntityRef("env", "*"))
    for name in ba.env_reads:
        if name not in ba.env_uploads:
            b.add(S.READS, EntityRef("env", name))
    if ba.env_dump and not ba.env_uploaded:
        b.add(S.READS, EntityRef("env", "*"))
    for url in ba.fetches:
        b.http(url, send=False)
    for kind, value in ba.destinations:
        if kind == "url":
            b.http(value, fetch=False)
        elif kind == "host":
            b.host(value)
        elif kind in ("repo", "email"):
            b.dest(EntityRef(kind, value.lower()))
    for item in ba.executed:
        b.add(S.EXECUTES, url_entity(item) if "://" in item else file_entity(item, cwd))
    for path in ba.staged:
        b.add(S.READS, file_entity(path, cwd), staged=True)
    derived = []
    for target, source in ba.derived:
        if source.startswith("env:"):
            src = EntityRef("env", source[4:])
        else:
            src = url_entity(source) if "://" in source else file_entity(source, cwd)
        if src is not None:
            derived.append((file_entity(target, cwd).id, src.id))
    if derived:
        call.extra["derived"] = derived
    call.is_sink = ba.is_sink
    call.sink_kind = (ba.sink_kinds[0] if ba.sink_kinds else "")
    call.executes_download = ba.executes_download
    call.encodes = ba.encodes
    call.env_dump = ba.env_dump
    call.extra["carries_payload"] = ba.carries_payload
    call.extra["env_auth"] = list(ba.env_auth)
    # A request that is nothing but a GET of a URL: no body, no upload, no variable, no pipe into it.
    call.extra["plain_get"] = not (ba.uploads or ba.env_uploads or ba.env_uploaded or ba.opaque or _NOT_A_GET.search(command))
    if ba.opaque:
        call.extra["opaque_reasons"] = list(ba.opaque_reasons)
    call.arg_text = command[: cfg.max_content_bytes]
    call.summary = "Bash: " + ba.summary


def _analyze_mcp(call: CallAnalysis, b: _Builder, server: str, tool: str, tool_input: dict, cfg: Config,
                 cwd: str, labels: ToolLabels, limit: int) -> None:
    entry = match_server(server, catalog=load_catalog())
    forge = _FORGE_HOST.get((entry or {}).get("id", ""))
    leaves = list(_leaves(tool_input))
    by_key = {k.lower(): v for k, v in leaves}
    specific = False

    owner, repo = by_key.get("owner"), by_key.get("repo") or by_key.get("repository")
    if repo and "/" in repo and not owner:
        owner, repo = repo.split("/", 1)
    if owner and repo:
        ref = EntityRef("repo", f"{forge}/{owner}/{repo}".lower()) if forge else EntityRef("mcp", f"{server}/{owner}/{repo}".lower())
        if labels.external_sink:
            b.dest(ref)
            specific = True
        else:
            b.add(S.READS, ref)

    url_only = True
    for key, value in leaves:
        k = key.lower()
        urls = find_urls(value) if "://" in value else []
        if k in _URL_KEYS or (urls and value.strip() == urls[0]):
            for url in urls or [value]:
                if "://" not in url:
                    continue
                b.http(url, send=labels.external_sink or not labels.untrusted_input, fetch=True)
                specific = specific or labels.external_sink
            continue
        url_only = False
        if k in _RECIPIENT_KEYS and labels.external_sink and value.strip():
            for part in re.split(r"[,;\s]+", value.strip()):
                if "@" in part and "." in part:
                    b.dest(EntityRef("email", part.strip("<>").lower()))
                elif part:
                    b.dest(EntityRef("mcp", f"{server}/{k}:{part}"[:200]))
                specific = True
        elif k in _PATH_KEYS and value and "://" not in value and len(value) < 400:
            looks_local = value.startswith(("/", "~", "./", "../")) or (entry or {}).get("id") in (
                "filesystem", "git", "desktop-commander")
            if looks_local:
                b.add(S.WRITES if labels.local_write else S.READS, file_entity(value, cwd))

    for key, value in leaves:
        v = value.strip()
        if key.lower() in _OBJECT_KEYS and 2 <= len(v) <= 80 and not re.search(r"\s", v):
            b.add(S.REFERENCES if labels.external_sink else S.READS, EntityRef("mcp", f"{server}/obj:{v}"), object=True)
    call.is_sink = bool(labels.external_sink)
    free_text = [v for k, v in leaves if k.lower() not in _ID_LIKE and k.lower() not in _URL_KEYS]
    roomy = any(len(v) >= 40 for v in free_text) or sum(len(v) for v in free_text) >= 80
    if call.is_sink:
        call.sink_kind = "mcp"
        if not specific:
            b.dest(EntityRef("mcp", server))
        only_fetches = url_only and bool(leaves)
        call.extra["carries_payload"] = (any(_url_room(v) for _, v in leaves if "://" in v) if only_fetches else roomy)
    elif (entry or {}).get("id") not in _LOCAL_MCP:
        # Whatever a tool's label, its arguments go to the server that provides it. For a
        # server that is not known to be local, that is somewhere else.
        call.extra["args_leave"] = True
        call.extra["carries_payload"] = roomy
        b.dest(EntityRef("mcp", server))
    call.arg_text = "\n".join(v for _, v in leaves)[:limit]
    call.extra["mcp_server"] = server
    call.extra["mcp_key"] = _mcp_key(by_key)
    call.summary = f"{server}.{tool} {call.extra['mcp_key']}".strip()


# Arguments that name the remote object a call reads or writes (a page, an issue, a channel).
_OBJECT_KEYS = frozenset({"id", "page_id", "pageid", "issueid", "issue_id", "channel_id", "channel", "document_id",
                          "doc_id", "project_id", "ticket_id", "thread_id", "conversation_id"})
_NOT_A_GET = re.compile(
    r"(?:^|\s)(?:-d|--data[\w-]*|--json|-F|--form[\w-]*|-T|--upload-file|--post-data|--post-file|--body-data|--body-file)(?:\s|=)"
    r"|-X\s*(?:POST|PUT|PATCH|DELETE)|\|\s*(?:curl|wget|nc|ncat|netcat|ssh)\b")


def _mcp_key(by_key: dict[str, str]) -> str:
    """A short handle for the object an MCP call is about, built from id-like arguments."""
    owner, repo = by_key.get("owner"), by_key.get("repo") or by_key.get("repository")
    parts = []
    if owner and repo:
        parts.append(f"{owner}/{repo}")
    for key in _ID_KEYS:
        if key in ("owner", "repo", "repository"):
            continue
        value = by_key.get(key)
        if value and len(value) <= 80 and "\n" not in value:
            parts.append(f"#{value}" if key.endswith("number") else value)
        if len(parts) >= 3:
            break
    return " ".join(parts)[:100]


# -- results -----------------------------------------------------------------------------------


def response_text(tool_name: str, tool_response: Any) -> str:
    """The text a tool put into the agent's context, whatever shape the harness reports it in."""
    r = tool_response
    if r is None:
        return ""
    if isinstance(r, str):
        return r
    _, tool = parse_tool_name(tool_name)
    if isinstance(r, dict):
        if "error" in r and len(r) <= 2 and isinstance(r["error"], str):
            return r["error"]
        if tool in WRITE_TOOLS:
            return ""          # the agent sees a confirmation, not new content
        text = _known_shape(tool, r)
        if text is not None:
            return text
        # A shape this version does not know (a notebook's cells, a background command's handle):
        # every string in it still entered the context. Dropping it would record the result as
        # empty, and nothing in it could ever appear on a path.
        return _flat_text(r, 1_000_000)
    if isinstance(r, list):
        text = _blocks_text(r)
        if text:
            return text
    return _flat_text(r, 1_000_000)


def _known_shape(tool: str, r: dict[str, Any]) -> str | None:
    """The text of a result in the shape the harness uses for this tool; None for any other shape."""
    if tool in READ_TOOLS:
        file = r.get("file")
        if not isinstance(file, dict):
            return None
        if isinstance(file.get("content"), str):
            return file["content"]
        if "base64" in file:
            return ""      # an image or another binary: no text entered the context
        return _flat_text({k: v for k, v in file.items() if k not in ("filePath", "path")}, 1_000_000)
    if tool == "Bash":
        if "stdout" not in r and "stderr" not in r:
            return None
        return "\n".join(x for x in (r.get("stdout"), r.get("stderr")) if isinstance(x, str) and x)
    if tool == "Grep":
        if "content" not in r and "filenames" not in r:
            return None
        content = r.get("content")
        if isinstance(content, str) and content:
            return content
        return "\n".join(str(n) for n in _as_list(r.get("filenames")))
    if tool in ("Glob", "LS"):
        return "\n".join(str(n) for n in _as_list(r["filenames"])) if "filenames" in r else None
    if tool == "WebFetch":
        if "result" not in r:
            return None
        return r["result"] if isinstance(r["result"], str) else _flat_text(r["result"], 1_000_000)
    if tool in SUBAGENT_TOOLS:
        if "content" not in r and "result" not in r:
            return None
        return _blocks_text(r.get("content")) or (r["result"] if isinstance(r.get("result"), str) else "")
    if isinstance(r.get("content"), list):
        return _blocks_text(r["content"]) or None
    return None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _blocks_text(blocks: Any) -> str:
    if not isinstance(blocks, list):
        return ""
    out = []
    for block in blocks:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            out.append(block["text"])
        elif isinstance(block, str):
            out.append(block)
    return "\n".join(out)


def _content(text: str, cfg: Config, cwd: str, *, origin: str = "tool") -> ContentAnalysis:
    """The parts of a content analysis that do not depend on where the text came from."""
    full_bytes = len(text.encode("utf-8", "replace"))
    text = text[: cfg.max_content_bytes]
    key = cfg.key()
    secrets = find_secrets(text)
    score, markers = injection_score(text)
    a = ContentAnalysis(
        origin=origin, text_bytes=full_bytes, injection_score=score, injection_markers=markers,
        excerpt=redact(text, 240), sha=fingerprint(text, key) if text else "",
        mentions=extract_entities(text, cwd=cwd, limit=cfg.max_entities),
        chunks=content_chunks(text, key, limit=cfg.max_chunks),
    )
    if secrets:
        a.sensitive = True
        for kind in dict.fromkeys(h.kind for h in secrets):
            a.reasons.append(f"secret:{kind}")
    hidden, kinds = encoded_secret_chunks(text[:65_536], key) if origin == "tool" else ([], [])
    if hidden:
        known = {c.id for c in a.chunks}
        a.chunks = [c for c in hidden if c.id not in known] + a.chunks
        a.sensitive = True
        a.reasons += [f"encoded-secret:{kind}" for kind in kinds if f"secret:{kind}" not in a.reasons]
    return a


def analyze_result(tool_name: str, tool_input: dict, tool_response: Any, call: CallAnalysis, cfg: Config, *,
                   cwd: str, tainted_sources: Iterable[str] = frozenset()) -> ContentAnalysis:
    """What entered the agent's context when a tool returned."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    tainted = set(tainted_sources)
    server, tool = parse_tool_name(tool_name)
    a = _content(response_text(tool_name, tool_response), cfg, cwd)
    has_text = a.text_bytes > 0

    def untrusted(reason: str) -> None:
        if has_text and reason not in a.reasons:
            a.untrusted = True
            a.reasons.append(reason)

    def sensitive(reason: str) -> None:
        if has_text and reason not in a.reasons:
            a.sensitive = True
            a.reasons.append(reason)

    if server is not None:
        key = call.extra.get("mcp_key") or ""
        fetched = [act.entity for act in call.actions if act.rel == S.FETCHES and act.entity.kind == "url"]
        a.source = fetched[0] if fetched else EntityRef("mcp", f"{server}/{tool} {key}".strip()[:200])
        if (match_server(server, catalog=load_catalog()) or {}).get("id") in _LOCAL_MCP:
            for ref in [e for e in call.entities(S.READS) if e.kind == "file"]:
                if cfg.is_untrusted_path(ref.value):
                    untrusted("path:untrusted")
                if ref.id in tainted:
                    untrusted(f"tainted:{ref.name}")
                if cfg.is_sensitive_path(ref.value):
                    sensitive("path:sensitive")
        else:
            if call.labels.untrusted_input:
                untrusted(f"source:{server}")
            if call.labels.private_data:
                sensitive(f"private:{server}")
    elif tool in READ_TOOLS or tool in SEARCH_TOOLS:
        read = call.entities(S.READS)
        a.source = read[0] if read else None
        for ref in read:
            if cfg.is_untrusted_path(ref.value):
                untrusted("path:untrusted")
            if ref.id in tainted:
                untrusted(f"tainted:{ref.name}")
            if tool in READ_TOOLS and cfg.is_sensitive_path(ref.value):
                sensitive("path:sensitive")
    elif tool == "WebFetch":
        fetched = [act.entity for act in call.actions if act.rel == S.FETCHES and act.entity.kind == "url"]
        a.source = fetched[0] if fetched else None
        untrusted("source:web")
    elif tool == "WebSearch":
        untrusted("source:web-search")
    elif tool == "Bash":
        ba = call.extra.get("bash")
        if not isinstance(ba, BashAnalysis):
            ba = analyze_bash(str(tool_input.get("command") or ""), cwd)
        reads = [file_entity(p, cwd) for p in ba.reads]
        fetched = [url_entity(u) for u in ba.fetches]
        fetched = [u for u in fetched if u is not None]
        # A response from this machine is not third-party text. (A local service can relay stored
        # third-party text; `paths.untrusted` and the injection score still apply to what it returns.)
        all_local = bool(fetched) and all(cfg.is_local_host(host_of(u.value) or "") for u in fetched)
        if ba.untrusted_output and not all_local:
            untrusted("source:network" if fetched else "source:third-party")
        # A file that is sourced (`. ./.env`) is not printed, and a variable that is sent elsewhere
        # is not in the output: the output is sensitive when the command prints the secret.
        sourced = {file_entity(p, cwd).id for p in ba.executed if "://" not in p}
        for ref in reads:
            if cfg.is_untrusted_path(ref.value):
                untrusted("path:untrusted")
            if ref.id in tainted:
                untrusted(f"tainted:{ref.name}")
            if cfg.is_sensitive_path(ref.value) and ref.id not in sourced:
                sensitive("path:sensitive")
        prints = ba.env_dump or any(prog in ("echo", "printf", "printenv") for prog in ba.programs)
        if ba.env_dump or (prints and any(_SECRETISH.search(name) for name in ba.env_reads)):
            sensitive("environment")
        if ba.sensitive_output:
            sensitive("credential-command")
        if ba.untrusted_output and fetched:
            a.source = fetched[0]
        elif len(reads) == 1 and not fetched:
            a.source = reads[0]
    is_memory_file = a.source is not None and a.source.kind == "file" and is_instruction_file(a.source.value)
    if has_text and a.injection_score >= 0.5 and not a.untrusted and not is_memory_file:
        # Text addressed to the agent inside a "trusted" file or tool result is the attack
        # most reports describe: a README, a source comment, a rules file in the repository.
        untrusted("reads-like-instructions")
    if not has_text:
        a.untrusted = a.sensitive = False
        a.reasons = []
    return a


def analyze_memory(text: str, cfg: Config, *, cwd: str, name: str) -> ContentAnalysis:
    """An instruction file the harness loads by itself, known to have been written under untrusted influence."""
    a = _content(text or "", cfg, cwd, origin="memory")
    a.untrusted = True
    a.sensitive = False
    a.reasons = [f"inherited:{name}"]
    a.excerpt = f"{name} was written by an earlier session that held untrusted content"
    return a


def prompt_file_mentions(prompt: str, cwd: str) -> list[EntityRef]:
    """Files named with ``@path`` in a prompt. The harness inserts their contents without a tool call."""
    refs: dict[str, EntityRef] = {}
    for m in _MENTION.finditer(prompt or ""):
        ref = file_entity(m.group(1).rstrip(".,;:"), cwd)
        refs.setdefault(ref.id, ref)
    return list(refs.values())


def analyze_attachment(path_ref: EntityRef, text: str, cfg: Config, *, cwd: str,
                       tainted_sources: Iterable[str] = frozenset()) -> ContentAnalysis:
    """A file the user attached to a prompt, judged exactly as if the agent had read it."""
    call = CallAnalysis(tool="Read", actions=[Action(S.READS, path_ref)], labels=ToolLabels())
    a = analyze_result("Read", {"file_path": path_ref.value}, {"type": "text", "file": {"content": text}}, call, cfg,
                       cwd=cwd, tainted_sources=tainted_sources)
    a.origin = "attached"
    return a


def analyze_prompt(prompt: str, cfg: Config, *, cwd: str) -> ContentAnalysis:
    """What the user typed. Never untrusted; it is the one voice the agent works for."""
    prompt = prompt or ""
    a = _content(prompt, cfg, cwd, origin="user")
    seen = {m.id for m in a.mentions}
    for m in _MENTION.finditer(prompt):      # @path mentions
        ref = file_entity(m.group(1), cwd)
        if ref.id not in seen:
            a.mentions.append(ref)
            seen.add(ref.id)

    def also(ref: EntityRef) -> None:
        if ref.id not in seen:
            a.mentions.append(ref)
            seen.add(ref.id)

    # "the token is in PYPI_TOKEN" names the variable as surely as "$PYPI_TOKEN" does
    for m in re.finditer(r"(?<![\w$])[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?![\w])", prompt):
        also(EntityRef("env", m.group(0)))
    # naming docs.vendor.example names the vendor: its other hosts are not strangers
    for ref in [m for m in a.mentions if m.kind == "host"]:
        for parent in parent_domains(ref.value):
            also(EntityRef("host", parent))
    # a bucket the user typed is the host the upload goes to
    for m in re.finditer(r"\bs3://([a-z0-9][a-z0-9.-]{1,62})", prompt):
        also(EntityRef("host", f"{m.group(1)}.s3.amazonaws.com"))
    return a
