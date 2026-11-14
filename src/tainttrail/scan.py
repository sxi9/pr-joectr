"""The static scanner: what an agent is configured to be able to do.

``tainttrail scan`` reads the configuration files of the agent harnesses on this machine
(which MCP servers they start, which tools those provide, which permission rules apply)
and writes them into the same graph the guard records sessions in::

    (:Agent)-[:CONNECTS]->(:Server)-[:PROVIDES]->(:Tool)-[:HAS_CAPABILITY]->(:Capability)
    (:Server)-[:HOLDS]->(:Credential)

One ``Agent`` node is the *effective* configuration of that agent for this project: user,
project and local scopes merged the way the agent merges them. ``paths.py`` then asks
that graph which combinations of tools form a path from untrusted text to private data to
a place outside the machine.

Nothing here starts a server or opens a connection unless ``--introspect --yes`` is given.
Secret values never reach the graph: environment variables and headers are recorded by
name only, and command lines, URLs and rule texts are redacted before they are stored.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

from . import classify
from .config import Config
from .extract import find_secrets, shannon_entropy
from .model import CAPABILITY_NAMES, ToolLabels
from .store import Store, StoreError, StoreMissing, open_store

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as _toml  # type: ignore[no-redef]

AGENT_NAMES: dict[str, str] = {
    "claude-code": "Claude Code",
    "claude-desktop": "Claude Desktop",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "windsurf": "Windsurf",
    "gemini-cli": "Gemini CLI",
    "codex": "Codex CLI",
}
AGENT_KINDS: tuple[str, ...] = tuple(AGENT_NAMES)

# Labels a person, a model or a live ``tools/list`` produced outrank the tables.
STICKY_LABEL_SOURCES = ("user", "llm", "introspect")

REDACTED = "«redacted»"
MAX_CONFIG_BYTES = 32 * 1024 * 1024
MAX_LENIENT_BYTES = 2 * 1024 * 1024     # comment-tolerant JSON and TOML are parsed in Python: keep them small
MAX_RULE_CHARS = 2000                   # a permission rule longer than this is not a rule anybody wrote
BUILTIN_SERVER = "builtin"


# -- what the configuration files say ------------------------------------------------------


@dataclass
class CredentialRef:
    """A credential a server entry names. The value is never kept."""

    name: str
    kind: str               # "env" | "header" | "url-param" | "argument" | "reference"
    literal: bool = False   # the value itself is written in the file, not a ${REFERENCE}
    secret: bool = False    # the name, the catalog or the value's shape says it is a credential


@dataclass
class ServerEntry:
    """One MCP server as an agent would start or reach it.

    ``argv``, ``env``, ``url`` and ``headers`` are the raw values from the file. They
    stay in memory (matching the catalog, optional introspection) and are redacted by
    ``redact_argv`` / ``redact_url`` before anything is written or printed.
    """

    agent: str
    name: str
    scope: str                      # "user" | "local" | "project" | "managed" | "builtin" | "observed"
    source_file: str
    transport: str = "stdio"        # "stdio" | "http" | "sse" | "ws" | "builtin" | "unknown"
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    env_names: list[str] = field(default_factory=list)      # variables passed by name only
    enabled: bool = True
    status: str = ""                # why it is off, or what its approval state is
    include_tools: list[str] | None = None                  # only these tools are exposed
    exclude_tools: list[str] = field(default_factory=list)
    trust: str = ""                 # set when the entry pre-approves every tool; says by what
    tool_permissions: dict[str, tuple[str, str]] = field(default_factory=dict)  # tool -> (permission, rule)
    default_permission: tuple[str, str] | None = None       # (permission, rule) for the server's other tools
    declared_type: str = ""         # the entry's own "type" / "transport" field, lower case
    notes: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.agent}/{self.name}"


@dataclass
class PermissionRule:
    kind: str       # "allow" | "ask" | "deny"
    text: str       # as written in the file
    source: str     # the file it came from
    scope: str      # "managed" | "local" | "project" | "user"
    dialect: str = "claude"     # rule syntax: "claude" | "cursor" | "gemini"


@dataclass
class AgentConfig:
    """Everything the files say about one agent, merged across scopes."""

    kind: str
    found: bool = False
    config_paths: list[str] = field(default_factory=list)
    servers: list[ServerEntry] = field(default_factory=list)
    rules: list[PermissionRule] = field(default_factory=list)   # highest-precedence file first
    permission_mode: str = ""
    permission_mode_source: str = ""
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    broken: bool = False            # discovery itself failed; nothing reliable is known about the agent

    @property
    def name(self) -> str:
        return AGENT_NAMES.get(self.kind, self.kind)


# -- reading files ---------------------------------------------------------------------------


def _read_text(path: Path, cfg: AgentConfig, *, counts: bool = True, max_bytes: int | None = None) -> str | None:
    """The text of a config file, or None when it is absent or unreadable.

    Every file that exists is remembered on the agent, readable or not, so the report
    can say exactly what was looked at. ``counts=False`` is for files that do not prove
    the agent is in use (a shared ``.mcp.json``, an editor's general settings).
    """
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
    except OSError:
        return None
    cfg.found = cfg.found or counts
    if str(path) not in cfg.config_paths:
        cfg.config_paths.append(str(path))
    limit = MAX_CONFIG_BYTES if max_bytes is None else max_bytes
    if size > limit:
        cfg.problems.append(f"{path}: larger than {max(1, limit // (1024 * 1024))} MB, not read")
        return None
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        cfg.problems.append(f"{path}: cannot be read ({exc.strerror or type(exc).__name__})")
        return None


def strip_jsonc(text: str) -> str:
    """JSON with ``//`` and ``/* */`` comments and trailing commas, as plain JSON.

    VS Code and Zed write their settings this way. Strings are left alone.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif ch == "/" and text.startswith("//", i):
            while i < n and text[i] not in "\r\n":
                i += 1
        elif ch == "/" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    # Trailing commas: drop a comma whose next non-blank character closes a container.
    text = "".join(out)
    cleaned: list[str] = []
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            cleaned.append(ch)
            if ch == "\\" and i + 1 < n:
                cleaned.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            cleaned.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if not (j < n and text[j] in "]}"):
                cleaned.append(ch)
        else:
            cleaned.append(ch)
        i += 1
    return "".join(cleaned)


def _load_json(path: Path, cfg: AgentConfig, *, lenient: bool = False,
               counts: bool = True) -> dict[str, Any] | None:
    """A JSON object from a config file. A broken file is reported, never fatal."""
    text = _read_text(path, cfg, counts=counts)
    if text is None:
        return None
    if not text.strip():
        return {}
    try:
        data = json.loads(strip_jsonc(text) if lenient and len(text) <= MAX_LENIENT_BYTES else text)
    except json.JSONDecodeError as exc:
        cfg.problems.append(f"{path}: not valid JSON (line {exc.lineno}, column {exc.colno}); skipped")
        return None
    except (ValueError, RecursionError):
        cfg.problems.append(f"{path}: not valid JSON; skipped")
        return None
    if not isinstance(data, dict):
        cfg.problems.append(f"{path}: expected a JSON object at the top level; skipped")
        return None
    return data


def _load_toml(path: Path, cfg: AgentConfig) -> dict[str, Any] | None:
    text = _read_text(path, cfg, max_bytes=MAX_LENIENT_BYTES)
    if text is None:
        return None
    try:
        return _toml.loads(text)
    except (ValueError, RecursionError):  # TOMLDecodeError is a ValueError
        cfg.problems.append(f"{path}: not valid TOML; skipped")
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str_list(value: Any) -> list[str]:
    """The strings of a list; anything else in it is ignored."""
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


# -- redaction -------------------------------------------------------------------------------
# A config file is where people paste tokens. Nothing below may let one through to the
# graph, the terminal or a JSON report: values are dropped, and free text is scrubbed.

_SECRET_WORDS = frozenset({
    "key", "apikey", "token", "secret", "password", "passwd", "pwd", "pass", "passphrase", "credential",
    "auth", "authorization", "bearer", "cookie", "pat", "signature",
})
# Names written as one word (PGPASSWORD, AUTHTOKEN, ACCESSKEY) end in one of these.
_SECRET_ENDINGS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "secretkey",
                   "privatekey", "credential")
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")

_REF_ATOM = r"(?:\$\{\{[^{}]*\}\}|\$\{[^{}]*\}|\{env:[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)"
_PURE_REFERENCE = re.compile(rf"^\s*(?:(?:Bearer|Basic|Token)\s+)?{_REF_ATOM}\s*$", re.I)
_REF_DEFAULT = re.compile(r"\$\{[^{}:]*:-([^{}]*)\}")
_REF_NAMES = re.compile(
    r"\$\{\{\s*secrets\.([\w.-]+)\s*\}\}|\$\{input:([\w.-]+)\}|\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-[^{}]*)?\}"
    r"|\{env:([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%")
# Variables that name a place, not a credential.
_PATH_VARIABLES = frozenset({
    "workspaceFolder", "workspaceFolderBasename", "userHome", "pathSeparator", "extensionPath",
    "CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA", "HOME", "PATH", "USER", "PWD",
    "APPDATA", "LOCALAPPDATA", "USERPROFILE", "TMPDIR", "TEMP",
})
_PLACEHOLDER = re.compile(
    r"(?i)^\s*(?:<[^<>]*>|\[[^\[\]]*\]|x{3,}|\*{3,}|\.{3,}|-+|placeholder|change[-_ ]?me|todo|tbd|none|null|nil"
    r"|your[-_ ].*|.*\byour[-_ ]?(?:api[-_ ]?)?(?:key|token|secret|password)\b.*|example|dummy|redacted|value"
    r"|true|false|\d{1,6})?\s*$")

_ALNUM_RUN = re.compile(r"[A-Za-z0-9]{16,}")
_DASHED_TOKEN = re.compile(r"^[A-Za-z0-9]{4,}(?:[-_][A-Za-z0-9]{4,}){3,}$")
_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+=_~-]{20,}")
_URL_IN_TEXT = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>`]+")
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+([^\s\"',;]{6,})")
_AUTH_HEADER = re.compile(r"(?i)(\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:[A-Za-z]{3,12}[ \t]+)?)([^\s\"',;]+)")
# name=value, name = value, name: value and "name": "value" where the name says the value is a
# credential. The shared detector wants eight characters or more; a password is often shorter.
_ASSIGNED = re.compile(
    r"(?i)(?:password|passwd|passphrase|secret|tokens?|api[_-]?keys?|access[_-]?key|private[_-]?key"
    r"|(?<![a-z])pwd|(?<![a-z])pass)"
    r"(?:=|[ \t]+=[ \t]+|:[ \t]+|[\"']:[ \t]*)"
    rf"({_REF_ATOM}|\"[^\"\n]*\"|'[^'\n]*'|[^\s;,&'\"<>(){{}}\[\]]+)")
_SAFE_QUERY_VALUE = re.compile(r"^(?:true|false|on|off|yes|no|\d{1,6}|[a-z]{1,12})$", re.I)
# Characters that can repaint a terminal or hide text from a reader: C0 and C1 controls, and the
# invisible Unicode ones (soft hyphen, zero-width and bidirectional marks, line separators, tag
# characters, variation selectors). The last group is also how text is smuggled past a person.
_CONTROL = re.compile(
    "[\x00-\x1f\x7f-\x9f­؜ᅟᅠ឴឵᠋-᠏​-‏ -‮"
    "⁠-⁯ㅤ︀-️﻿ﾠ￹-￻\U000e0000-\U000e0fff]")
_TOKEN_TAIL = re.compile(r"[A-Za-z0-9+/=_~.%-]+$")
_WEB_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
_FLAG = re.compile(r"^--?[A-Za-z][\w.-]*$")
_FLAG_VALUE = re.compile(r"^(--?[A-Za-z][\w.-]*)=(.*)$", re.S)
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


def printable(text: str, max_len: int = 200) -> str:
    """Text from a configuration file with control characters made visible.

    A cloned repository's ``.mcp.json`` is somebody else's text: an escape sequence in a
    server name must not be able to repaint the terminal a report is read in.
    """
    return _CONTROL.sub("?", str(text))[:max_len]


def secretish_name(name: str) -> bool:
    """Does a variable, header, flag or parameter name say it holds a credential?"""
    for part in _NAME_SPLIT.split(name):
        word = part.lower()
        if word.endswith("s") and not word.endswith("ss"):
            word = word[:-1]            # tokens, keys, credentials
        if word in _SECRET_WORDS or word.endswith(_SECRET_ENDINGS):
            return True
    return False


def is_reference(value: str) -> bool:
    """``${VAR}``, ``${env:VAR}``, ``$VAR``, ``{env:VAR}``, ``${input:id}``, ``${{ secrets.X }}``.

    A reference with a long default (``${KEY:-sk-...}``) is not one: the default is a value.
    """
    if not _PURE_REFERENCE.match(value):
        return False
    return all(len(default) < 8 for default in _REF_DEFAULT.findall(value))


def referenced_names(value: str) -> list[str]:
    names: list[str] = []
    for m in _REF_NAMES.finditer(value):
        name = next((g for g in m.groups() if g), None)
        if name and name not in names and name not in _PATH_VARIABLES:
            names.append(name)
    return names


def literal_value(value: str) -> bool:
    """Is this a real value written into the file (not empty, a reference or a placeholder)?"""
    value = value[:4096]
    return not is_reference(value) and not _PLACEHOLDER.match(value)


def _mixed(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]", text)) and bool(re.search(r"\d", text))


def looks_random(token: str, *, dashed: bool = True) -> bool:
    """A long run of letters and digits with no words in it: a key, a hash, a UUID."""
    token = token[:4096]
    for m in _ALNUM_RUN.finditer(token):
        run = m.group(0)
        if _mixed(run) and shannon_entropy(run) >= 3.3:
            return True
    if dashed and _DASHED_TOKEN.match(token) and _mixed(token):
        digits = sum(ch.isdigit() for ch in token)
        return digits / len(token) >= 0.2 and shannon_entropy(token) >= 3.3
    return False


def value_is_secret(name: str, value: str) -> bool:
    """Does the shape of a literal value say it is a credential?"""
    value = value[:4096]    # the shape shows in the first few kilobytes; do not chew on megabytes
    if not literal_value(value):
        return False
    return bool(find_secrets(f"{name}={value}")) or bool(find_secrets(value)) or looks_random(value)


def _as_agents_read(url: str) -> str:
    """A URL the way the agents' own (WHATWG) parsers read it: in a web scheme a backslash is a slash.

    Python's parser would take ``https://evil.example\\@known.example/`` to be on ``known.example``;
    the agent connects to ``evil.example``. The scan must name the host the agent reaches.
    """
    scheme = url.split(":", 1)[0].strip().lower()
    return url.replace("\\", "/") if scheme in _WEB_SCHEMES else url


def url_host(url: str) -> str:
    try:
        return (urlsplit(_as_agents_read(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _replace_shapes(text: str) -> str:
    """Known credential shapes (tokens, keys, webhook URLs) replaced by their kind."""
    parts: list[str] = []
    pos = 0
    for hit in find_secrets(text):
        if hit.start < pos or "«" in hit.value:
            continue  # overlapping, or what is left of an earlier redaction
        parts += [text[pos:hit.start], f"«{hit.kind}»"]
        pos = hit.end
    return "".join(parts) + text[pos:]


def _secret_part(part: str) -> bool:
    """Is one path segment or query name token-like, as written or once its %-escapes are decoded?"""
    if not part:
        return False
    if looks_random(part) or find_secrets(part):
        return True
    plain = unquote(part) if "%" in part else part
    return plain != part and (looks_random(plain) or bool(find_secrets(plain)))


def _redact_query_pair(pair: str) -> str:
    name, equals, value = pair.partition("=")
    if not equals:      # a bare token has no name to judge it by: keep it only when it is plainly harmless
        return pair if not pair or is_reference(pair) or _SAFE_QUERY_VALUE.match(pair) else REDACTED
    plain = unquote_plus(value)
    keep = not value or is_reference(plain) or (
        not secretish_name(unquote_plus(name)) and bool(_SAFE_QUERY_VALUE.match(plain)))
    return f"{REDACTED if _secret_part(name) else name}={value if keep else REDACTED}"


def redact_url(url: str) -> str:
    """A URL without its credentials: no user info, no query values, no token-like path parts, no fragment."""
    if any(hit.kind.endswith("webhook") for hit in find_secrets(url)):
        return _replace_shapes(url)     # some URLs are secret as a whole
    url = _as_agents_read(url)
    bare = "://" not in url             # "host:port/path", "//host/path": an address written without a scheme
    try:
        parts = urlsplit("x://" + url.lstrip("/") if bare else url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return REDACTED
    prefix = ("//" if url.startswith("//") else "") if bare else f"{parts.scheme}://"
    netloc = parts.netloc
    if "@" in netloc:
        netloc = REDACTED + "@" + (f"[{host}]" if ":" in host else host) + (f":{port}" if port is not None else "")
    path = "/".join(REDACTED if _secret_part(seg) else seg for seg in parts.path.split("/"))
    pairs = [_redact_query_pair(pair) for pair in parts.query.split("&")] if parts.query else []
    return f"{prefix}{netloc}{path}" + ("?" + "&".join(pairs) if pairs else "")


def _redact_assigned(m: re.Match[str]) -> str:
    """``password=hunter2`` -> ``password=«redacted»``; references, placeholders and wildcards stay."""
    value = m.group(1)
    quoted = len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'"
    inner = value[1:-1] if quoted else value
    if "«" in inner or not re.search(r"[A-Za-z0-9]", inner) or not literal_value(inner):
        return m.group(0)
    quote = value[0] if quoted else ""
    return m.group(0)[: m.start(1) - m.start(0)] + quote + REDACTED + quote


def _redact_authorization(m: re.Match[str]) -> str:
    value = m.group(2)
    return m.group(0) if "«" in value or is_reference(value) else m.group(1) + REDACTED


def scrub(text: str, max_len: int = 600) -> str:
    """Free text from a config file with everything secret-shaped replaced.

    Idempotent, so it is safe to run again as a last pass over what is about to be stored.
    """
    if not text:
        return ""
    text = str(text)
    if len(text) > max_len * 4:
        text = text[: max_len * 4]
        text = _TOKEN_TAIL.sub("", text) or text    # never keep the first half of a token the cut went through
    text = _CONTROL.sub("?", text)
    text = _URL_IN_TEXT.sub(_redact_url_match, text)
    text = _BEARER.sub(lambda m: m.group(0) if is_reference(m.group(2)) else f"{m.group(1)} {REDACTED}", text)
    text = _AUTH_HEADER.sub(_redact_authorization, text)
    text = _replace_shapes(text)
    text = _ASSIGNED.sub(_redact_assigned, text)
    text = _CANDIDATE_TOKEN.sub(lambda m: REDACTED if looks_random(m.group(0)) else m.group(0), text)
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _redact_url_match(m: re.Match[str]) -> str:
    """Redact a URL found inside other text, leaving the punctuation that follows it."""
    url, tail = m.group(0), ""
    while url and url[-1] in ".,;:!?)]}>'\"":
        url, tail = url[:-1], url[-1] + tail
    return redact_url(url) + tail


def redact_argv(argv: Iterable[str]) -> str:
    """A command line for display: values of secret-named flags and assignments removed."""
    out: list[str] = []
    redact_next = False
    for raw in argv:
        arg = str(raw)
        if redact_next:
            redact_next = False
            out.append(arg if is_reference(arg) else REDACTED)
            continue
        m = _FLAG_VALUE.match(arg)
        if m and secretish_name(m.group(1)):
            out.append(f"{m.group(1)}=" + (m.group(2) if is_reference(m.group(2)) else REDACTED))
            continue
        if _FLAG.match(arg) and secretish_name(arg):
            redact_next = True
            out.append(arg)
            continue
        m = _ASSIGNMENT.match(arg)
        if m and m.group(2) and (secretish_name(m.group(1)) or value_is_secret(m.group(1), m.group(2))):
            out.append(f"{m.group(1)}=" + (m.group(2) if is_reference(m.group(2)) else REDACTED))
            continue
        out.append(scrub(arg))
    return scrub(" ".join(out), max_len=600)


def credentials_of(entry: ServerEntry, catalog_entry: Mapping[str, Any] | None = None) -> list[CredentialRef]:
    """The credentials a server entry names: variable, header and parameter NAMES only."""
    known = {str(n) for n in (catalog_entry or {}).get("credential_env") or []}
    found: dict[str, CredentialRef] = {}

    def add(name: str, kind: str, literal: bool, secret: bool) -> None:
        name = name.strip()[:120]
        if not re.fullmatch(r"[\w.:\- ]+", name) or looks_random(name, dashed=False) or find_secrets(name):
            return  # not a name: never risk storing a value under the wrong heading
        current = found.setdefault(name, CredentialRef(name, kind))
        current.literal = current.literal or literal
        current.secret = current.secret or secret

    def add_references(value: str, secret: bool) -> None:
        for ref in referenced_names(value):
            add(ref, "reference", False, secret or secretish_name(ref) or ref in known)

    for name, value in entry.env.items():
        secret = name in known or secretish_name(name) or value_is_secret(name, value)
        add(name, "env", literal_value(value), secret)
        add_references(value, secret)
    for name in entry.env_names:
        add(name, "env", False, name in known or secretish_name(name))
    for name, value in entry.headers.items():
        secret = secretish_name(name) or bool(_BEARER.search(value)) or value_is_secret(name, value)
        if secret or referenced_names(value):
            add(name, "header", literal_value(value) and secret, secret)
            add_references(value, secret)
    for text in [entry.url, *entry.argv]:
        if "://" not in text:
            continue
        try:
            parts = urlsplit(text)
            has_userinfo = parts.username is not None or parts.password is not None
        except ValueError:
            continue
        if has_userinfo and not is_reference(parts.password or parts.username or ""):
            add("url user info", "url-param" if text == entry.url else "argument", True, True)
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if secretish_name(key) or value_is_secret(key, value):
                add(key, "url-param", literal_value(value), True)
                add_references(value, True)
    previous = ""
    for arg in entry.argv:
        m = _FLAG_VALUE.match(arg) or _ASSIGNMENT.match(arg)
        if m and (secretish_name(m.group(1)) or m.group(1) in known or value_is_secret(m.group(1), m.group(2))):
            add(m.group(1).lstrip("-"), "argument", literal_value(m.group(2)), True)
            add_references(m.group(2), True)
        elif _FLAG.match(previous) and secretish_name(previous):
            add(previous.lstrip("-"), "argument", literal_value(arg), True)
            add_references(arg, True)
        elif previous in ("-e", "--env") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", arg):
            add(arg, "env", False, arg in known or secretish_name(arg))  # docker passes it through by name
        previous = arg
    return list(found.values())


# -- discovery: shared pieces ----------------------------------------------------------------

_REMOTE_TYPES = {
    "http": "http", "streamable-http": "http", "streamablehttp": "http", "streamable_http": "http",
    "remote": "http", "sse": "sse", "ws": "ws", "websocket": "ws",
}
_CLAUDE_MODES = ("default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions")


def normalize_server_name(name: str) -> str:
    """The server part of a tool name: characters outside ``[A-Za-z0-9_-]`` become ``_``."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def _string_map(value: Any) -> dict[str, str]:
    return {str(k): "" if v is None else str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _server_entry(agent: str, name: str, raw: dict[str, Any], scope: str, source: str) -> ServerEntry:
    """One server entry in the JSON shape most clients share (``command``/``args``/``env``/``url``)."""
    entry = ServerEntry(agent=agent, name=printable(name.strip(), 128), scope=scope, source_file=source)
    command, args = raw.get("command"), raw.get("args")
    if isinstance(command, list):  # one array holding the executable and its arguments
        entry.argv = [str(x) for x in command if isinstance(x, (str, int, float))]
    elif isinstance(command, str) and command.strip():
        extra = [str(a) for a in args if isinstance(a, (str, int, float))] if isinstance(args, list) else []
        entry.argv = [command.strip(), *extra]
    entry.declared_type = str(raw.get("type") or raw.get("transport") or "").strip().lower()
    url = next((raw[k].strip() for k in ("httpUrl", "url", "serverUrl")
                if isinstance(raw.get(k), str) and raw[k].strip()), "")
    remote = bool(url) and (not entry.argv or entry.declared_type in _REMOTE_TYPES or agent == "gemini-cli")
    if remote:
        entry.url, entry.argv = url, []
        guess = "sse" if agent == "gemini-cli" and not isinstance(raw.get("httpUrl"), str) else "http"
        entry.transport = _REMOTE_TYPES.get(entry.declared_type, guess)
    elif not entry.argv:
        entry.transport = "unknown"
        entry.notes.append("the entry has neither a command nor a url")
    entry.env = _string_map(raw.get("env") if isinstance(raw.get("env"), dict) else raw.get("environment"))
    entry.headers = _string_map(raw.get("headers"))
    if raw.get("disabled") is True or raw.get("enabled") is False:
        entry.enabled, entry.status = False, "disabled in the configuration file"
    if isinstance(raw.get("includeTools"), list):
        entry.include_tools = _str_list(raw["includeTools"])
    tools = raw.get("tools")
    if isinstance(tools, list) and "*" not in tools:  # an availability filter; ["*"] means all
        entry.include_tools = _str_list(tools)
        if not entry.include_tools:
            entry.enabled, entry.status = False, "its tools list is empty, so no tool is exposed"
    entry.exclude_tools = _str_list(raw.get("excludeTools")) + _str_list(raw.get("disabledTools"))
    if raw.get("trust") is True:
        entry.trust = "trust: true"
    for key in ("autoApprove", "alwaysAllow"):
        for tool in _str_list(raw.get(key)):
            entry.tool_permissions[tool] = ("allow", f"{key}: {tool}")
    return entry


def _server_entries(agent: str, servers: Any, scope: str, source: Path, cfg: AgentConfig) -> list[ServerEntry]:
    if servers is None:
        return []
    if not isinstance(servers, dict):
        cfg.problems.append(f"{source}: the list of MCP servers is not an object; skipped")
        return []
    out: list[ServerEntry] = []
    for name, raw in servers.items():
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(raw, dict):
            cfg.problems.append(f"{source}: server {scrub(name, 80)!r} is not an object; skipped")
            continue
        out.append(_server_entry(agent, name, raw, scope, str(source)))
    return out


def _mcp_servers_of(data: dict[str, Any] | None) -> Any:
    """The server map of an ``.mcp.json``-style file; some clients omit the ``mcpServers`` wrapper."""
    if not data:
        return None
    if "mcpServers" in data:
        return data["mcpServers"]
    looks_bare = all(isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values())
    return data if looks_bare else None


def _merge_servers(target: dict[str, ServerEntry], entries: Iterable[ServerEntry]) -> None:
    """Add entries a lower-precedence scope defines; the first definition of a name wins."""
    for entry in entries:
        winner = target.get(entry.name)
        if winner is None:
            target[entry.name] = entry
        else:
            winner.notes.append(f"also defined in {entry.scope} scope ({entry.source_file}); this definition wins")


# -- discovery: Claude Code ------------------------------------------------------------------


def _claude_project_entry(state: dict[str, Any], project: Path) -> dict[str, Any]:
    """The per-project record of ``~/.claude.json`` for this project (local-scope servers live there).

    The key is the directory Claude Code was started in. A scan from a subdirectory falls
    back to the enclosing directories, but never above the repository root.
    """
    projects = _as_dict(state.get("projects"))
    if not projects:
        return {}
    starts = [project]
    try:
        resolved = project.resolve()
    except OSError:
        resolved = project
    if resolved != project:
        starts.append(resolved)
    for start in starts:
        chain = [start, *start.parents]
        root = next((i for i, directory in enumerate(chain) if (directory / ".git").exists()), 0)
        for directory in chain[: root + 1]:     # outside a repository: the directory itself only
            for key in (str(directory), directory.as_posix()):
                if isinstance(projects.get(key), dict):
                    return projects[key]
    return {}


def _policy_matches(policies: list[dict[str, Any]], entry: ServerEntry) -> bool:
    """Does an ``allowedMcpServers`` / ``deniedMcpServers`` list name this server?"""
    for policy in policies:
        if policy.get("serverName") == entry.name:
            return True
        command = policy.get("serverCommand")
        if isinstance(command, list) and entry.argv and [str(c) for c in command] == entry.argv:
            return True
        pattern = policy.get("serverUrl")
        if isinstance(pattern, str) and entry.url and fnmatch.fnmatchcase(entry.url, pattern):
            return True
    return False


def _discover_claude_code(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("claude-code")
    config_dir = Path(env["CLAUDE_CONFIG_DIR"]).expanduser() if env.get("CLAUDE_CONFIG_DIR") else None
    state_path = (config_dir or home) / ".claude.json"
    state = _load_json(state_path, cfg) or {}
    record = _claude_project_entry(state, project)

    # Settings files, highest precedence first: managed, project local, shared project, user.
    files: list[tuple[str, Path]] = []
    if system is not None:
        files.append(("managed", system / "managed-settings.json"))
        try:
            files += [("managed", p) for p in sorted((system / "managed-settings.d").glob("*.json"))]
        except OSError:
            pass
    files += [
        ("local", project / ".claude" / "settings.local.json"),
        ("project", project / ".claude" / "settings.json"),
        ("user", (config_dir or home / ".claude") / "settings.json"),
    ]
    settings = [(scope, path, data) for scope, path in files if (data := _load_json(path, cfg)) is not None]

    for scope, path, data in settings:
        permissions = _as_dict(data.get("permissions"))
        for kind in ("deny", "ask", "allow"):
            cfg.rules += [PermissionRule(kind, text, str(path), scope) for text in _str_list(permissions.get(kind))]
    cfg.rules += [PermissionRule("allow", text, str(state_path), "local") for text in _str_list(record.get("allowedTools"))]
    _claude_default_mode(cfg, settings)

    servers: dict[str, ServerEntry] = {}
    managed_mcp = _load_json(system / "managed-mcp.json", cfg) if system is not None else None
    exclusive = isinstance((managed_mcp or {}).get("mcpServers"), dict)
    if exclusive:
        _merge_servers(servers, _server_entries(cfg.kind, managed_mcp["mcpServers"], "managed",
                                                system / "managed-mcp.json", cfg))
    for scope, path, data in settings:
        if scope == "managed":
            _merge_servers(servers, _server_entries(cfg.kind, data.get("managedMcpServers"), "managed", path, cfg))
    _merge_servers(servers, _server_entries(cfg.kind, record.get("mcpServers"), "local", state_path, cfg))
    mcp_json_path = project / ".mcp.json"
    project_servers = _mcp_servers_of(_load_json(mcp_json_path, cfg))
    _merge_servers(servers, _server_entries(cfg.kind, project_servers, "project", mcp_json_path, cfg))
    _merge_servers(servers, _server_entries(cfg.kind, state.get("mcpServers"), "user", state_path, cfg))

    switched_off = set(_str_list(record.get("disabledMcpServers")))
    rejected = set(_str_list(record.get("disabledMcpjsonServers")))
    approved = set(_str_list(record.get("enabledMcpjsonServers")))
    approve_all = False
    denied: list[dict[str, Any]] = []
    allowed: list[dict[str, Any]] | None = None
    for _scope, _path, data in settings:
        rejected |= set(_str_list(data.get("disabledMcpjsonServers")))
        approved |= set(_str_list(data.get("enabledMcpjsonServers")))
        approve_all = approve_all or data.get("enableAllProjectMcpServers") is True
        if isinstance(data.get("deniedMcpServers"), list):
            denied += [d for d in data["deniedMcpServers"] if isinstance(d, dict)]
        if isinstance(data.get("allowedMcpServers"), list):
            allowed = (allowed or []) + [d for d in data["allowedMcpServers"] if isinstance(d, dict)]

    for entry in servers.values():
        if not entry.enabled:
            pass  # "disabled" in the entry itself
        elif entry.declared_type == "sdk":
            entry.enabled, entry.status = False, "type sdk: only loaded inside an SDK host"
        elif entry.url and not entry.declared_type:
            entry.enabled, entry.status = False, "configuration error: url without type; Claude Code skips this entry"
        elif exclusive and entry.scope != "managed":
            entry.enabled, entry.status = False, "managed-mcp.json takes exclusive control; this server does not load"
        elif _policy_matches(denied, entry):
            entry.enabled, entry.status = False, "blocked by deniedMcpServers"
        elif allowed is not None and not _policy_matches(allowed, entry):
            entry.enabled, entry.status = False, "not in allowedMcpServers"
        elif entry.name in switched_off:
            entry.enabled, entry.status = False, "switched off with /mcp (disabledMcpServers)"
        elif entry.scope == "project":
            if entry.name in rejected:
                entry.enabled, entry.status = False, "rejected in the approval dialog (disabledMcpjsonServers)"
            elif approve_all or entry.name in approved:
                entry.status = "approved"
            else:
                entry.status = "pending approval; headless runs (claude -p) load it without asking"
    cfg.servers = list(servers.values())
    cfg.notes.append("Plugin-provided servers and claude.ai connectors are not in these files; "
                     "their tools appear here once a recorded session has used them.")
    return cfg


def _claude_default_mode(cfg: AgentConfig, settings: list[tuple[str, Path, dict[str, Any]]]) -> None:
    """``permissions.defaultMode``: the highest-precedence file that sets a usable value wins."""
    bypass_off = any(_as_dict(d.get("permissions")).get("disableBypassPermissionsMode") == "disable"
                     for _, _, d in settings)
    for scope, path, data in settings:
        mode = _as_dict(data.get("permissions")).get("defaultMode")
        if not isinstance(mode, str) or not mode:
            continue
        mode = "default" if mode == "manual" else mode
        if mode not in _CLAUDE_MODES:
            cfg.notes.append(f"{path}: unknown permissions.defaultMode {scrub(mode, 40)!r}; ignored")
        elif mode in ("auto", "bypassPermissions") and scope in ("project", "local"):
            cfg.notes.append(f"{path}: defaultMode {mode} does not take effect from a project file; ignored")
        elif mode == "bypassPermissions" and bypass_off:
            cfg.notes.append(f"{path}: defaultMode bypassPermissions is switched off by disableBypassPermissionsMode")
        else:
            cfg.permission_mode, cfg.permission_mode_source = mode, str(path)
            return


# -- discovery: the other agents ---------------------------------------------------------------


def _config_home(home: Path, env: Mapping[str, str]) -> Path:
    return Path(env["XDG_CONFIG_HOME"]).expanduser() if env.get("XDG_CONFIG_HOME") else home / ".config"


def _unique(pairs: Iterable[tuple[str, Path]]) -> list[tuple[str, Path]]:
    """Drop repeated paths (the same file reached through two conventions), keeping order."""
    seen: set[str] = set()
    out: list[tuple[str, Path]] = []
    for scope, path in pairs:
        if str(path) not in seen:
            seen.add(str(path))
            out.append((scope, path))
    return out


def _discover_claude_desktop(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("claude-desktop")
    servers: dict[str, ServerEntry] = {}
    for scope, path in _unique([
        ("user", home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        ("user", _config_home(home, env) / "Claude" / "claude_desktop_config.json"),
        ("user", home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"),
    ]):
        data = _load_json(path, cfg)
        if data:
            _merge_servers(servers, _server_entries(cfg.kind, data.get("mcpServers"), scope, path, cfg))
    for entry in servers.values():
        if entry.url and entry.enabled:
            entry.enabled, entry.status = False, "Claude Desktop starts local (stdio) servers only; a url entry is not used"
    cfg.servers = list(servers.values())
    cfg.notes.append("Tool approvals are kept by the app, not in a file; remote connectors belong to the account.")
    return cfg


def _discover_cursor(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("cursor")
    servers: dict[str, ServerEntry] = {}
    for scope, path in _unique([("project", project / ".cursor" / "mcp.json"), ("user", home / ".cursor" / "mcp.json")]):
        data = _load_json(path, cfg)
        if data:
            _merge_servers(servers, _server_entries(cfg.kind, data.get("mcpServers"), scope, path, cfg))
    cli_home = Path(env["CURSOR_CONFIG_DIR"]).expanduser() if env.get("CURSOR_CONFIG_DIR") else home / ".cursor"
    for scope, path in _unique([("project", project / ".cursor" / "cli.json"), ("user", cli_home / "cli-config.json")]):
        permissions = _as_dict((_load_json(path, cfg) or {}).get("permissions"))
        for kind in ("deny", "allow"):
            cfg.rules += [PermissionRule(kind, t, str(path), scope, "cursor") for t in _str_list(permissions.get(kind))]
    cfg.servers = list(servers.values())
    return cfg


def _discover_vscode(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("vscode")
    servers: dict[str, ServerEntry] = {}
    user_dirs = [
        _config_home(home, env) / "Code" / "User",
        home / "Library" / "Application Support" / "Code" / "User",
        home / "AppData" / "Roaming" / "Code" / "User",
    ]
    # The editor-managed format keeps servers under "servers" and allows comments.
    for scope, path in _unique([("project", project / ".vscode" / "mcp.json"),
                                *(("user", d / "mcp.json") for d in user_dirs)]):
        data = _load_json(path, cfg, lenient=True)
        if data:
            _merge_servers(servers, _server_entries(cfg.kind, data.get("servers"), scope, path, cfg))
    # The portable format (Copilot harness and Copilot CLI) uses "mcpServers".
    copilot_home = Path(env["COPILOT_HOME"]).expanduser() if env.get("COPILOT_HOME") else home / ".copilot"
    for scope, path in _unique([("project", project / ".github" / "mcp.json"), ("user", copilot_home / "mcp-config.json")]):
        portable = _mcp_servers_of(_load_json(path, cfg, lenient=True))
        _merge_servers(servers, _server_entries(cfg.kind, portable, scope, path, cfg))
    if not cfg.found:
        return cfg  # a bare .mcp.json or .vscode/settings.json does not show that this agent is in use
    shared = project / ".mcp.json"
    shared_servers = _mcp_servers_of(_load_json(shared, cfg, counts=False))
    _merge_servers(servers, _server_entries(cfg.kind, shared_servers, "project", shared, cfg))
    for path in [project / ".vscode" / "settings.json", *(d / "settings.json" for d in user_dirs)]:
        data = _load_json(path, cfg, lenient=True, counts=False)
        if data and data.get("chat.tools.global.autoApprove") is True and not cfg.permission_mode:
            cfg.permission_mode, cfg.permission_mode_source = "autoApprove", str(path)
    cfg.servers = list(servers.values())
    cfg.notes.append("Per-tool 'always allow' decisions are kept in VS Code's own state, not in a file.")
    return cfg


def _discover_windsurf(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("windsurf")
    devin = _config_home(home, env) / "devin"
    servers: dict[str, ServerEntry] = {}
    for scope, path in _unique([
        ("local", project / ".devin" / "mcp_config.local.json"),
        ("project", project / ".devin" / "mcp_config.json"),
        ("user", devin / "mcp_config.json"),
        ("user", home / "AppData" / "Roaming" / "devin" / "mcp_config.json"),
        ("user", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("user", home / ".codeium" / "windsurf-next" / "mcp_config.json"),
    ]):
        data = _load_json(path, cfg)
        if data:
            _merge_servers(servers, _server_entries(cfg.kind, data.get("mcpServers"), scope, path, cfg))
    for scope, path in _unique([
        ("local", project / ".devin" / "config.local.json"),
        ("project", project / ".devin" / "config.json"),
        ("user", devin / "config.json"),
    ]):
        data = _load_json(path, cfg)
        if data is None:
            continue
        _merge_servers(servers, _server_entries(cfg.kind, data.get("mcpServers"), scope, path, cfg))  # older releases
        permissions = _as_dict(data.get("permissions"))
        for kind in ("deny", "ask", "allow"):
            cfg.rules += [PermissionRule(kind, t, str(path), scope) for t in _str_list(permissions.get(kind))]
    cfg.servers = list(servers.values())
    return cfg


def _discover_gemini(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("gemini-cli")
    gemini_home = Path(env["GEMINI_CLI_HOME"]).expanduser() if env.get("GEMINI_CLI_HOME") else home
    servers: dict[str, ServerEntry] = {}
    layers: list[tuple[str, Path, dict[str, Any]]] = []
    for scope, path in _unique([("project", project / ".gemini" / "settings.json"),
                                ("user", gemini_home / ".gemini" / "settings.json")]):
        data = _load_json(path, cfg, lenient=True)
        if data is None:
            continue
        layers.append((scope, path, data))
        _merge_servers(servers, _server_entries(cfg.kind, data.get("mcpServers"), scope, path, cfg))

    def first(section: str, key: str) -> tuple[Any, str]:
        for _scope, path, data in layers:  # the project file overrides the user file
            value = _as_dict(data.get(section)).get(key)
            if value is not None:
                return value, str(path)
        return None, ""

    allowed, _ = first("mcp", "allowed")
    excluded, _ = first("mcp", "excluded")
    for entry in servers.values():
        if entry.enabled and entry.name in _str_list(excluded):
            entry.enabled, entry.status = False, "listed in mcp.excluded"
        elif entry.enabled and _str_list(allowed) and entry.name not in _str_list(allowed):
            entry.enabled, entry.status = False, "not in mcp.allowed"
    for key, kind in (("exclude", "deny"), ("allowed", "allow")):
        value, source = first("tools", key)
        cfg.rules += [PermissionRule(kind, t, source, "user", "gemini") for t in _str_list(value)]
    mode, source = first("general", "defaultApprovalMode")
    if isinstance(mode, str) and mode:
        cfg.permission_mode, cfg.permission_mode_source = scrub(mode, 40), source
    cfg.servers = list(servers.values())
    cfg.notes.append("Policy files (~/.gemini/policies/*.toml) are not read.")
    return cfg


_CODEX_APPROVAL = {"approve": "allow", "prompt": "ask"}


def _codex_entry(name: str, raw: dict[str, Any], scope: str, source: str) -> ServerEntry:
    entry = _server_entry("codex", name, raw, scope, source)
    entry.env_names += _str_list(raw.get("env_vars"))
    if isinstance(raw.get("bearer_token_env_var"), str):
        entry.env_names.append(raw["bearer_token_env_var"])
    entry.headers.update(_string_map(raw.get("http_headers")))
    entry.env_names += list(_string_map(raw.get("env_http_headers")).values())
    if isinstance(raw.get("enabled_tools"), list):
        entry.include_tools = _str_list(raw["enabled_tools"])
    entry.exclude_tools += _str_list(raw.get("disabled_tools"))
    default = raw.get("default_tools_approval_mode")
    if isinstance(default, str) and default in _CODEX_APPROVAL:
        entry.default_permission = (_CODEX_APPROVAL[default], f"default_tools_approval_mode = {default}")
    for tool, spec in _as_dict(raw.get("tools")).items():
        mode = _as_dict(spec).get("approval_mode")
        if isinstance(mode, str) and mode in _CODEX_APPROVAL:
            entry.tool_permissions[str(tool)] = (_CODEX_APPROVAL[mode], f"tools.{tool}.approval_mode = {mode}")
    return entry


def _discover_codex(home: Path, project: Path, env: Mapping[str, str], system: Path | None) -> AgentConfig:
    cfg = AgentConfig("codex")
    codex_home = Path(env["CODEX_HOME"]).expanduser() if env.get("CODEX_HOME") else home / ".codex"
    servers: dict[str, ServerEntry] = {}
    for scope, path in _unique([("project", project / ".codex" / "config.toml"), ("user", codex_home / "config.toml")]):
        data = _load_toml(path, cfg)
        if data is None:
            continue
        table = data.get("mcp_servers")
        if isinstance(table, dict):
            _merge_servers(servers, [_codex_entry(str(n), raw, scope, str(path)) for n, raw in table.items()
                                     if isinstance(raw, dict) and str(n).strip()])
        elif table is not None:
            cfg.problems.append(f"{path}: mcp_servers is not a table; skipped")
        policy = data.get("approval_policy")
        if isinstance(policy, str) and policy and not cfg.permission_mode:
            cfg.permission_mode, cfg.permission_mode_source = scrub(policy, 40), str(path)
        if isinstance(data.get("sandbox_mode"), str):
            cfg.notes.append(f"{path}: sandbox_mode = {scrub(data['sandbox_mode'], 40)}")
    cfg.servers = list(servers.values())
    return cfg


_DISCOVERERS = {
    "claude-code": _discover_claude_code,
    "claude-desktop": _discover_claude_desktop,
    "cursor": _discover_cursor,
    "vscode": _discover_vscode,
    "windsurf": _discover_windsurf,
    "gemini-cli": _discover_gemini,
    "codex": _discover_codex,
}


def discover(home: str | os.PathLike[str], project: str | os.PathLike[str], *,
             env: Mapping[str, str] | None = None, system: str | os.PathLike[str] | None = None,
             agents: Iterable[str] | None = None) -> list[AgentConfig]:
    """Read every known agent's configuration under ``home`` and ``project``.

    Nothing outside those two directories (and ``system``, when given) is opened, and
    ``env`` is the only source of location overrides such as ``CLAUDE_CONFIG_DIR``, so a
    test or a what-if scan never touches the real home directory.
    """
    home_dir, project_dir = Path(home), Path(project)
    system_dir = Path(system) if system is not None else None
    wanted = set(agents) if agents else None
    out: list[AgentConfig] = []
    for kind, discoverer in _DISCOVERERS.items():
        if wanted is not None and kind not in wanted:
            continue
        try:
            out.append(discoverer(home_dir, project_dir, dict(env or {}), system_dir))
        except Exception as exc:  # noqa: BLE001 - one agent's odd files must not hide the others
            broken = AgentConfig(kind, found=True, broken=True)
            broken.problems.append(f"{AGENT_NAMES[kind]}: its configuration could not be read ({type(exc).__name__})")
            out.append(broken)
    return out


# -- permission rules ----------------------------------------------------------------------------
# Rule syntax and evaluation order follow Claude Code: ``Tool`` or ``Tool(specifier)``;
# deny is checked first, then ask, then allow, and the first match in that order decides.
# Lists merge across settings files, so precedence between files only decides which
# file is named as the source.


@dataclass(frozen=True)
class ToolSpec:
    """A tool as permission rules see it."""

    agent: str
    name: str                   # exactly as the harness names it
    server: str | None = None   # normalised MCP server name; None for a built-in
    tool: str = ""              # the tool's own name on that server
    server_raw: str = ""        # the server name as written in the config file


@dataclass
class Permission:
    permission: str = "default"     # "allow" | "ask" | "deny" | "default"
    rule: str = ""                  # the rule that decided it, redacted
    source: str = ""                # the file that rule is in
    partial: list[str] = field(default_factory=list)     # "<kind> <rule>" for rules covering part of its use
    allow_specs: list[str] = field(default_factory=list)  # raw specifiers of partial allow rules (memory only)
    block_specs: list[str] = field(default_factory=list)  # raw specifiers of partial ask and deny rules on the tool


_RULE = re.compile(r"^\s*([^()\s][^()]*?)\s*(?:\((.*)\))?\s*$", re.S)
_CATCH_ALL = frozenset({"*", "**", ":*", "/**", "//**", "~/**"})
_READ_FAMILY = frozenset({"Read", "Grep", "Glob", "LS", "NotebookRead"})
_EDIT_FAMILY = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_AGENT_ALIASES = frozenset({"Agent", "Task"})
# Claude Code accepts a path specifier on these names but never matches it.
_SPECIFIER_NEVER_MATCHES = frozenset({"Write", "Grep", "Glob"})


def parse_rule(text: str) -> tuple[str, str | None]:
    """``Bash(curl:*)`` -> ``("Bash", "curl:*")``; ``mcp__github`` -> ``("mcp__github", None)``."""
    m = _RULE.match(text)
    if not m:
        return text.strip(), None
    specifier = m.group(2)
    return m.group(1).strip(), (specifier if specifier and specifier.strip() else None)


def _glob(pattern: str, text: str) -> bool:
    """``*`` matches any run of characters; nothing else is special.

    Matched by hand rather than as a regular expression: the pattern comes from a
    settings file that may be somebody else's, and a row of stars must not be able to
    make the scan crawl.
    """
    p = t = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and pattern[p] == text[t]:
            p += 1
            t += 1
        elif star >= 0:
            mark += 1
            p, t = star + 1, mark
        else:
            return False
    return all(ch == "*" for ch in pattern[p:])


def _match_claude(kind: str, name: str, spec: str | None, tool: ToolSpec) -> str | None:
    """How a Claude Code rule covers a tool: ``"full"``, ``"partial"`` or not at all."""
    if name == "*":
        return "full" if kind != "allow" and spec is None else None    # only deny and ask accept it
    if tool.server is not None:
        if name == "mcp__*":
            return "full" if kind != "allow" else None                 # an allow rule needs a literal server
        prefix = f"mcp__{tool.server}"
        if name != prefix and not (name.startswith(prefix + "__") and _glob(name[len(prefix) + 2:], tool.tool)):
            return None
        if spec is not None:
            return None if kind == "allow" else "partial"              # an MCP allow rule with (...) matches nothing
        return "full"
    if name.startswith("mcp__"):
        return None
    same = name == tool.name or (name in _AGENT_ALIASES and tool.name in _AGENT_ALIASES)
    family = (name == "Read" and tool.name in _READ_FAMILY) or (name == "Edit" and tool.name in _EDIT_FAMILY)
    if not (same or family):
        # Read and Edit deny rules also reach file commands inside the shell, best effort.
        return "partial" if tool.name == "Bash" and name in ("Read", "Edit") and kind != "allow" and spec else None
    if spec is None:
        return "full"
    if not family and name in _SPECIFIER_NEVER_MATCHES:
        return None
    if spec.strip() in _CATCH_ALL or (name == "WebFetch" and spec.strip() == "domain:*"):
        return "full"
    return "partial"


def _match_cursor(kind: str, name: str, spec: str | None, tool: ToolSpec) -> str | None:
    """Cursor CLI tokens: ``Shell(cmd)``, ``Read(glob)``, ``Write(glob)``, ``WebFetch(domain)``, ``Mcp(server:tool)``."""
    if name == "Mcp":
        if tool.server is None or spec is None:
            return None
        server_pattern, _, tool_pattern = spec.partition(":")
        on_server = _glob(server_pattern.strip(), tool.server) or _glob(server_pattern.strip(), tool.server_raw)
        return "full" if on_server and _glob(tool_pattern.strip() or "*", tool.tool) else None
    if tool.server is not None or name != tool.name:
        return None
    return "full" if spec is None or spec.strip() in _CATCH_ALL else "partial"


def _match_gemini(kind: str, name: str, spec: str | None, tool: ToolSpec) -> str | None:
    """Gemini CLI ``tools.allowed`` / ``tools.exclude``: a tool name, or ``name(command prefix)``."""
    if name != tool.name:
        return None
    return "full" if spec is None else "partial"


_MATCHERS = {"claude": _match_claude, "cursor": _match_cursor, "gemini": _match_gemini}


def evaluate_permission(tool: ToolSpec, rules: Iterable[PermissionRule]) -> Permission:
    """Apply an agent's allow / ask / deny rules to one tool.

    ``rules`` must be ordered highest-precedence file first. A rule that covers only part
    of what the tool can do (``Bash(curl:*)``, ``Read(./.env)``) never becomes the tool's
    permission; it is listed under ``partial``.
    """
    rules = list(rules)
    result = Permission()
    for kind in ("deny", "ask", "allow"):
        for rule in rules:
            if rule.kind != kind or len(rule.text) > MAX_RULE_CHARS:
                continue
            name, spec = parse_rule(rule.text)
            match = _MATCHERS.get(rule.dialect, _match_claude)(kind, name, spec, tool)
            if match == "full" and result.permission == "default":
                result.permission, result.rule, result.source = kind, scrub(rule.text, 200), rule.source
            elif match == "partial":
                entry = f"{kind} {scrub(rule.text, 200)}"
                if entry not in result.partial and len(result.partial) < 40:
                    result.partial.append(entry)
                if kind == "allow" and spec is not None:
                    result.allow_specs.append(spec)
                elif spec is not None and name == tool.name:
                    result.block_specs.append(spec)
    return result


# -- what happens when the tool is called ---------------------------------------------------------


@dataclass
class Gate:
    """The effect of permission rules *and* the agent's permission mode on one tool."""

    gate: str = "ask"           # "open" (runs unasked) | "ask" (a person approves) | "deny" (refused)
    reason: str = ""
    data: str = ""              # set when plain reads behave differently (a shell's read-only commands)
    open_partial: list[str] = field(default_factory=list)   # allow rules that open part of it, verbatim


_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "fish", "dash", "ksh", "pwsh", "powershell", "python", "python2", "python3", "node",
    "deno", "bun", "ruby", "perl", "php", "eval", "exec", "env", "xargs", "sudo", "npx", "uvx", "bunx",
    "busybox", "docker",
})
_PROBES = ("", " https://probe.example.test/x", " probe.example.test 443", " ./file user@probe.example.test:/tmp/x")
_UNATTENDED_MODES = frozenset({"bypasspermissions", "auto", "yolo", "never", "autoapprove", "full-auto"})


def _pattern_prefix(spec: str) -> tuple[str, bool]:
    """A command pattern as its fixed prefix, and whether anything may follow it."""
    prefix = spec.strip()
    for suffix in (":*", " *", "*"):
        if prefix.endswith(suffix):
            return prefix[: -len(suffix)].strip(), True
    return prefix, False


def pattern_covers(blocker: str, spec: str) -> bool:
    """Does an ask or deny pattern catch every command an allow pattern lets through?

    Ask and deny are checked before allow, so an allow pattern they cover opens nothing.
    """
    outer, outer_open = _pattern_prefix(blocker)
    inner, inner_open = _pattern_prefix(spec)
    if outer_open:
        return not outer or inner == outer or inner.startswith(outer + " ")
    return not inner_open and inner == outer


def shell_pattern_sends(spec: str) -> bool:
    """Can a command that a ``Bash(...)`` allow pattern covers send data off the machine?

    The pattern's fixed prefix is given to the shell analyser with a few probe
    arguments. A pattern that allows an interpreter or everything counts as yes.
    """
    prefix, _ = _pattern_prefix(spec)
    if not prefix or prefix.startswith("*"):
        return True
    program = os.path.basename(prefix.split()[0])
    if program in _INTERPRETERS:
        return True
    from .bashparse import analyze_bash  # imported late: the shell analyser is large

    for probe in _PROBES:
        try:
            if analyze_bash(prefix + probe).is_sink:
                return True
        except Exception:  # noqa: BLE001 - an unparsable pattern is treated as dangerous
            return True
    return False


def effective_gate(agent: AgentConfig, kind: str, permission: Permission, *, rule_name: str = "Bash") -> Gate:
    """Does a call run unasked, wait for a person, or get refused?

    ``kind`` is what sort of tool it is: ``shell``, ``read``, ``edit``, ``fetch``,
    ``search``, ``none`` (bookkeeping tools that never prompt), ``mcp`` or ``other``.
    """
    if permission.permission == "deny":
        return Gate("deny", f"deny rule {permission.rule}")
    if permission.permission == "ask":
        return Gate("ask", f"ask rule {permission.rule}")
    if permission.permission == "allow":
        return Gate("open", f"allow rule {permission.rule}")
    mode = agent.permission_mode
    if mode.lower() in _UNATTENDED_MODES:
        return Gate("open", f"permission mode {mode} runs calls without asking a person")
    if kind in ("read", "none"):
        return Gate("open", "runs without a prompt in every permission mode")
    if kind == "edit" and mode in ("acceptEdits", "auto_edit"):
        return Gate("open", f"permission mode {mode} applies file edits without asking")
    if agent.kind == "claude-code" and mode == "dontAsk":
        return Gate("deny", "dontAsk mode refuses calls that no rule pre-approves")
    if kind == "shell":
        sending = [spec for spec in permission.allow_specs if shell_pattern_sends(spec)
                   and not any(pattern_covers(blocker, spec) for blocker in permission.block_specs)]
        if sending:
            exact = [f"{rule_name}({spec})" for spec in sending]
            storable = all(scrub(text, 400) == text for text in exact)   # never keep a pattern that holds a secret
            return Gate("open", f"allow rule {scrub(exact[0], 200)} lets it send data without a prompt",
                        data="open", open_partial=exact if storable else [])
        return Gate("ask", "asks before commands that are not read-only", data="open")
    if agent.kind == "claude-desktop":
        return Gate("ask", "approvals are kept by the app and are not visible to a scan")
    return Gate("ask", "asks before each use unless a rule or the user approves it")


# -- which catalog entry a server is, and which tools it brings -------------------------------------


def _strip_version(token: str) -> str:
    """``@playwright/mcp@latest``, ``mcp-server-git==2026.11.11``, ``ghcr.io/x/y:v1`` without the version."""
    if "://" in token:
        return token
    token = token.split("==")[0]
    m = re.match(r"^(@?[^@]+)@[^/]+$", token)
    if m:
        token = m.group(1)
    head, sep, tail = token.rpartition("/")
    return head + sep + tail.split(":")[0] if ":" in tail else token


def _argument_urls(argv: Iterable[str]) -> list[str]:
    """URLs among the arguments: a wrapper such as ``mcp-remote`` names the real server there."""
    return [a for a in argv if re.match(r"^(?:https?|wss?)://", a)]


def identify_server(entry: ServerEntry, catalog: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """The catalog entry for a configured server, and what gave it away.

    Strongest evidence first, as the catalog's ``matching`` section lays out: URL host,
    then package or image name, then a command pattern, then the name the user chose.
    A package must equal a whole token of the command line: one package name can be
    the beginning of another (``mcp/git``, ``mcp/github``, ``mcp/gitlab``).
    """
    servers = [s for s in catalog.get("servers") or [] if isinstance(s, dict)]
    hosts = {url_host(u) for u in [entry.url, *_argument_urls(entry.argv)] if u} - {""}
    for server in servers:
        match = _as_dict(server.get("match"))
        for known in [*(match.get("url_hosts") or []), *(match.get("url_hosts_unverified") or [])]:
            known = str(known).lower()
            if known and any(host == known or host.endswith("." + known) for host in hosts):
                return server, "host"
    tokens = {_strip_version(a).lower() for a in entry.argv if "://" not in a}
    if entry.argv:
        tokens.add(os.path.basename(entry.argv[0]).lower())      # a binary named after its package
    tokens |= {t.replace("_", "-") for t in tokens}               # python -m mcp_server_fetch
    line = " ".join(entry.argv)
    for server in servers:
        match = _as_dict(server.get("match"))
        for package in [*(match.get("packages") or []), *(match.get("packages_unverified") or [])]:
            package = str(package).lower()
            if package and any(t == package or t.endswith("/" + package) for t in tokens):
                return server, "package"
        if any(str(pattern) in line for pattern in match.get("command_patterns") or [] if pattern):
            return server, "command"
    by_name = classify.match_server(entry.name, catalog=dict(catalog)) if entry.name else None
    return (by_name, "name") if by_name is not None else (None, "")


def _variant_matches(variant: str, evidence: str) -> bool:
    """Does a catalog variant label (``"korotovsky/slack-mcp-server"``) name what this entry runs?"""
    for key in re.findall(r"[@\w./-]{6,}", variant.lower()):
        for candidate in {key, key.rsplit("/", 1)[-1]}:
            if len(candidate) >= 8 and re.search(r"[-./@]", candidate) and candidate in evidence:
                return True
    return False


def _catalog_tools(catalog_entry: Mapping[str, Any], entry: ServerEntry) -> list[tuple[str, dict[str, Any] | None]]:
    """``(tool name, catalog record or None)`` for every tool the catalog knows on this server.

    Some catalog entries merge several implementations of one product. When the command
    line or URL names one of them, only its tools (and the shared ones) are kept.
    """
    tools = [t for t in catalog_entry.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    variants = {str(t["variant"]) for t in tools if t.get("variant")}
    if variants:
        evidence = " ".join([*entry.argv, entry.url]).lower()
        chosen = {v for v in variants if _variant_matches(v, evidence)}
        if chosen:
            tools = [t for t in tools if not t.get("variant") or str(t["variant"]) in chosen]
    out: list[tuple[str, dict[str, Any] | None]] = [(str(t["name"]), t) for t in tools]
    seen = {name for name, _ in out}
    out += [(str(n), None) for n in catalog_entry.get("other_tools") or [] if str(n) not in seen]
    return out


def _catalog_record(catalog_entry: Mapping[str, Any] | None, tool: str) -> dict[str, Any] | None:
    wanted = re.sub(r"[^a-z0-9]+", "", tool.lower())
    for record in (catalog_entry or {}).get("tools") or []:
        if isinstance(record, dict) and re.sub(r"[^a-z0-9]+", "", str(record.get("name", "")).lower()) == wanted:
            return record
    return None


def _config_flags(entry: ServerEntry, flags: Iterable[Any]) -> list[str]:
    """Which of a catalog entry's risk-relevant settings appear in this server entry."""
    off = ("", "0", "false", "no", "off")
    line = " ".join(entry.argv)
    found: list[str] = []
    for flag in flags:
        f = str(flag)
        if not f:
            continue
        hit = (
            any(a == f or a.startswith(f + "=") or (f.endswith("=") and a.startswith(f)) for a in entry.argv)
            or (" " in f and f in line)
            or any(k == f and str(v).strip().lower() not in off for k, v in entry.env.items())
            or any(k.lower() == f.lower() and v.strip().lower() not in off for k, v in entry.headers.items())
            or ((f.startswith("/") or f.endswith("=")) and f in entry.url)
        )
        if hit and f not in found:
            found.append(f)
    return found


def mcp_tool_name(agent: str, server: str, tool: str) -> str:
    """The name an agent harness gives an MCP tool. Gemini CLI documents a single underscore."""
    return f"mcp_{server}_{tool}" if agent == "gemini-cli" else f"mcp__{server}__{tool}"


def _classify(catalog_entry: Mapping[str, Any] | None, tool: str, description: str, schema: dict | None,
              catalog: Mapping[str, Any]) -> ToolLabels:
    """Capability labels from ``classify``, pinned to the server ``identify_server`` found."""
    narrow = {"servers": [catalog_entry] if catalog_entry else [], "heuristics": catalog.get("heuristics") or {}}
    server = str(catalog_entry.get("id")) if catalog_entry else "unlisted"
    return classify.classify_tool(f"mcp__{server}__{tool}", description, schema, catalog=narrow)


# Built-in tools: (kind, what the gate needs to know). Names for agents other than Claude
# Code map to the Claude Code tool with the same capability; True marks a documented name.
_CLAUDE_KIND = {
    "Bash": "shell", "Read": "read", "NotebookRead": "read", "Glob": "read", "Grep": "read", "LS": "read",
    "Write": "edit", "Edit": "edit", "MultiEdit": "edit", "NotebookEdit": "edit",
    "WebFetch": "fetch", "WebSearch": "search", "Skill": "other", "SlashCommand": "other",
    "ReadMcpResourceTool": "other",
}
_OTHER_BUILTINS: dict[str, dict[str, tuple[str, str, bool]]] = {
    "cursor": {"Shell": ("Bash", "shell", True), "Read": ("Read", "read", True),
               "Write": ("Write", "edit", True), "WebFetch": ("WebFetch", "fetch", True)},
    "gemini-cli": {"run_shell_command": ("Bash", "shell", True), "read_file": ("Read", "read", False),
                   "write_file": ("Write", "edit", False), "web_fetch": ("WebFetch", "fetch", False),
                   "google_web_search": ("WebSearch", "search", False)},
    "codex": {"shell": ("Bash", "shell", False), "apply_patch": ("Write", "edit", False),
              "web_search": ("WebSearch", "search", False)},
    "vscode": {"runInTerminal": ("Bash", "shell", False), "readFile": ("Read", "read", False),
               "editFiles": ("Write", "edit", False), "fetch": ("WebFetch", "fetch", False)},
    "windsurf": {"run_command": ("Bash", "shell", False), "read_file": ("Read", "read", False),
                 "write_to_file": ("Write", "edit", False), "read_url_content": ("WebFetch", "fetch", False),
                 "search_web": ("WebSearch", "search", False)},
    "claude-desktop": {},
}
_BUILTIN_SOURCE_SCOPE = {"Bash": "public", "BashOutput": "public", "WebFetch": "public", "WebSearch": "public"}


def builtin_tools(agent: str) -> list[tuple[str, ToolLabels, str, str]]:
    """``(name, labels, kind, source scope)`` for the tools an agent ships with."""
    out: list[tuple[str, ToolLabels, str, str]] = []
    if agent == "claude-code":
        for name, labels in classify.BUILTIN_TOOLS.items():
            out.append((name, ToolLabels(**labels.__dict__), _CLAUDE_KIND.get(name, "none"),
                        _BUILTIN_SOURCE_SCOPE.get(name, "")))
        return out
    for name, (twin, kind, documented) in _OTHER_BUILTINS.get(agent, {}).items():
        labels = ToolLabels(**classify.BUILTIN_TOOLS[twin].__dict__)
        labels.confidence = 0.8 if documented else 0.6
        labels.notes = (f"built-in {kind} tool of {AGENT_NAMES.get(agent, agent)}"
                        + ("" if documented else "; the tool name is assumed, the capability is not"))
        out.append((name, labels, kind, _BUILTIN_SOURCE_SCOPE.get(twin, "")))
    return out


# -- the rows of one agent ---------------------------------------------------------------------------


@dataclass
class ToolRow:
    spec: ToolSpec
    labels: ToolLabels
    kind: str = "mcp"               # "shell" | "read" | "edit" | "fetch" | "search" | "none" | "mcp" | "other"
    origin: str = "catalog"         # "builtin" | "catalog" | "observed" | "introspect"
    source_scope: str = ""          # who can plant text in its results: "public" | "org" | "local" | ""
    description: str = ""
    permission: Permission = field(default_factory=Permission)
    gate: Gate = field(default_factory=Gate)
    observed: bool = False
    calls: int = 0

    @property
    def id(self) -> str:
        return f"{self.spec.agent}::{self.spec.name}"


@dataclass
class ServerRow:
    entry: ServerEntry
    id: str = ""
    catalog_entry: dict[str, Any] | None = None
    catalog_match: str = ""         # "host" | "package" | "command" | "name" | ""
    credentials: list[CredentialRef] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    risk_reducing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    tools: list[ToolRow] = field(default_factory=list)
    fresh_listing: bool = False     # the tool list was asked from the server during this scan


@dataclass
class ExistingTool:
    """A ``Tool`` node already in the graph, and how many recorded calls point at it."""

    props: dict[str, Any]
    calls: int = 0


_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:/\-]{1,128}")


def _server_row(cfg: AgentConfig, entry: ServerEntry, catalog: Mapping[str, Any],
                listed: list[dict[str, Any]] | None) -> ServerRow:
    """A configured server with the tools it is known to provide.

    ``listed`` is the answer of a live ``tools/list`` when the user asked for one; it
    replaces the catalog's list, because it is what the server really exposes.
    """
    found, how = identify_server(entry, catalog)
    row = ServerRow(entry=entry, id=entry.id, catalog_entry=found, catalog_match=how)
    row.credentials = credentials_of(entry, found)
    if found:
        row.risk_flags = _config_flags(entry, found.get("risk_increasing_config") or [])
        row.risk_reducing = _config_flags(entry, found.get("risk_reducing_config") or [])
    read_only = next((f for f in row.risk_reducing if re.search(r"read[-_]?only", f, re.I)), "")

    specs: list[tuple[str, dict[str, Any] | None, str, dict | None, str]] = []
    if listed is not None:
        for item in listed:
            name = item.get("name")
            if isinstance(name, str) and _TOOL_NAME.fullmatch(name):     # a server's answer is not trusted text
                schema = item.get("inputSchema") if isinstance(item.get("inputSchema"), dict) else None
                specs.append((name, _catalog_record(found, name), str(item.get("description") or ""), schema, "introspect"))
    elif found is not None:
        specs = [(name, record, "", None, "catalog") for name, record in _catalog_tools(found, entry)]
        if how == "name":
            row.notes.append("recognised by its name only: the tool list is the catalog's and may not be this "
                             "server's (tainttrail scan --introspect asks the server itself)")
    else:
        row.notes.append("not in the catalog: its tools are unknown until a session uses them or "
                         "`tainttrail scan --introspect` asks the server")

    server = normalize_server_name(entry.name)
    left_out = 0
    for name, record, description, schema, origin in specs:
        if (entry.include_tools is not None and name not in entry.include_tools) or name in entry.exclude_tools:
            continue
        labels = _classify(found, name, description, schema, catalog)
        if origin == "introspect" and labels.source in ("heuristic", "default"):
            labels.source = "introspect"
            labels.confidence = max(labels.confidence, 0.6) if labels.capabilities() else 0.3
            labels.notes = "judged from the name, description and parameters the server reported"
        elif how == "name" and labels.source == "catalog":
            labels.confidence = min(labels.confidence, 0.6)
        writes_only = (labels.external_sink or labels.local_write) and not (labels.untrusted_input or labels.private_data)
        if read_only and origin != "introspect" and writes_only:
            left_out += 1
            continue
        row.tools.append(ToolRow(
            spec=ToolSpec(cfg.kind, mcp_tool_name(cfg.kind, server, name), server, name, entry.name),
            labels=labels, origin=origin, source_scope=str((record or {}).get("source_scope") or ""),
            description=scrub(description, 300),
        ))
    if left_out:
        row.notes.append(f"read-only mode ({read_only}): {left_out} tools that only write were left out")
    return row


def _attach_observed(cfg: AgentConfig, rows: list[ServerRow], existing: Mapping[str, ExistingTool],
                     catalog: Mapping[str, Any]) -> None:
    """Add tools that recorded sessions called but no configuration file explains.

    Plugin servers, claude.ai connectors and ``--mcp-config`` servers never appear in
    the files a scan reads; the session graph is the only place they show up.
    """
    have = {tool.id for row in rows for tool in row.tools}
    by_server = {normalize_server_name(row.entry.name): row for row in rows if row.entry.transport != "builtin"}
    builtin = rows[0]
    for tool_id, prior in sorted(existing.items()):
        if tool_id in have or prior.calls <= 0:
            continue
        name = str(prior.props.get("name") or tool_id.split("::", 1)[-1])
        server, tool = classify.parse_tool_name(name)
        if server is None:
            labels = classify.classify_tool(name) if cfg.kind == "claude-code" else ToolLabels()
            builtin.tools.append(ToolRow(ToolSpec(cfg.kind, name), labels, kind=_CLAUDE_KIND.get(name, "other"),
                                         origin="observed"))
            continue
        row = by_server.get(server)
        if row is None:
            entry = ServerEntry(cfg.kind, server, "observed", "", transport="unknown")
            row = _server_row(cfg, entry, catalog, [])     # no listing: only what was seen is added
            row.notes = ["seen in recorded sessions but not declared in a scanned file "
                         "(a plugin, a claude.ai connector or --mcp-config)"]
            row.credentials = []
            rows.append(row)
            by_server[server] = row
        record = _catalog_record(row.catalog_entry, tool)
        row.tools.append(ToolRow(
            spec=ToolSpec(cfg.kind, name, server, tool, row.entry.name),
            labels=_classify(row.catalog_entry, tool, "", None, catalog), origin="observed",
            source_scope=str((record or {}).get("source_scope") or ""),
        ))


def build_agent(cfg: AgentConfig, existing: Mapping[str, ExistingTool], catalog: Mapping[str, Any], *,
                introspected: Mapping[str, list[dict[str, Any]]] | None = None,
                include_observed: bool = True) -> list[ServerRow]:
    """Everything a scan will write for one agent: servers, tools, labels, permissions, gates."""
    builtin = ServerRow(ServerEntry(cfg.kind, BUILTIN_SERVER, "builtin", "", transport="builtin"))
    for name, labels, kind, source_scope in builtin_tools(cfg.kind):
        builtin.tools.append(ToolRow(ToolSpec(cfg.kind, name), labels, kind=kind, origin="builtin",
                                     source_scope=source_scope))
    rows = [builtin]
    remembered = _remembered_listings(existing)
    for entry in cfg.servers:
        listed = (introspected or {}).get(entry.id)
        row = _server_row(cfg, entry, catalog, listed if listed is not None else remembered.get(entry.id))
        row.fresh_listing = listed is not None
        if listed is None and entry.id in remembered:
            row.notes.append("its tool list is what an earlier `tainttrail scan --introspect` got from the server")
        rows.append(row)
    if include_observed:
        _attach_observed(cfg, rows, existing, catalog)

    server_ids: set[str] = set()
    tool_ids: set[str] = set()
    for row in rows:
        row.id = row.entry.id
        suffix = 2
        while row.id in server_ids:     # a server literally named "builtin", or the same name twice
            row.id, suffix = f"{row.entry.id}~{suffix}", suffix + 1
        server_ids.add(row.id)
        unique: list[ToolRow] = []
        for tool in row.tools:
            if tool.id in tool_ids:
                continue                 # two server names that spell the same tool prefix: the first keeps it
            tool_ids.add(tool.id)
            unique.append(tool)
            _finish_tool(cfg, row, tool, existing.get(tool.id))
        if len(unique) != len(row.tools):
            row.notes.append("some tool names collide with another server's; those tools are listed there")
        row.tools = unique
    return rows


def _remembered_listings(existing: Mapping[str, ExistingTool]) -> dict[str, list[dict[str, Any]]]:
    """Tool lists an earlier ``--introspect`` scan got from servers, rebuilt from the graph.

    A server's real tool list stays the best answer until the server is asked again,
    so a plain scan keeps it instead of falling back to the catalog or to nothing.
    """
    listings: dict[str, list[dict[str, Any]]] = {}
    for _tool_id, prior in sorted(existing.items()):
        props = prior.props
        if props.get("origin") == "introspect" and props.get("server_id") and props.get("tool"):
            listings.setdefault(str(props["server_id"]), []).append(
                {"name": str(props["tool"]), "description": str(props.get("description") or "")})
    return listings


def _finish_tool(cfg: AgentConfig, row: ServerRow, tool: ToolRow, prior: ExistingTool | None) -> None:
    """Carry over what the graph already knows about a tool, then apply rules and mode."""
    if prior is not None:
        tool.calls = prior.calls
        tool.observed = prior.calls > 0 or bool(prior.props.get("observed"))
        sticky = prior.props.get("label_source") in STICKY_LABEL_SOURCES
        # A fresh answer from the server replaces what an earlier answer led to, nothing else.
        if sticky and not (row.fresh_listing and prior.props.get("label_source") == "introspect"):
            tool.labels = ToolLabels.from_props(prior.props)
            tool.source_scope = str(prior.props.get("source_scope") or tool.source_scope)
    permission = evaluate_permission(tool.spec, cfg.rules)
    if permission.permission == "default" and tool.spec.server is not None:
        entry = row.entry
        local = (entry.tool_permissions.get(tool.spec.tool)
                 or (("allow", entry.trust) if entry.trust else None)
                 or entry.default_permission)
        if local is not None:
            permission.permission, permission.rule, permission.source = local[0], scrub(local[1], 200), entry.source_file
    tool.permission = permission
    tool.gate = effective_gate(cfg, tool.kind, permission, rule_name=tool.spec.name)


def _existing_tools(store: Store, kind: str) -> dict[str, ExistingTool]:
    rows = store.run(
        "MATCH (t:Tool) WHERE t.id STARTS WITH $prefix "
        "RETURN t.id AS id, properties(t) AS props, COUNT { (:ToolCall)-[:INVOKES]->(t) } AS calls",
        {"prefix": kind + "::"},
    )
    return {row["id"]: ExistingTool(dict(row["props"]), int(row["calls"] or 0)) for row in rows}


def _server_props(row: ServerRow, now: int) -> dict[str, Any]:
    entry = row.entry
    wrapped = next(iter(_argument_urls(entry.argv)), "")
    return {
        "name": entry.name, "agent": entry.agent, "transport": entry.transport, "scope": entry.scope,
        "command": redact_argv(entry.argv) if entry.argv else "",
        "url": scrub(redact_url(entry.url), 300) if entry.url else "",
        "url_host": url_host(entry.url) or url_host(wrapped),
        "catalog_id": str(row.catalog_entry.get("id")) if row.catalog_entry else "",
        "catalog_match": row.catalog_match, "source_file": entry.source_file,
        "enabled": bool(entry.enabled), "status": scrub(entry.status, 200),
        "notes": scrub("; ".join([*entry.notes, *row.notes]), 600),
        "risk_flags": [scrub(f, 80) for f in row.risk_flags],
        "risk_reducing": [scrub(f, 80) for f in row.risk_reducing],
        "tools": len(row.tools), "scanned_at": now,
    }


def _tool_props(row: ServerRow, tool: ToolRow, now: int) -> dict[str, Any]:
    props = tool.labels.to_props()
    props.update(
        name=tool.spec.name, agent_kind=tool.spec.agent, server=tool.spec.server or BUILTIN_SERVER,
        server_id=row.id, tool=tool.spec.tool or tool.spec.name, kind=tool.kind, origin=tool.origin,
        description=tool.description, source_scope=tool.source_scope, observed=bool(tool.observed),
        permission=tool.permission.permission, permission_rule=tool.permission.rule,
        permission_source=tool.permission.source, permission_partial=list(tool.permission.partial),
        gate=tool.gate.gate, gate_reason=scrub(tool.gate.reason, 300),
        gate_data=tool.gate.data or None,       # None removes a value an earlier scan left behind
        open_partial=list(tool.gate.open_partial), scanned_at=now,
    )
    return props


# -- writing the scan ---------------------------------------------------------------------------------


@dataclass
class ScanResult:
    """What a scan found, in plain values that print and serialise as they are."""

    home: str
    project: str
    scanned_at: int
    agents: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def note_problems(self, problems: Iterable[str]) -> None:
        """Add file problems once each: a shared file is read on behalf of several agents."""
        for problem in problems:
            problem = scrub(problem, 400)
            if problem not in self.problems:
                self.problems.append(problem)

    def to_dict(self) -> dict[str, Any]:
        return {"home": self.home, "project": self.project, "scanned_at": self.scanned_at,
                "agents": self.agents, "warnings": self.warnings, "problems": self.problems}


def _summarise(cfg: AgentConfig, rows: list[ServerRow], result: ScanResult) -> dict[str, Any]:
    servers = []
    for row in rows:
        entry = row.entry
        credentials = [{"name": c.name, "kind": c.kind, "literal": c.literal, "secret": c.secret}
                       for c in row.credentials]
        servers.append({
            "id": row.id, "name": entry.name, "transport": entry.transport, "scope": entry.scope,
            "catalog_id": str(row.catalog_entry.get("id")) if row.catalog_entry else "",
            "catalog_match": row.catalog_match, "enabled": bool(entry.enabled), "status": scrub(entry.status, 200),
            "source_file": entry.source_file, "command": redact_argv(entry.argv) if entry.argv else "",
            "url_host": url_host(entry.url) or url_host(next(iter(_argument_urls(entry.argv)), "")),
            "tools": len(row.tools),
            "sources": sum(t.labels.untrusted_input for t in row.tools),
            "data": sum(t.labels.private_data for t in row.tools),
            "sinks": sum(t.labels.external_sink for t in row.tools),
            "open": sum(t.gate.gate == "open" for t in row.tools),
            "credentials": credentials, "risk_flags": list(row.risk_flags), "risk_reducing": list(row.risk_reducing),
            "notes": [scrub(n, 300) for n in [*entry.notes, *row.notes]],
        })
        for cred in row.credentials:
            if cred.literal and cred.secret:
                result.warnings.append(
                    f"{cfg.name}, server {entry.name}: the value of {cred.name} is written into "
                    f"{entry.source_file} in clear text. Keep it in the environment and reference it instead.")
        if entry.transport not in ("builtin",) and entry.enabled and not row.tools:
            result.warnings.append(
                f"{cfg.name}, server {entry.name}: no tools are known for it, so it is missing from the path "
                "analysis. `tainttrail scan --introspect --yes` asks the server for its tool list.")
        guessed = [t for t in row.tools if t.permission.permission == "allow" and t.spec.server is not None
                   and t.labels.source in ("heuristic", "default", "introspect")]
        if guessed and entry.enabled:
            rules = sorted({t.permission.rule for t in guessed})
            result.warnings.append(
                f"{cfg.name}, server {entry.name}: {len(guessed)} tools run without a prompt "
                f"({', '.join(rules[:3])}) although what they can do is a guess, not a catalog entry. "
                f"`tainttrail tools --server {entry.name}` lists them; `tainttrail tools set` corrects one.")
    result.note_problems(cfg.problems)
    return {
        "kind": cfg.kind, "name": cfg.name, "config_paths": list(cfg.config_paths),
        "permission_mode": cfg.permission_mode, "permission_mode_source": cfg.permission_mode_source,
        "servers": servers, "tools": sum(len(row.tools) for row in rows),
        "problems": [scrub(p, 400) for p in cfg.problems], "notes": [scrub(n, 300) for n in cfg.notes],
    }


def _replace_agent(store: Store, cfg: AgentConfig, rows: list[ServerRow], existing: Mapping[str, ExistingTool],
                   now: int, present: bool, home: str = "", project: str = "") -> None:
    """Swap the stored scan of one agent for the new one. Runs inside the caller's transaction.

    Server and credential nodes are rebuilt from nothing. ``Tool`` nodes are different:
    recorded calls point at them (``ToolCall-[:INVOKES]->Tool``) and a person or a model
    may have corrected their labels, so a tool is only deleted when neither is the case.
    A tool that is kept without being part of the new scan is marked as detached.
    """
    prefix = cfg.kind + "/"
    store.write("MATCH (s:Server) WHERE s.id STARTS WITH $prefix "
                "OPTIONAL MATCH (s)-[:HOLDS]->(c:Credential) DETACH DELETE s, c", {"prefix": prefix})
    store.write("MATCH (c:Credential) WHERE c.id STARTS WITH $prefix DETACH DELETE c", {"prefix": prefix})
    new_ids = {tool.id for row in rows for tool in row.tools}
    gone = [tool_id for tool_id in existing if tool_id not in new_ids]
    stale = [tool_id for tool_id in gone
             if existing[tool_id].calls == 0 and existing[tool_id].props.get("label_source") not in ("user", "llm")]
    if stale:
        store.write("UNWIND $ids AS id MATCH (t:Tool {id: id}) DETACH DELETE t", {"ids": stale})
    detached = sorted(set(gone) - set(stale))
    if detached:
        store.write("UNWIND $ids AS id MATCH (t:Tool {id: id}) "
                    "SET t.origin = 'detached', t.server_id = null, t.gate = null, t.gate_data = null",
                    {"ids": detached})
    if not present:
        # Nothing configures this agent any more. Keep the node only if sessions hang off it.
        store.write("MATCH (a:Agent {id: $id}) WHERE NOT EXISTS { (:Session)-[:BY]->(a) } DETACH DELETE a",
                    {"id": cfg.kind})
        store.write("MATCH (a:Agent {id: $id}) SET a.config_paths = [], a.scanned_at = null, "
                    "a.permission_mode = null, a.permission_mode_source = null, a.problems = [], a.notes = []",
                    {"id": cfg.kind})
        return

    store.write("MERGE (a:Agent {id: $id}) SET a += $props", {"id": cfg.kind, "props": {
        "kind": cfg.kind, "name": cfg.name, "config_paths": list(cfg.config_paths),
        "permission_mode": cfg.permission_mode, "permission_mode_source": cfg.permission_mode_source,
        "problems": [scrub(p, 400) for p in cfg.problems], "notes": [scrub(n, 300) for n in cfg.notes],
        "scanned_at": now, "home": home, "project": project,
    }})
    store.write(
        "MATCH (a:Agent {id: $agent}) UNWIND $rows AS r "
        "CREATE (s:Server {id: r.id}) SET s += r.props CREATE (a)-[:CONNECTS]->(s)",
        {"agent": cfg.kind, "rows": [{"id": row.id, "props": _server_props(row, now)} for row in rows]},
    )
    credentials = [
        {"sid": row.id, "id": f"{row.id}#{cred.name}",
         "props": {"name": cred.name, "kind": cred.kind, "literal": cred.literal, "secret": cred.secret}}
        for row in rows for cred in row.credentials
    ]
    if credentials:
        store.write(
            "UNWIND $rows AS r MATCH (s:Server {id: r.sid}) "
            "CREATE (c:Credential {id: r.id}) SET c += r.props CREATE (s)-[:HOLDS]->(c)",
            {"rows": credentials},
        )
    tools = [
        {"id": tool.id, "sid": row.id, "props": _tool_props(row, tool, now), "caps": tool.labels.capabilities(),
         "source": tool.labels.source, "confidence": float(tool.labels.confidence)}
        for row in rows for tool in row.tools
    ]
    for start in range(0, len(tools), 500):
        batch = tools[start:start + 500]
        store.write("UNWIND $rows AS r MERGE (t:Tool {id: r.id}) SET t += r.props", {"rows": batch})
        store.write("UNWIND $rows AS r MATCH (s:Server {id: r.sid}) MATCH (t:Tool {id: r.id}) "
                    "CREATE (s)-[:PROVIDES]->(t)", {"rows": batch})
        store.write("UNWIND $rows AS r MATCH (t:Tool {id: r.id})-[h:HAS_CAPABILITY]->() DELETE h", {"rows": batch})
        store.write(
            "UNWIND $rows AS r MATCH (t:Tool {id: r.id}) UNWIND r.caps AS cap "
            "MATCH (k:Capability {name: cap}) "
            "CREATE (t)-[:HAS_CAPABILITY {source: r.source, confidence: r.confidence}]->(k)",
            {"rows": batch},
        )


def write_scan(store: Store, configs: Iterable[AgentConfig], *, home: str = "", project: str = "",
               catalog: Mapping[str, Any] | None = None, include_observed: bool = True,
               introspected: Mapping[str, list[dict[str, Any]]] | None = None,
               now: int | None = None) -> ScanResult:
    """Write discovered configurations into the graph, replacing each agent's earlier scan.

    All of it happens in one transaction: a reader never sees half of an old map and
    half of a new one, and a failure leaves the previous scan in place.
    """
    catalog = catalog or classify.load_catalog()
    now = int(time.time() * 1000) if now is None else now
    result = ScanResult(home=home, project=project, scanned_at=now)
    with store.transaction():
        for cfg in configs:
            if cfg.broken:      # keep whatever an earlier scan stored; say what went wrong
                result.note_problems(cfg.problems)
                continue
            existing = _existing_tools(store, cfg.kind)
            seen_in_sessions = include_observed and any(prior.calls > 0 for prior in existing.values())
            present = cfg.found or seen_in_sessions
            rows = build_agent(cfg, existing, catalog, introspected=introspected,
                               include_observed=include_observed) if present else []
            _replace_agent(store, cfg, rows, existing, now, present, home, project)
            if present:
                result.agents.append(_summarise(cfg, rows, result))
    return result


def scan(store: Store, *, home: str | os.PathLike[str], project: str | os.PathLike[str],
         env: Mapping[str, str] | None = None, system: str | os.PathLike[str] | None = None,
         agents: Iterable[str] | None = None, include_observed: bool = True,
         introspected: Mapping[str, list[dict[str, Any]]] | None = None,
         catalog: Mapping[str, Any] | None = None, now: int | None = None) -> ScanResult:
    """Discover agent configurations under ``home`` and ``project`` and write them to the graph."""
    configs = discover(home, project, env=env, system=system, agents=agents)
    return write_scan(store, configs, home=str(home), project=str(project), catalog=catalog,
                      include_observed=include_observed, introspected=introspected, now=now)


# -- asking a server for its tools (only with --introspect --yes) --------------------------------------


class IntrospectError(RuntimeError):
    """A server could not be started or did not answer ``tools/list`` in time."""


_EXPAND = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?::-([^{}]*))?\}")


def _expand(value: str, environ: Mapping[str, str]) -> str:
    """``${VAR}`` and ``${VAR:-default}`` filled in from the environment, as the agent would."""
    return _EXPAND.sub(lambda m: environ.get(m.group(1), m.group(2) or ""), value)


def introspect_server(entry: ServerEntry, *, timeout: float = 10.0, environ: Mapping[str, str] | None = None,
                      cwd: str | None = None) -> list[dict[str, Any]]:
    """Start a stdio MCP server, ask it for its tools, and stop it again.

    Speaks newline-delimited JSON-RPC 2.0 (``initialize``, ``notifications/initialized``,
    ``tools/list``). The server's own output is never stored: only the tool list returns.
    """
    import queue
    import subprocess
    import threading

    from . import __version__

    if entry.transport != "stdio" or not entry.argv:
        raise IntrospectError("only local (stdio) servers can be asked for their tools")
    environ = dict(os.environ if environ is None else environ)
    env = {**environ, **{k: _expand(v, environ) for k, v in entry.env.items()}}
    argv = [_expand(a, environ) for a in entry.argv]
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, cwd=cwd, start_new_session=True)
    except (OSError, ValueError) as exc:
        raise IntrospectError(f"could not start: {type(exc).__name__}") from exc

    lines: "queue.Queue[bytes | None]" = queue.Queue(maxsize=2000)

    def pump() -> None:
        try:
            for raw in iter(lambda: proc.stdout.readline(1_048_576), b""):  # type: ignore[union-attr]
                try:
                    lines.put_nowait(raw)
                except queue.Full:
                    pass                # a server flooding its output: drop, never buffer without bound
        except (OSError, ValueError):
            pass                        # the pipe was closed under us
        finally:
            try:
                lines.put_nowait(None)
            except queue.Full:
                pass

    threading.Thread(target=pump, daemon=True).start()
    deadline = time.monotonic() + max(0.1, timeout)

    def send(message: dict[str, Any]) -> None:
        try:
            proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")  # type: ignore[union-attr]
            proc.stdin.flush()  # type: ignore[union-attr]
        except OSError as exc:
            raise IntrospectError("the server closed its input") from exc

    def reply(request_id: int) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IntrospectError(f"no answer within {timeout:g} s")
            try:
                raw = lines.get(timeout=remaining)
            except queue.Empty:
                raise IntrospectError(f"no answer within {timeout:g} s") from None
            if raw is None:
                raise IntrospectError("the server exited before answering")
            try:
                message = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue    # log lines on stdout are not ours to interpret
            if isinstance(message, dict) and message.get("id") == request_id:
                if isinstance(message.get("error"), dict):
                    raise IntrospectError("the server answered with an error")
                return _as_dict(message.get("result"))

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "tainttrail", "version": __version__}}})
        reply(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[dict[str, Any]] = []
        cursor: Any = None
        for page in range(50):
            send({"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list",
                  "params": {"cursor": cursor} if cursor else {}})
            result = reply(2 + page)
            tools += [t for t in result.get("tools") or [] if isinstance(t, dict)][: 2000 - len(tools)]
            cursor = result.get("nextCursor")
            if not cursor or len(tools) >= 2000:
                break
        return tools
    finally:
        _stop(proc)


def _stop(proc: Any) -> None:
    """End a server we started, and everything it started.

    The process is signalled before its pipes are closed: a reader thread blocked on
    the pipe holds the stream's lock, and closing first would wait for the server to
    exit by itself.
    """
    import signal
    import subprocess

    try:
        if proc.stdin is not None:
            proc.stdin.close()      # a well-behaved server leaves when its input ends
    except OSError:
        pass
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is not None:
            break
        try:
            os.killpg(proc.pid, sig)
        except (OSError, AttributeError):
            try:
                proc.terminate() if sig == signal.SIGTERM else proc.kill()
            except OSError:
                break
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            continue
    try:
        if proc.stdout is not None:
            proc.stdout.close()
    except OSError:
        pass


def introspection_targets(configs: Iterable[AgentConfig]) -> list[ServerEntry]:
    """The servers ``--introspect`` would start: enabled, local, with a command."""
    return [e for cfg in configs for e in cfg.servers if e.enabled and e.transport == "stdio" and e.argv]


# -- reading and correcting labels (tainttrail tools) ----------------------------------------------------

_TOOLS_QUERY = """
MATCH (t:Tool)
OPTIONAL MATCH (s:Server)-[:PROVIDES]->(t)
RETURN t.id AS id, properties(t) AS props, s.id AS server_id, s.name AS server_name,
       coalesce(s.enabled, true) AS enabled, COUNT { (:ToolCall)-[:INVOKES]->(t) } AS calls
ORDER BY id
"""
_SINK_SCOPES = ("public", "org", "private")
_SOURCE_SCOPES = ("public", "org", "local")
_TRUE, _FALSE = ("true", "yes", "on", "1"), ("false", "no", "off", "0")


def list_tools(store: Store, *, agent: str | None = None, server: str | None = None,
               capability: str | None = None) -> list[dict[str, Any]]:
    """Every tool in the capability map with its labels, permission and gate."""
    out = []
    for row in store.run(_TOOLS_QUERY):
        props = row["props"]
        tool_agent = str(props.get("agent_kind") or row["id"].split("::", 1)[0])
        if agent and tool_agent != agent:
            continue
        if server and server not in (row["server_name"], props.get("server")):
            continue
        if capability and not props.get(capability):
            continue
        out.append({
            "id": row["id"], "name": props.get("name") or row["id"].split("::", 1)[-1], "agent": tool_agent,
            "server": row["server_name"] or props.get("server") or "", "attached": row["server_id"] is not None,
            "server_enabled": bool(row["enabled"]),
            **{cap: bool(props.get(cap)) for cap in CAPABILITY_NAMES},
            "label_source": props.get("label_source") or "default",
            "label_confidence": float(props.get("label_confidence") or 0.0),
            "sink_scope": props.get("sink_scope") or "", "source_scope": props.get("source_scope") or "",
            "permission": props.get("permission") or "default", "permission_rule": props.get("permission_rule") or "",
            "permission_source": props.get("permission_source") or "",
            "permission_partial": list(props.get("permission_partial") or []),
            "gate": props.get("gate") or "", "gate_reason": props.get("gate_reason") or "",
            "notes": props.get("notes") or "", "calls": int(row["calls"] or 0),
        })
    return out


def parse_assignments(items: Iterable[str]) -> dict[str, Any]:
    """``external_sink=true sink_scope=public`` as a dict. Raises ValueError with a usable message."""
    changes: dict[str, Any] = {}
    for item in items:
        key, sep, value = item.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key:
            raise ValueError(f"expected KEY=VALUE, got {item!r}")
        if key in CAPABILITY_NAMES:
            if value.lower() not in (*_TRUE, *_FALSE):
                raise ValueError(f"{key} takes true or false, not {value!r}")
            changes[key] = value.lower() in _TRUE
        elif key in ("sink_scope", "source_scope"):
            allowed = _SINK_SCOPES if key == "sink_scope" else _SOURCE_SCOPES
            if value.lower() not in (*allowed, "none", ""):
                raise ValueError(f"{key} takes one of {', '.join(allowed)} or none, not {value!r}")
            changes[key] = "" if value.lower() in ("none", "") else value.lower()
        elif key == "notes":
            changes[key] = scrub(value, 300)
        else:
            raise ValueError(f"unknown key {key!r}; use one of {', '.join(CAPABILITY_NAMES)}, sink_scope, "
                             "source_scope, notes")
    if not changes:
        raise ValueError("nothing to set; give at least one KEY=VALUE, for example external_sink=true")
    return changes


def _resolve_tool(store: Store, name: str, agent: str | None) -> tuple[str, dict[str, Any] | None]:
    """The id of the tool a name refers to, and its stored properties if it exists."""
    rows = store.run("MATCH (t:Tool {name: $name}) RETURN t.id AS id, properties(t) AS props ORDER BY id", {"name": name})
    if agent:
        rows = [r for r in rows if r["id"].startswith(agent + "::")]
    if len(rows) > 1:
        agents = ", ".join(r["id"].split("::", 1)[0] for r in rows)
        raise ValueError(f"{name} exists for several agents ({agents}); say which with --agent")
    if rows:
        return rows[0]["id"], dict(rows[0]["props"])
    return f"{agent or 'claude-code'}::{name}", None


def _write_labels(store: Store, tool_id: str, name: str, labels: ToolLabels, extra: dict[str, Any]) -> None:
    server, _tool = classify.parse_tool_name(name)
    with store.transaction():
        store.write(
            "MERGE (t:Tool {id: $id}) "
            "ON CREATE SET t.name = $name, t.agent_kind = $agent, t.server = $server, t.observed = false, "
            "              t.permission = 'default' "
            "SET t += $props",
            {"id": tool_id, "name": name, "agent": tool_id.split("::", 1)[0], "server": server or BUILTIN_SERVER,
             "props": {**labels.to_props(), **extra}},
        )
        store.write("MATCH (t:Tool {id: $id})-[h:HAS_CAPABILITY]->() DELETE h", {"id": tool_id})
        store.write(
            "MATCH (t:Tool {id: $id}) UNWIND $caps AS cap MATCH (k:Capability {name: cap}) "
            "CREATE (t)-[:HAS_CAPABILITY {source: $source, confidence: $confidence}]->(k)",
            {"id": tool_id, "caps": labels.capabilities(), "source": labels.source,
             "confidence": float(labels.confidence)},
        )


def set_tool_labels(store: Store, name: str, changes: Mapping[str, Any], *, agent: str | None = None) -> dict[str, Any]:
    """Correct what a tool is labelled as able to do. The result is kept as a user label:
    later scans and the guard use it instead of the built-in tables."""
    tool_id, props = _resolve_tool(store, name, agent)
    if props is None and not _TOOL_NAME.fullmatch(name):
        raise ValueError(f"{printable(name, 80)!r} does not look like a tool name")
    labels = ToolLabels.from_props(props) if props is not None else classify.classify_tool(name)
    for cap in CAPABILITY_NAMES:
        if cap in changes:
            setattr(labels, cap, bool(changes[cap]))
    if "sink_scope" in changes:
        labels.sink_scope = changes["sink_scope"] or None
    if "notes" in changes:
        labels.notes = str(changes["notes"])
    labels.source, labels.confidence = "user", 1.0
    extra = {"source_scope": changes["source_scope"]} if "source_scope" in changes else {}
    _write_labels(store, tool_id, name, labels, extra)
    return {"id": tool_id, "name": name, "created": props is None, **labels.to_props(), **extra}


def reset_tool_labels(store: Store, name: str, *, agent: str | None = None) -> dict[str, Any]:
    """Drop a user label: the tool goes back to what the tables say (a scan refines it)."""
    tool_id, props = _resolve_tool(store, name, agent)
    if props is None:
        raise ValueError(f"no tool named {name} in the graph")
    labels = classify.classify_tool(name)
    _write_labels(store, tool_id, name, labels, {})
    return {"id": tool_id, "name": name, "created": False, **labels.to_props()}


# -- commands --------------------------------------------------------------------------------------------


def tolerant_output() -> None:
    """Never let a character the terminal cannot encode (the « » around a redaction) abort a report."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def default_system_dir() -> Path:
    """Where Claude Code looks for managed (administrator) settings on this platform."""
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if sys.platform.startswith("win"):
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClaudeCode"
    return Path("/etc/claude-code")


def _short(path: str, home: str, project: str) -> str:
    """A path as a person would say it: ``./`` for the project, ``~`` for the home directory."""
    for base, mark in ((project, "."), (home, "~")):
        base = base.rstrip("/\\")
        if base and (path == base or path.startswith(base + os.sep) or path.startswith(base + "/")):
            return mark + path[len(base):].replace(os.sep, "/")
    return path


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", metavar="DIR", help="project directory to scan (default: this project)")
    parser.add_argument("--home", metavar="DIR",
                        help="home directory to scan (default: yours). With this option nothing outside "
                             "DIR and the project is read, and environment overrides are ignored")
    parser.add_argument("--agent", action="append", choices=AGENT_KINDS, metavar="KIND",
                        help="scan only this agent; repeat for several (" + ", ".join(AGENT_KINDS) + ")")
    parser.add_argument("--introspect", action="store_true",
                        help="start each local MCP server and ask it for its real tool list (needs --yes)")
    parser.add_argument("--yes", action="store_true", help="confirm that --introspect may start the servers")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS",
                        help="how long --introspect waits for one server (default 10)")
    parser.add_argument("--no-observed", action="store_true",
                        help="leave out tools that only recorded sessions know about")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    from .report import paint, use_color

    tolerant_output()
    home_given = bool(getattr(args, "home", None))
    home = Path(args.home).expanduser() if home_given else Path.home()
    project = Path(args.path).expanduser() if getattr(args, "path", None) else cfg.root
    for option, directory in (("--home", home), ("--path", project)):
        if not directory.is_dir():
            print(f"tainttrail scan: {option} {directory} is not a directory", file=sys.stderr)
            return 2
    # An explicit --home is a what-if: read nothing that the caller did not point at.
    env = {} if home_given else dict(os.environ)
    system = None if home_given else default_system_dir()
    configs = discover(home, project, env=env, system=system, agents=getattr(args, "agent", None))

    introspected: dict[str, list[dict[str, Any]]] | None = None
    notices: list[str] = []
    if getattr(args, "introspect", False):
        targets = introspection_targets(configs)
        if not getattr(args, "yes", False):
            print("tainttrail scan --introspect would start these commands and ask each for its tools:",
                  file=sys.stderr)
            for entry in targets:
                print(f"  {entry.agent}/{entry.name}: {redact_argv(entry.argv)}", file=sys.stderr)
            print("Nothing was started. Run again with --yes to allow it.", file=sys.stderr)
            return 2
        introspected = {}
        for entry in targets:
            print(f"starting {entry.agent}/{entry.name}: {redact_argv(entry.argv)}", file=sys.stderr)
            try:
                introspected[entry.id] = introspect_server(entry, timeout=getattr(args, "timeout", 10.0),
                                                           cwd=str(project))
                notices.append(f"{entry.agent}/{entry.name}: the server listed {len(introspected[entry.id])} tools")
            except IntrospectError as exc:
                notices.append(f"{entry.agent}/{entry.name}: not introspected ({exc}); the catalog list is used")

    try:
        with open_store(cfg) as store:
            result = write_scan(store, configs, home=str(home), project=str(project), introspected=introspected,
                                include_observed=not getattr(args, "no_observed", False))
            summary = _path_summary(store)
    except StoreError as exc:
        print(f"tainttrail scan: {exc}", file=sys.stderr)
        return 1
    result.warnings = notices + result.warnings

    if getattr(args, "json", False):
        print(json.dumps({**result.to_dict(), "paths": summary}, indent=1, sort_keys=True))
        return 0
    print(render_scan(result, summary, color=use_color(), paint=paint))
    return 0


def _path_summary(store: Store) -> dict[str, Any] | None:
    """Toxic-path totals for the scan report; None when the path module is unavailable."""
    try:
        from . import paths

        report = paths.find_paths(store, limit=1)
    except Exception:  # noqa: BLE001 - the scan itself succeeded; the summary is a courtesy
        return None
    top = report.paths[0] if report.paths else None
    return {"total": report.total, "open": report.open, "gated": report.gated,
            "top_score": top.score if top else 0, "top": top.sentence if top else ""}


def render_scan(result: ScanResult, summary: Mapping[str, Any] | None, *, color: bool = False,
                paint: Any = None) -> str:
    """The scan as terminal text."""
    paint = paint or (lambda text, *styles, color=True: text)
    short = lambda p: _short(p, result.home, result.project)  # noqa: E731
    lines = [paint("TaintTrail scan", "bold", color=color),
             f"  project  {result.project}", f"  home     {result.home}", ""]
    if not result.agents:
        lines += ["No agent configuration was found under these directories.", ""]
    for agent in result.agents:
        mode = agent["permission_mode"] or "not set"
        where = f" (from {short(agent['permission_mode_source'])})" if agent["permission_mode_source"] else ""
        lines.append(paint(agent["name"], "bold", color=color) + f"   permission mode: {mode}{where}")
        files = "  ".join(short(p) for p in agent["config_paths"]) or "none"
        lines.append(paint(f"  files  {files}", "dim", color=color))
        width = max([len("(built-in)"), *(len(s["name"]) for s in agent["servers"])]) + 2
        lines.append(paint(f"  {'server':<{width}}{'transport':<10}{'scope':<9}{'catalog':<20}"
                           f"{'tools':>5}{'source':>8}{'data':>6}{'sink':>6}{'unasked':>9}  status", "dim", color=color))
        for server in agent["servers"]:
            status = server["status"] if server["enabled"] else "OFF: " + (server["status"] or "disabled")
            name = "(built-in)" if server["transport"] == "builtin" else server["name"]
            row = (f"  {name:<{width}}{server['transport']:<10}{server['scope']:<9}"
                   f"{(server['catalog_id'] or '-'):<20}{server['tools']:>5}{server['sources']:>8}"
                   f"{server['data']:>6}{server['sinks']:>6}{server['open']:>9}  {status}")
            lines.append(paint(row, "dim", color=color) if not server["enabled"] else row)
        for server in agent["servers"]:
            for cred in server["credentials"]:
                if cred["literal"] and cred["secret"]:
                    how = paint("value written in the file", "bright_red", color=color)
                elif cred["kind"] == "reference":
                    how = "referenced"
                else:
                    how = "by name"
                lines.append(f"    credential  {server['name']}: {cred['name']} ({cred['kind']}, {how})")
            for flag in server["risk_flags"]:
                lines.append("    " + paint(f"risk  {server['name']}: {flag} widens what the server can reach",
                                             "yellow", color=color))
            for note in server["notes"]:
                lines.append(paint(f"    note  {server['name']}: {note}", "dim", color=color))
        for note in agent["notes"]:
            lines.append(paint(f"    note  {note}", "dim", color=color))
        lines.append("")
    if result.warnings:
        lines.append(paint("Warnings", "bold", color=color))
        for warning in result.warnings:     # paths inside the sentences, said the short way too
            for base, mark in ((result.project, "."), (result.home, "~")):
                if base.rstrip("/\\"):
                    warning = warning.replace(base.rstrip("/\\") + "/", mark + "/")
            lines.append(f"  - {warning}")
        lines.append("")
    if result.problems:
        lines.append(paint("Files that could not be used", "bold", color=color))
        lines += [f"  - {short(p)}" for p in result.problems]
        lines.append("")
    if summary is not None:
        if summary["total"]:
            lines.append(paint("Toxic paths", "bold", color=color)
                         + f"  {summary['total']:,} (untrusted source -> private data -> outside), "
                         f"{summary['open']:,} of them with no approval on the way out; top score {summary['top_score']}")
            lines.append("  `tainttrail paths` lists them. `tainttrail fix` proposes the smallest change that breaks them.")
        else:
            lines.append("No toxic path: no agent has an untrusted source, private data and a way out at once.")
    return "\n".join(lines).rstrip() + "\n"


def add_tools_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", nargs="?", choices=("list", "set", "reset"), default="list",
                        help="list (default), set NAME KEY=VALUE..., or reset NAME")
    parser.add_argument("name", nargs="?", help="tool name for set and reset, e.g. mcp__github__create_issue")
    parser.add_argument("assignments", nargs="*", metavar="KEY=VALUE",
                        help="for set: " + ", ".join(f"{c}=true|false" for c in CAPABILITY_NAMES)
                             + ", sink_scope=public|org|private|none, source_scope=public|org|local|none, notes=TEXT")
    parser.add_argument("--agent", choices=AGENT_KINDS, metavar="KIND", help="which agent's tool")
    parser.add_argument("--server", metavar="NAME", help="list only this server's tools")
    parser.add_argument("--capability", choices=CAPABILITY_NAMES, metavar="CAP",
                        help="list only tools with this capability (" + ", ".join(CAPABILITY_NAMES) + ")")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")


def cmd_tools(args: argparse.Namespace, cfg: Config) -> int:
    from .report import paint, use_color

    tolerant_output()
    action = getattr(args, "action", None) or "list"
    name = getattr(args, "name", None)
    as_json = getattr(args, "json", False)
    try:
        if action == "list":
            if name:
                print(f"tainttrail tools: unexpected argument {name!r}; to change a tool use "
                      "`tainttrail tools set NAME KEY=VALUE`", file=sys.stderr)
                return 2
            try:
                store = open_store(cfg, read_only=True).open()
            except StoreMissing:
                rows = []       # nothing recorded or scanned yet
            else:
                with store:
                    rows = list_tools(store, agent=getattr(args, "agent", None), server=getattr(args, "server", None),
                                      capability=getattr(args, "capability", None))
            print(json.dumps(rows, indent=1, sort_keys=True) if as_json
                  else render_tools(rows, color=use_color(), paint=paint), end="" if not as_json else "\n")
            return 0
        if not name:
            print(f"tainttrail tools {action}: which tool? Give its name, e.g. mcp__github__create_issue",
                  file=sys.stderr)
            return 2
        with open_store(cfg) as store:
            if action == "set":
                changed = set_tool_labels(store, name, parse_assignments(getattr(args, "assignments", None) or []),
                                          agent=getattr(args, "agent", None))
            else:
                changed = reset_tool_labels(store, name, agent=getattr(args, "agent", None))
    except ValueError as exc:
        print(f"tainttrail tools: {exc}", file=sys.stderr)
        return 2
    except StoreError as exc:
        print(f"tainttrail tools: {exc}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(changed, indent=1, sort_keys=True))
        return 0
    caps = ", ".join(c for c in CAPABILITY_NAMES if changed.get(c)) or "no capability"
    if action == "set":
        print(f"{changed['id']}: now labelled {caps} (label source: user)."
              + (" The tool was not in the graph and has been added." if changed["created"] else ""))
        print("Scans and the guard keep this label. `tainttrail tools reset " + name + "` removes it.")
    else:
        print(f"{changed['id']}: back to the built-in label ({caps}). Run `tainttrail scan` to refine it.")
    return 0


def render_tools(rows: list[dict[str, Any]], *, color: bool = False, paint: Any = None) -> str:
    """Tools as a table: capabilities, permission, gate, and where the labels came from."""
    paint = paint or (lambda text, *styles, color=True: text)
    if not rows:
        return "No tools in the graph yet. Run `tainttrail scan` first.\n"
    width = min(64, max(len(r["name"]) for r in rows)) + 2
    letters = (("untrusted_input", "U"), ("private_data", "P"), ("external_sink", "S"),
               ("local_write", "W"), ("code_exec", "X"))
    lines = [paint("U untrusted input  P private data  S external sink  W local write  X code execution",
                   "dim", color=color)]
    group = None
    for row in sorted(rows, key=lambda r: (r["agent"], r["server"], r["name"])):
        if (row["agent"], row["server"]) != group:
            group = (row["agent"], row["server"])
            state = "" if row["attached"] else "  (not in the current configuration)"
            state = state or ("" if row["server_enabled"] else "  (server is off)")
            lines += ["", paint(f"{row['agent']}  {row['server'] or '(no server)'}{state}", "bold", color=color),
                      paint(f"  {'tool':<{width}}UPSWX  {'permission':<11}{'gate':<6}{'labels':<16}scope",
                            "dim", color=color)]
        caps = "".join(letter if row[cap] else "-" for cap, letter in letters)
        gate_style = {"open": ("bright_red",), "deny": ("green",), "ask": ("yellow",)}.get(row["gate"], ())
        scope = "/".join(x for x in (row["source_scope"] and f"from {row['source_scope']}",
                                     row["sink_scope"] and f"to {row['sink_scope']}") if x)
        label = f"{row['label_source']} {row['label_confidence']:.1f}"
        name = row["name"] if len(row["name"]) <= width - 2 else row["name"][: width - 3] + "~"
        extra = f"  {row['calls']} calls" if row["calls"] else ""
        partial = f"  partly: {'; '.join(row['permission_partial'][:3])}" if row["permission_partial"] else ""
        lines.append(f"  {name:<{width}}{caps}  {row['permission']:<11}"
                     + paint(f"{row['gate'] or '-':<6}", *gate_style, color=color)
                     + f"{label:<16}{scope}{extra}{partial}")
    return "\n".join(lines) + "\n"
