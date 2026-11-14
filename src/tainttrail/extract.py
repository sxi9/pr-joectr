"""Reading text the way the guard needs it read.

Four jobs, all on plain strings:

* **entities** - the hosts, URLs, files, repositories, addresses and environment
  variables a piece of text names;
* **secrets** - credentials in the text, found by shape;
* **fingerprints** - keyed hashes of secrets, long tokens and lines, so that the same
  text can be recognised later in a tool call's arguments without keeping it;
* **injection score** - how much the text reads like instructions aimed at an agent.

Fingerprints are the evidence layer. ``content_chunks`` is run on what enters the
agent's context, ``carried_fingerprints`` on what a tool call is about to send, and the
recorder joins the two in the graph. The second also looks through base64, hex and
percent-encoding, because that is how copied data is usually wrapped.
"""

from __future__ import annotations


import base64
import binascii
import hashlib
import hmac
import math
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import unquote, unquote_plus, urlsplit

from .config import normalize_path
from .model import ChunkRef, EntityRef

# -- entities ----------------------------------------------------------------------------------

_URL = re.compile(r"""\b(?:https?|wss?|ftp|sftp|ssh|git)://[^\s<>"'`\\\x00-\x1f]+""", re.I)
_TRAILING = ".,;:!?)]}>'\"*"
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w-])")
_SCP_REPO = re.compile(r"(?<![\w.-])(?:[\w.-]+@)([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,24}):([\w.-]+(?:/[\w.-]+)+?)(?:\.git)?(?![\w/-])")
_BARE_HOST = re.compile(r"(?<![\w@/.:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w(=-])(?!\.[a-z])", re.I)
_IPV4 = re.compile(r"(?<![\w.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\w.])")
_ENV_REF = re.compile(
    r"""\$\{?([A-Z][A-Z0-9_]{2,})\}?"""
    r"""|process\.env\.([A-Za-z_][A-Za-z0-9_]{2,})"""
    r"""|(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\s*\(\s*|ENV\[\s*|getenv\s*\(\s*)['"]([A-Za-z_][A-Za-z0-9_]{2,})['"]""")
_ABS_PATH = re.compile(r"""(?<![\w.:/@%+~-])((?:~|/(?:etc|home|Users|tmp|var|usr|opt|root|proc|srv|mnt|private|Library))(?:/[\w.@%+~-]+)+/?)""")
_DOT_PATH = re.compile(r"""(?<![\w.:/@%+~-])(\.{1,2}/[\w.@%+~-]+(?:/[\w.@%+~-]+)*)""")
_REL_PATH = re.compile(r"""(?<![\w.:/@%+~-])((?:[\w.@+-]+/)+[\w.@+-]*\.[A-Za-z0-9]{1,8}|\.(?:claude|github|cursor|vscode|ssh|aws|git|tainttrail)/[\w.@+/-]+)(?![\w/-])""")

# Top-level domains accepted for a host written without a scheme. Anything with a scheme
# is always accepted. The list is deliberately short: `main.py`, `README.md` and
# `requests.post` must not become hosts.
_TLDS = frozenset("""
com org net io dev app ai co edu gov mil int info biz xyz cloud site online tech example test invalid local
internal lan corp onion uk us de fr jp cn ru br in au ca nl se no fi dk ch at be es it pt ie nz kr tw hk sg il tr
mx ar za eu me tv to ly gg fm is id page link click top work live store shop blog news email host space website
world zone gl gd im ws cz gr hu ro ua pk bd vn th my ph ae sa eg ng ke
""".split())
_CODE_NAMESPACES = frozenset({"java.io", "java.net", "javax.net", "system.io", "system.net", "kotlin.io", "scala.io",
                              "golang.org", "self.app", "this.app", "app.id", "e.g", "i.e"})
# "owner/name" written without a host. Ordinary prose is full of a/b pairs, so a slug
# only counts when something marks it as a repository: an issue number after it, a
# repository word before it, or a hyphen, digit or underscore in one of its parts.
_SLUG = re.compile(r"(?<![\w./@:#-])([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{2,100})(#\d+)?(?![\w/-])")
_SLUG_CONTEXT = re.compile(r"(?:\b(?:repo(?:sitory)?|repos|fork(?:ed)? of|clone|issues? (?:in|on|of)|pull requests? (?:in|on)"
                           r"|github|gitlab)|(?:-R|--repo))\s*(?:named|called|is|at)?[\s:=\"'`(]*$", re.I)
_SLUG_FILE_EXT = re.compile(r"\.(?:py|js|ts|tsx|jsx|json|md|txt|sh|ya?ml|toml|lock|log|csv|html?|css|c|h|cc|cpp|rs|go|java|rb"
                            r"|php|png|jpe?g|gif|svg|pdf|zip|gz|tgz|env|ini|cfg|conf|xml|sql)$", re.I)
_FORGES = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
_FORGE_RESERVED = frozenset({"orgs", "settings", "login", "features", "topics", "search", "marketplace", "sponsors",
                             "about", "pricing", "apps", "notifications", "issues", "pulls", "explore", "users",
                             "organizations", "enterprise", "site", "security", "contact", "join", "new", "-"})

# Names that mean one particular file even when written without a directory.
_KNOWN_FILES: dict[str, str] = {
    ".bashrc": "~/.bashrc", ".zshrc": "~/.zshrc", ".profile": "~/.profile", ".bash_profile": "~/.bash_profile",
    ".gitconfig": "~/.gitconfig", ".netrc": "~/.netrc", ".pypirc": "~/.pypirc", ".git-credentials": "~/.git-credentials",
    "id_rsa": "~/.ssh/id_rsa", "id_ed25519": "~/.ssh/id_ed25519", "id_ecdsa": "~/.ssh/id_ecdsa",
    "id_dsa": "~/.ssh/id_dsa", "authorized_keys": "~/.ssh/authorized_keys",
}
_KNOWN_LOCAL = re.compile(
    r"""(?<![\w./@%+~-])(\.env(?:\.[\w-]+)?|\.npmrc|\.mcp\.json|\.envrc|CLAUDE(?:\.local)?\.md|AGENTS\.md|GEMINI\.md"""
    r"""|secrets\.(?:json|ya?ml|toml)|credentials\.json|terraform\.tfstate|\.cursorrules|\.windsurfrules)(?![\w/-])""")
_KNOWN_HOME = re.compile(r"(?<![\w./@%+~-])(" + "|".join(re.escape(k) for k in _KNOWN_FILES) + r")(?![\w./-])")
_HOME_DIRS = re.compile(r"""(?<![\w./@%+~-])(\.(?:ssh|aws|kube|gnupg|docker|azure|config/gcloud|config/gh)/[\w.@+/-]+)""")


def host_of(url_or_host: str) -> str | None:
    """Lower-case host of a URL or of a bare ``host[:port]``; None when there is none."""
    text = (url_or_host or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "//" + text
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")
    return host if re.fullmatch(r"[a-z0-9._:-]+", host) else None


def normalize_url(url: str) -> str | None:
    """``scheme://host[:port]/path`` in lower-case scheme and host, without query, fragment or user info."""
    try:
        parts = urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    scheme = parts.scheme.lower()
    host = host.lower().rstrip(".")
    default = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21, "ssh": 22}.get(scheme)
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc += f":{port}"
    path = parts.path if parts.path != "/" else ""
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return f"{scheme}://{netloc}{path}"


_ANY_SCHEME = re.compile(r"""\b[a-z][a-z0-9+.-]{1,20}://[^\s<>"'`\\\x00-\x1f]+""", re.I)


def _safe_part(part: str, key: bytes) -> str:
    """A path segment or host label, or a short keyed hash of it when it looks like a credential."""
    if len(part) < 16:
        return part
    if find_secrets(part) or (len(part) >= 20 and _random_looking(part)):
        return f"«{fingerprint(part, key)[:10]}»"
    return part


def safe_entity(ref: EntityRef, key: bytes) -> EntityRef:
    """The entity with nothing credential-like in its value.

    Entity values are stored, shown and exported like summaries, so they get the same care: a
    token in a URL path (``/bot<token>/sendMessage``), a secret glued into a host name, a key in
    a file name. The part is replaced by a short keyed hash of itself, so the same URL still
    meets itself in one node and two different tokens stay two nodes.
    """
    value = ref.value
    if ref.kind == "url":
        scheme, sep, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        name, colon, port = host.partition(":")
        name = ".".join(_safe_part(label, key) for label in name.split("."))
        path = "/".join(_safe_part(seg, key) for seg in path.split("/"))
        value = f"{scheme}{sep}{name}{colon}{port}{slash}{path}"
    elif ref.kind == "host":
        value = ".".join(_safe_part(label, key) for label in value.split("."))
    elif ref.kind == "file":
        value = "/".join(seg if not (len(seg) >= 16 and find_secrets(seg)) else f"«{fingerprint(seg, key)[:10]}»"
                         for seg in value.split("/"))
    elif ref.kind == "email":
        local, at, domain = value.partition("@")
        value = f"{_safe_part(local, key)}{at}{domain}"
    return ref if value == ref.value else EntityRef(ref.kind, value)


def url_entity(url: str) -> EntityRef | None:
    norm = normalize_url(url)
    return EntityRef("url", norm[:500]) if norm else None


def host_entity(host: str) -> EntityRef | None:
    h = host_of(host)
    return EntityRef("host", h) if h else None


def file_entity(path: str, cwd: str | None = None) -> EntityRef:
    return EntityRef("file", normalize_path(path, cwd if cwd else None))


def repo_entity(text: str) -> EntityRef | None:
    """A repository from a git URL, an scp-style address or a forge page URL.

    ``git@github.com:Owner/Name.git`` and ``https://github.com/owner/name/issues/3``
    both give ``repo:github.com/owner/name``.
    """
    text = (text or "").strip()
    m = _SCP_REPO.fullmatch(text.rstrip("/"))
    if m:
        return EntityRef("repo", f"{m.group(1).lower()}/{_no_git_suffix(m.group(2)).lower()}")
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host or parts.scheme.lower() not in ("http", "https", "ssh", "git"):
        return None
    segments = [s for s in parts.path.split("/") if s]
    if host == "api.github.com" and segments[:1] == ["repos"] and len(segments) >= 3:
        return EntityRef("repo", f"github.com/{segments[1].lower()}/{segments[2].lower()}")
    if host == "raw.githubusercontent.com" and len(segments) >= 2:
        return EntityRef("repo", f"github.com/{segments[0].lower()}/{segments[1].lower()}")
    is_git_url = parts.path.endswith(".git") or parts.scheme.lower() in ("ssh", "git")
    if host in _FORGES:
        if len(segments) < 2 or segments[0].lower() in _FORGE_RESERVED:
            return None
        name = segments[1][:-4] if segments[1].endswith(".git") else segments[1]
        return EntityRef("repo", f"{host}/{segments[0].lower()}/{name.lower()}")
    if is_git_url and len(segments) >= 2:
        path = "/".join(segments)
        path = path[:-4] if path.endswith(".git") else path
        return EntityRef("repo", f"{host}/{path.lower()}")
    return None


def _no_git_suffix(path: str) -> str:
    return path[:-4] if path.endswith(".git") else path


def find_urls(text: str) -> list[str]:
    """Every URL in the text, as written, without the punctuation that follows it."""
    out = []
    for m in _URL.finditer(text):
        url = m.group(0)
        end, opened, closed = len(url), url.count("("), url.count(")")
        while end and url[end - 1] in _TRAILING:
            if url[end - 1] == ")":
                if opened >= closed:
                    break   # the bracket belongs to the address: .../Foo_(bar)
                closed -= 1
            end -= 1
        url = url[:end]
        if "://" in url and len(url) > url.index("://") + 3:
            out.append(url)
    return out


def extract_entities(text: str, *, cwd: str | None = None, limit: int = 200, max_urls: int = 40) -> list[EntityRef]:
    """The things a piece of text names, in first-seen order, without duplicates.

    Every host and repository a link points at is named, but only the first ``max_urls`` links
    become entities of their own: who named a destination is decided by host, and a page of two
    hundred links would otherwise put two hundred nodes into a graph that is loaded for every
    hook event.
    """
    if not text:
        return []
    found: dict[EntityRef, None] = {}

    def add(ref: EntityRef | None) -> None:
        if ref is not None and ref.value and len(found) < limit * 2:
            found.setdefault(ref)

    masked = text
    urls = 0
    for url in find_urls(text):
        if urls < max_urls:
            add(url_entity(url))
            urls += 1
        add(host_entity(host_of(url) or ""))
        add(repo_entity(url))
    masked = _URL.sub(lambda m: " " * len(m.group(0)), masked)
    # Any other scheme (mongodb+srv://user:password@host, amqp://, smtp://): the host is named, and the
    # run is blanked so that "password@host" is never taken for an e-mail address.
    for m in _ANY_SCHEME.finditer(masked):
        add(host_entity(host_of(m.group(0)) or ""))
    masked = _ANY_SCHEME.sub(lambda m: " " * len(m.group(0)), masked)

    for m in _SCP_REPO.finditer(masked):
        add(EntityRef("repo", f"{m.group(1).lower()}/{_no_git_suffix(m.group(2)).lower()}"))
        add(EntityRef("host", m.group(1).lower()))
    masked = _SCP_REPO.sub(lambda m: " " * len(m.group(0)), masked)

    for m in _EMAIL.finditer(masked):
        add(EntityRef("email", m.group(1).lower()))
    masked = _EMAIL.sub(lambda m: " " * len(m.group(0)), masked)

    for m in _ENV_REF.finditer(masked):
        add(EntityRef("env", m.group(1) or m.group(2) or m.group(3)))

    for pattern, base in ((_ABS_PATH, None), (_HOME_DIRS, "~"), (_DOT_PATH, cwd), (_REL_PATH, cwd),
                          (_KNOWN_LOCAL, cwd)):
        for m in pattern.finditer(masked):
            path = m.group(1).rstrip(".,;:")
            if base == "~":
                path = "~/" + path
            elif pattern is _REL_PATH and _is_hostlike(path.split("/", 1)[0]):
                add(EntityRef("host", path.split("/", 1)[0].lower()))   # example.com/page.html is a web address
                continue
            add(EntityRef("file", normalize_path(path, base if base not in (None, "~") else None)))
        if pattern in (_ABS_PATH, _HOME_DIRS, _DOT_PATH, _REL_PATH):
            masked = pattern.sub(lambda m: " " * len(m.group(0)), masked)
    for m in _KNOWN_HOME.finditer(masked):
        add(EntityRef("file", normalize_path(_KNOWN_FILES[m.group(1)])))

    for m in _SLUG.finditer(masked):
        owner, name, issue = m.group(1), m.group(2).rstrip("."), m.group(3)
        if _SLUG_FILE_EXT.search(name) or name.endswith(".git") and False:
            continue
        marked = bool(issue) or bool(re.search(r"[-_\d]", owner + name)) or bool(_SLUG_CONTEXT.search(masked[max(0, m.start() - 40):m.start()]))
        if marked:
            add(EntityRef("repo", f"github.com/{owner.lower()}/{_no_git_suffix(name).lower()}"))

    for m in _IPV4.finditer(masked):
        add(EntityRef("host", m.group(1)))
    for m in _BARE_HOST.finditer(masked):
        if _is_hostlike(m.group(1)):
            add(EntityRef("host", m.group(1).lower().rstrip(".")))
    return list(found)[:limit]


# Two-part names that are as likely an attribute access in code as a host: `c.id`, `session.id`,
# `self.name`, `row.is`. They are still recorded as hosts (a page may well say "send it to evil.id"),
# but a mention in trusted content is too weak to make such a host one the project knows.
_ATTRIBUTE_TLDS = frozenset("id name is it in at as to do so no be my me by".split())
_CODE_RECEIVERS = frozenset("""
    self this cls obj item row node data config cfg file app db ctx args opts params props state result res req
    request response event user session entry record doc msg env model query input output key value val tmp err error
    el ev fn cb it x y z i j k n m p q r s t u v w a b c d e f g h
""".split())


def is_ambiguous_host(host: str) -> bool:
    """Whether a host name could just as well be ``variable.attribute`` in source code."""
    labels = host.lower().split(".")
    if len(labels) != 2:
        return False
    return len(labels[0]) <= 2 or labels[0] in _CODE_RECEIVERS or labels[1] in _ATTRIBUTE_TLDS


def _is_hostlike(name: str) -> bool:
    name = name.lower().rstrip(".")
    if name in _CODE_NAMESPACES or "." not in name:
        return False
    labels = name.split(".")
    if labels[-1] not in _TLDS or all(label.isdigit() for label in labels[:-1]):
        return False
    return all(label and not label.startswith("-") and not label.endswith("-") for label in labels)


# -- secrets --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretHit:
    kind: str
    value: str
    start: int
    end: int


# "author" and "tokenizer" are not credentials; the look-aheads keep them out.
_GENERIC_NAME = r"(?:password|passwd|pwd|secret|token(?!iz)|api[_-]?key|access[_-]?key|private[_-]?key|auth(?!or)|credential)"
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\Z)", re.S), 0),
    # Bounded by its own alphabet, not by word boundaries: glued to lower-case filler it is still a key id.
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), 0),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,24}?(?:secret|sk)[A-Za-z_]{0,16}\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), 0),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), 0),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), 0),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 0),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), 0),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}"), 0),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), 0),
    # Starts only where a run of token characters starts, and each part is taken whole (the look-ahead
    # plus back-reference is an atomic group that also works on Python 3.10): no start inside a long
    # run, no backtracking into one.
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ(?=([A-Za-z0-9_-]{8,}))\1\.eyJ(?=([A-Za-z0-9_-]{8,}))\2\.[A-Za-z0-9_-]{8,}"), 0),
    ("url_password", re.compile(r"\b[a-z][a-z0-9+.-]{0,20}://[^\s:/@]{1,64}:([^\s@/]{3,200})@[\w.-]"), 1),
    ("canary", re.compile(r"\bcanary-[A-Za-z0-9_-]{8,}"), 0),
    # Anchored on the keyword, with every repeat bounded: a pattern that may start anywhere in a run
    # of dots or word characters and scan to its end is quadratic, and one line of test-runner dots
    # was enough to keep a hook busy past its timeout.
    ("assigned_secret", re.compile(
        r"(?i)" + _GENERIC_NAME + r"[\w.-]{0,64}[\"']?\s{0,8}[=:]\s{0,8}[\"']?([^\s\"'#,;`<>(){}\[\]]{8,})"), 1),
    ("env_value", re.compile(r"(?m)^(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*[\"']?([A-Za-z0-9+/=_-]{20,})[\"']?\s*$"), 1),
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:change[-_]?me|password|secret|example|placeholder|none|null|nil|true|false|undefined|test|dummy|foo|bar"
    r"|todo|redacted|\*+|x{4,}|\.{3,}|your[-_ ].*|<.*|\$.*|\{\{.*|os\.environ.*|process\.env.*|getenv.*|required|optional"
    r"|string|bool(?:ean)?|integer|number)$")


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_NAME_ENDS_IN_CREDENTIAL_WORD = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?key|credentials?|auth)$")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


_ENV_SUFFIX = re.compile(r"(?i)(?:[_-]?(?:prod|production|dev|development|stag(?:e|ing)|stg|test|qa|live|local|old|new"
                         r"|backup|primary|secondary|base|main|default|v?\d+))+$")


def _credential_name(text: str, m: "re.Match[str]") -> bool:
    """Whether the name of a ``name = value`` hit ends in a credential word."""
    name = re.match(r"[\w.-]+", text[m.start():m.start(1)])
    if not name:
        return False
    word = name.group(0)
    word = _ENV_SUFFIX.sub("", word) or word    # DB_PASSWORD_PROD, API_KEY_V2, SECRET_KEY_BASE are credentials too
    return bool(_NAME_ENDS_IN_CREDENTIAL_WORD.search(word))


def _plausible_assignment(text: str, m: "re.Match[str]", value: str) -> bool:
    """Whether a ``name = value`` hit can be a credential at all.

    ``auth = HTTPBasicAuth(user, pw)``, ``"token_type": "bearer12"``, ``POSTGRES_PASSWORD: postgres``
    and ``token = create_access_token(...)`` are code and configuration, not secrets. Taking them
    for secrets fingerprints ordinary words, and the next commit message that repeats one is then
    "carrying a secret".
    """
    if not _credential_name(text, m):
        return False            # token_type, AUTH_USER_MODEL, password_hint, secret.txt
    head = text[m.start():m.start(1)]
    quoted = head.rstrip()[-1:] in ("\"", "'")
    after = text[m.end(1):m.end(1) + 1]
    if not quoted and _IDENTIFIER.fullmatch(value):
        passphrase = len(value) >= 16 and value.islower() and value.isalpha()     # correcthorsebatterystaple
        if "." in value or after in ("(", "[", ".") or (not any(ch.isdigit() for ch in value) and not passphrase):
            return False        # request.form, create_access_token(...), hashedPassword, postgres
    return True


def find_secrets(text: str, *, strict: bool = True) -> list[SecretHit]:
    """Credentials in the text, recognised by their shape. Non-overlapping, in order.

    ``strict`` is for fingerprints and for calling a content sensitive: a ``name = value`` hit
    must then be a plausible credential, because a wrong one makes an ordinary word evidence.
    Redaction passes ``strict=False``: one word too many replaced in an excerpt costs nothing.
    """
    if not text:
        return []
    hits: list[SecretHit] = []
    for kind, pattern, group in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(group)
            if not value:
                continue
            if kind == "assigned_secret":
                value = value.rstrip(".")
                if _PLACEHOLDER.match(value) or ("example" in value.lower() and not value.lower().startswith("canary")):
                    continue
                if value.startswith(("http://", "https://", "/", "./", "~/")) or value.endswith((":", "=")):
                    continue
                if not (_plausible_assignment(text, m, value) if strict else _credential_name(text, m)):
                    continue
            if kind == "env_value" and (
                    shannon_entropy(value) < 3.8 or value.startswith("-") or "=" in value.rstrip("=")
                    or not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value))):
                continue
            start = m.start(group)
            hits.append(SecretHit(kind, value, start, start + len(value)))
    hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
    out: list[SecretHit] = []
    covered_until = -1
    for h in hits:
        if h.start >= covered_until:
            out.append(h)
            covered_until = h.end
        elif h.end > covered_until and h.kind not in ("assigned_secret", "env_value"):
            out.append(h)
            covered_until = h.end
    return out


# Shapes that matter when text is stored or shown, on top of what find_secrets knows: the commonest
# ways an agent puts a working credential on a command line or gets one back.
_REDACT_ONLY: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("authorization", re.compile(
        r"(?i)\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic|token|digest|negotiate)\s+)?([^\s\"'`,;]{8,})")),
    ("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})")),
    ("password", re.compile(r"(?<![\w-])(?:-u|--user)[ =]+[\"']?[^\s:\"']{1,64}:([^\s\"'@]{3,})")),
    ("password", re.compile(
        r"(?i)(?<![\w-])--(?:password|passwd|pass|token|secret|api-?key|passphrase|auth-token|access-token)[ =]+[\"']?([^\s\"'`]{3,})")),
    ("secret", re.compile(
        r"(?i)[?&](?:key|api_?key|sig|signature|code|pass|password|auth|token|access_token|secret|client_secret)=([^&\s\"'`#]{4,})")),
    ("secret", re.compile(r"(?i)[\"'](?:pass|key|passphrase|pwd)[\"']\s*:\s*[\"']([^\"']{4,})[\"']")),
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+=_-]{20,}")
_LONG_HEX = re.compile(r"[0-9A-Fa-f]{32,}")
_BLOB = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


def _random_looking(token: str) -> bool:
    """A string of 20+ characters that is not a word, an identifier or a path segment.

    ``air_quality_station_measurements_2023`` is an identifier: its parts are words and numbers.
    ``canary_dbpass_7Qz4Lm9Xr2Tb`` is not: one part mixes letters and digits.
    """
    if _LONG_HEX.fullmatch(token):
        return True     # hex of ASCII text has low entropy and is still an encoding of something
    if not (any(ch.isalpha() for ch in token) and any(ch.isdigit() for ch in token)):
        return False
    if shannon_entropy(token) < 3.5:
        return False
    return any(len(part) >= 6 and any(ch.isalpha() for ch in part) and any(ch.isdigit() for ch in part)
               for part in re.split(r"[_=+-]+", token))


def _blank_unrecognised(line: str) -> str:
    """Replace what still looks like key material: encoded blobs and long random-looking strings."""
    def blob(m: "re.Match[str]") -> str:
        text = m.group(0)
        mixed = any(c.isupper() for c in text) and any(c.islower() for c in text) and any(c.isdigit() for c in text)
        return f"«{len(text)} encoded characters»" if mixed and shannon_entropy(text) >= 4.5 else text

    line = _BLOB.sub(blob, line)
    return _LONG_TOKEN.sub(lambda m: "«token»" if _random_looking(m.group(0)) else m.group(0), line)


def redact(text: str, max_len: int = 240) -> str:
    """One line of the text, with every credential replaced by its kind in guillemets, then cut.

    Redaction comes first and the cut second, and the cut never lands inside a long token: a
    token that is recognised only by its full shape would otherwise keep its first characters.
    """
    if not text:
        return ""
    head = text[: max(max_len * 8, 4096)]
    spans: list[tuple[int, int, str]] = [(h.start, h.end, h.kind) for h in find_secrets(head, strict=False)]
    for kind, pattern in _REDACT_ONLY:
        spans += [(m.start(1), m.end(1), kind) for m in pattern.finditer(head)]
    spans.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    parts: list[str] = []
    pos = 0
    for start, end, kind in spans:
        if start < pos:
            continue
        parts.append(head[pos:start])
        parts.append(f"«{kind}»")
        pos = end
    parts.append(head[pos:])
    line = _blank_unrecognised(" ".join("".join(parts).split()))
    if len(line) <= max_len:
        return line
    cut = max_len - 1
    start = line.rfind(" ", 0, cut) + 1
    end = line.find(" ", cut)
    if (end if end >= 0 else len(line)) - start >= 16 and start > 0:
        cut = start      # the cut would fall inside a long token: leave the token out
    return line[:cut].rstrip() + "…"


# -- fingerprints -----------------------------------------------------------------------------------

_SPLIT_STRICT = re.compile(r"[^A-Za-z0-9_\-]+")
_SPLIT_LOOSE = re.compile(r"[^A-Za-z0-9+/=_\-.]+")
_QUOTED = re.compile(r"""(["'`])((?:(?!\1).){8,2000})\1""", re.S)
_AFTER_ASSIGN = re.compile(r"[=:]\s*[\"']?([^\s\"'&;,<>]{8,})")
_BOILERPLATE = re.compile(
    r"^(?:import |from \S+ import |#include|using |package |require\(|const \w+ = require\(|use |\s*[-=*#_/~.]{6,}\s*$|#!"
    r"|.*(?:Licensed under|Copyright \(c\)|Permission is hereby granted|SPDX-License-Identifier))", re.I)
MIN_SINK_TOKEN = 8
MIN_SOURCE_TOKEN = 16
MIN_SUBTOKEN = 12
MIN_LINE = 24


def fingerprint(value: str, key: bytes) -> str:
    """A keyed hash that identifies ``value`` without revealing it."""
    return hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:32]


_LINE_PREFIX = re.compile(r"^(?:[-*+>#]+\s+|\d{1,3}[.)]\s+|//+\s*|/\*+\s*)+")


def _normal_lines(text: str) -> list[str]:
    """Lines as they compare across copies: whitespace collapsed, list and quote markers dropped."""
    out = []
    for raw in text.splitlines():
        line = " ".join(raw.split())
        line = _LINE_PREFIX.sub("", line).strip("`*_ ")
        if MIN_LINE <= len(line) <= 2000:
            out.append(line)
    return out


def _tokens(text: str, minimum: int) -> list[str]:
    """Candidate substrings under every tokenisation, shortest allowed length ``minimum``."""
    seen: dict[str, None] = {}
    for part in text.split():
        if len(part) >= minimum:
            seen.setdefault(part)
            seen.setdefault(part.strip("\"'`,;()[]{}<>"))
            if part[0] == "-" and len(part) > 2 and part[1] != "-":
                seen.setdefault(part[2:])   # a value glued to a one-letter option: -pVALUE
    for splitter in (_SPLIT_STRICT, _SPLIT_LOOSE):
        for part in splitter.split(text):
            if len(part) >= minimum:
                seen.setdefault(part)
                stripped = part.strip("=.")
                if len(stripped) >= minimum:
                    seen.setdefault(stripped)
    for m in _QUOTED.finditer(text):
        seen.setdefault(m.group(2))
    for m in _AFTER_ASSIGN.finditer(text):
        seen.setdefault(m.group(1))
    seen.pop("", None)
    return [t for t in seen if len(t) >= minimum]


def _looks_random(token: str) -> bool:
    """A string worth remembering on its own: random-looking, or simply too long to recur by chance."""
    if token.startswith(("http", "www.")) or len(token) < MIN_SOURCE_TOKEN:
        return False
    if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
        return False
    if len(token) >= 64 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", token):
        return True   # an encoded blob: hex of ASCII text has low entropy but is still unique
    return shannon_entropy(token) >= 3.5 and not token.startswith("/")


def encoded_secret_chunks(text: str, key: bytes, *, limit: int = 100) -> tuple[list[ChunkRef], list[str]]:
    """Secrets hidden in an encoded blob: fingerprints of what the text decodes to.

    ``base64 .env`` and ``xxd -p .env`` put secrets into the agent's context without one
    readable secret in it. Returns the fingerprints of the secrets found after decoding
    and the kinds of secret, so the content can be marked sensitive.
    """
    chunks: dict[str, ChunkRef] = {}
    kinds: list[str] = []
    for variant in decode_variants(text):
        for hit in find_secrets(variant):
            if hit.kind not in kinds:
                kinds.append(hit.kind)
            for value in [hit.value, *_tokens(hit.value, MIN_SUBTOKEN)]:
                if len(chunks) < limit:
                    fp = fingerprint(value, key)
                    chunks.setdefault(fp, ChunkRef(fp, "secret", hit.kind, len(value)))
    return list(chunks.values()), kinds


def content_chunks(text: str, key: bytes, *, limit: int = 400) -> list[ChunkRef]:
    """Fingerprints of text that entered the agent's context.

    Secrets first (each value, and its parts as they would appear inside a URL or a JSON
    body), then links with a query string, then long random-looking tokens, then lines.
    """
    if not text:
        return []
    chunks: dict[str, ChunkRef] = {}

    def add(value: str, kind: str, hint: str = "") -> None:
        if value and len(chunks) < limit:
            fp = fingerprint(value, key)
            if fp not in chunks:
                chunks[fp] = ChunkRef(fp, kind, hint, len(value))

    for hit in find_secrets(text):
        if hit.kind in ("assigned_secret", "url_password") and len(hit.value) < 12 and hit.value.isalpha():
            continue    # a short dictionary-like word is no evidence when it shows up again
        add(hit.value, "secret", hit.kind)
        if hit.kind == "private_key":
            body = [ln.strip() for ln in hit.value.splitlines() if ln.strip() and not ln.startswith("-----")]
            add("".join(body), "secret", hit.kind)
            for line in body:
                if len(line) >= MIN_LINE:
                    add(line, "secret", hit.kind)
        else:
            for part in _tokens(hit.value, MIN_SUBTOKEN):
                add(part, "secret", hit.kind)
    for url in find_urls(text):
        add(url, "url")     # every link the content lists: a later GET of exactly it is "following a link"
    budget = len(chunks) + max(0, (limit - len(chunks)) // 2)
    for token in _tokens(text, MIN_SOURCE_TOKEN):
        if len(chunks) >= budget:
            break
        if _looks_random(token):
            add(token, "token")
    for line in _normal_lines(text):
        if len(chunks) >= limit:
            break
        if not _BOILERPLATE.match(line) and len(set(line)) >= 8:
            add(line, "line")
    return list(chunks.values())


def carried_fingerprints(text: str, key: bytes, *, limit: int = 4000) -> list[str]:
    """Every fingerprint the text of a tool call could share with recorded content.

    Looks at the text as written and at what it decodes to. Only ids are returned; the
    caller keeps those that exist as ``Chunk`` nodes.
    """
    return list(carried_pieces(text, key, limit=limit))


def carried_pieces(text: str, key: bytes, *, limit: int = 4000) -> dict[str, str]:
    """``carried_fingerprints`` with the piece of text behind each fingerprint.

    The caller needs the pieces for one thing: when a fingerprint turns out to be a recorded
    secret, that piece must not be written down again in the call's summary or in a URL.
    """
    if not text:
        return {}
    out: dict[str, str] = {}

    def take(piece: str) -> None:
        candidates = _tokens(piece, MIN_SINK_TOKEN) + _normal_lines(piece) + find_urls(piece)
        whole = piece.strip()
        if MIN_SINK_TOKEN <= len(whole) <= 4096:
            candidates.append(whole)
            candidates.append("".join(whole.split()))
        for cand in candidates:
            if len(out) >= limit:
                return
            out.setdefault(fingerprint(cand, key), cand)

    take(text)
    for variant in decode_variants(text):
        if len(out) >= limit:
            break
        take(variant)
    return out


_BOUNDARY = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9])|(?<=[A-Za-z0-9])(?![A-Za-z0-9])")


def window_fingerprints(text: str, key: bytes, lengths: Iterable[int], *, limit: int = 6_000,
                        max_text: int = 4096) -> list[str]:
    """Fingerprints of fixed-length windows that start or end at a word boundary.

    A token comparison misses a secret that is glued to other characters, such as
    ``NAME-secret.dns.example`` in a host name. The graph knows how long each recorded
    secret is, so for each of those lengths this takes the window after every word start
    and before every word end. The cost is the number of boundaries times the number of
    lengths, a few thousand hashes for a long command.
    """
    return list(window_pieces(text, key, lengths, limit=limit, max_text=max_text))


def window_pieces(text: str, key: bytes, lengths: Iterable[int], *, limit: int = 6_000,
                  max_text: int = 4096) -> dict[str, str]:
    """``window_fingerprints`` with the window of text behind each fingerprint."""
    text = text[:max_text]
    sizes = sorted({int(n) for n in lengths if 8 <= int(n) <= 256})[:24]
    if not text or not sizes:
        return {}
    out: dict[str, str] = {}
    bounds = [m.start() for m in _BOUNDARY.finditer(text)]
    for pos in bounds:
        for n in sizes:
            for piece in (text[pos:pos + n], text[max(0, pos - n):pos]):
                if len(piece) == n:
                    out.setdefault(fingerprint(piece, key), piece)
            if len(out) >= limit:
                return out
    return out


_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_LINE = re.compile(r"[0-9A-Fa-f]{16,}")
_B64_LINE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _wrapped_blobs(text: str, *, limit: int = 8) -> list[tuple[str, str]]:
    """Encoded output that a tool broke into lines (``xxd -p``, ``base64``), joined back together.

    One pass over the lines: consecutive lines that are entirely hex, or entirely
    base64, form one blob. Written as a scan because the obvious regular expression
    backtracks quadratically on a long unbroken run.
    """
    out: list[tuple[str, str]] = []
    run: list[str] = []
    kind = ""

    def flush() -> None:
        if len(run) >= 2 and len(out) < limit:
            out.append((kind, "".join(run)))

    for raw in text.splitlines():
        line = raw.strip()
        this = "hex" if _HEX_LINE.fullmatch(line) else ("b64" if _B64_LINE.fullmatch(line) else "")
        if this and (not run or this == kind or {this, kind} == {"hex", "b64"}):
            kind = this if not run else ("b64" if "b64" in (this, kind) else "hex")
            run.append(line)
        else:
            flush()
            run, kind = ([line], this) if this else ([], "")
    flush()
    return out
_MAX_VARIANTS = 64
_MAX_RUNS = 200


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return text if ok / len(text) >= 0.9 else None


def decode_variants(text: str, *, depth: int = 2) -> list[str]:
    """What the text says once base64, hex, percent-encoding and JSON escapes are undone."""
    if not text or depth <= 0:
        return []
    found: dict[str, None] = {}

    def add(value: str | None) -> None:
        if value and value != text and len(found) < _MAX_VARIANTS:
            found.setdefault(value[:262_144])

    for m in list(_B64_RUN.finditer(text))[:_MAX_RUNS]:
        run = m.group(0).rstrip("=")
        if re.fullmatch(r"[0-9a-fA-F]+", run) and len(run) % 2 == 0:
            continue   # hex, handled below
        padded = run + "=" * (-len(run) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                add(_printable(decoder(padded)))
            except (binascii.Error, ValueError):
                continue
    for m in list(_HEX_RUN.finditer(text))[:_MAX_RUNS]:
        try:
            add(_printable(bytes.fromhex(m.group(0))))
        except ValueError:
            continue
    for kind, joined in _wrapped_blobs(text):
        try:
            if kind == "hex":
                add(_printable(bytes.fromhex(joined)))
            else:
                joined = joined.rstrip("=")
                add(_printable(base64.b64decode(joined + "=" * (-len(joined) % 4))))
        except (binascii.Error, ValueError):
            continue
    if _PERCENT.search(text):
        add(unquote(text))
        add(unquote_plus(text))
    if "\\" in text:
        unescaped = (text.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\/", "/")
                     .replace("\\\\", "\\"))
        add(unescaped)
    variants = list(found)
    if depth > 1:
        for variant in list(variants):
            for inner in decode_variants(variant, depth=depth - 1):
                if inner not in found and inner != text and len(found) < _MAX_VARIANTS:
                    found[inner] = None
        variants = list(found)
    return variants


# -- injection score ---------------------------------------------------------------------------------

_CRED_WORDS = (r"(?:\.env\b|id_rsa|ssh[ _-]?keys?|private[ _-]?keys?|api[ _-]?(?:keys?|tokens?)|access[ _-]?tokens?"
               r"|credentials?|secrets?|passwords?|environment variables|your environment|auth(?:entication)? tokens?"
               r"|output of (?:the )?[`'\"]?(?:env|printenv)[`'\"]?)")
_SEND_VERBS = r"(?:send|post|upload|attach|include|paste|transmit|share|e-?mail|append|forward|submit|exfiltrate|leak)"
_ADDRESSEE = r"(?:AI|LLM|language model|assistant|(?:AI|LLM|automated|coding) agent|claude|copilot|chatgpt|gemini)s?"
_MODAL = r"(?:must|should|need to|have to|are required to|shall|please|now)"
# Three markers are functions, not patterns. As single regular expressions they were either
# quadratic or cost tens of microseconds per byte on dense input (a page of "<!--", compact JSON
# full of URLs), which is how a hook comes to outlive its timeout. Each scans the text once.
_CRED_RX = re.compile(_CRED_WORDS, re.I)
_SEND_TO_URL_RX = re.compile(r"\b" + _SEND_VERBS + r"\b[^\n]{0,80}https?://", re.I)
_TEMPLATE_RX = re.compile(r"<[^<>\s]{0,60}(?:token|key|secret|password|credential|\.env)[^<>\s]{0,60}>", re.I)
# "<!-- prettier-ignore-start -->" and "<!-- this must stay in sync -->" are ordinary comments.
_COMMENT_WORD_RX = re.compile(
    r"\b(?:assistants?|agents?|AI|LLM|claude|copilot|instructions?)\b|\bignore\s+(?:all|any|the|previous|prior|above)", re.I)
_SPACE_RX = re.compile(r"\s")


def _read_then_send(text: str) -> bool:
    """A credential word, then within the same or the next line a send verb followed by a URL."""
    sends = [m.start() for m in _SEND_TO_URL_RX.finditer(text)]
    if not sends:
        return False
    creds = [m.end() for m in _CRED_RX.finditer(text)]
    if not creds:
        return False
    lo = 0
    for send in sends:
        while lo < len(creds) and creds[lo] < send - 241:
            lo += 1
        i = lo
        while i < len(creds) and creds[i] <= send:
            gap = text[creds[i]:send]
            first = gap.find("\n")
            if first < 0:
                if len(gap) <= 240:
                    return True
            elif first <= 80 and len(gap) - first - 1 <= 160 and "\n" not in gap[first + 1:]:
                return True
            i += 1
    return False


def _secret_in_url_template(text: str) -> bool:
    """A URL with a placeholder for a secret in it: https://host/collect?d=<API_KEY>."""
    for m in _TEMPLATE_RX.finditer(text):
        before = text[max(0, m.start() - 300):m.start()]
        cut = 0
        for ws in _SPACE_RX.finditer(before):
            cut = ws.end()
        address = before[cut:].lower()
        if "http://" in address or "https://" in address:
            return True
    return False


def _hidden_comment(text: str) -> bool:
    """An HTML comment that, within its first 800 characters, addresses an agent or gives an order."""
    at = text.find("<!--")
    while at >= 0:
        end = text.find("-->", at + 4)
        if end < 0:
            return False
        if _COMMENT_WORD_RX.search(text, at + 4, min(end, at + 4 + 800)):
            return True
        at = text.find("<!--", end + 3)
    return False


_INJECTION_MARKERS: tuple[tuple[str, float, "re.Pattern[str] | Callable[[str], bool]"], ...] = (
    ("ignore-previous", 0.6, re.compile(
        r"\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b.{0,40}"
        r"\b(?:instruction|prompt|rule|direction|guideline)s?\b", re.I | re.S)),
    # A markdown heading is a fake role tag only when it is written as one ("### System:"). "## System
    # Requirements" and "## Instructions" are in every README.
    ("fake-role-tag", 0.5, re.compile(
        r"<\s*/?\s*(?:system|assistant|instructions?)\s*>|\[/?INST\]|^#{2,3}\s*(?:system|instructions?)\s*:"
        r"|^#{2,3}\s*system\s+(?:prompt|message)\b|<\|(?:im_start|system|assistant)\|>|BEGIN (?:SYSTEM|ADMIN) (?:PROMPT|MESSAGE)",
        re.I | re.M)),
    # "model" and "cursor" are everyday nouns (Django models, database cursors). An agent is addressed
    # when the text names an AI assistant, qualifies the agent ("AI agents", "coding agents"), speaks
    # to it ("agents: ...") or tells agents what they must do, unless that is a user agent, a build
    # agent or another agent of that kind.
    ("addressed-to-agent", 0.3, re.compile(
        r"\b" + _ADDRESSEE + r"\b[^.\n]{0,60}\b" + _MODAL + r"\b"
        r"|\bagents?\s*[:,]\s*[^.\n]{0,80}\b" + _MODAL + r"\b"
        r"|(?<!user )(?<!user-)(?<!build )(?<!ssh )(?<!monitoring )(?<!transfer )\bagents?\b[^.\n]{0,60}\b" + _MODAL + r"\b"
        r"|\b(?:attention|note (?:to|for)|message for|instructions? for)\b[^.\n]{0,24}\b(?:" + _ADDRESSEE + r"|agents?)\b", re.I)),
    ("new-instructions", 0.3, re.compile(
        r"\b(?:new|updated|additional|important|urgent|special|system)\s+(?:instructions?|task|directive)s?\b\s*[:\-]", re.I)),
    # "Send ... credentials" needs somewhere to send them. "Include your API key in the Authorization
    # header of every request" is how every API documents authentication.
    ("send-credentials", 0.4, re.compile(
        r"\b" + _SEND_VERBS + r"\b[^.\n]{0,100}" + _CRED_WORDS + r"[^.\n]{0,80}"
        r"(?:\bto\s+(?:https?://|[\w-]+(?:\.[\w-]+)+\b|the\s+(?:server|endpoint|url|address|webhook|maintainers?))"
        r"|\b(?:in|into|as)\s+(?:your|the|a|an)\s+(?:[\w-]+\s+){0,2}"
        r"(?:comments?|reply|review|issue|pull request|pr|message|response|summary|commit|gist|blob|paste))"
        r"|" + _CRED_WORDS + r"[^.\n]{0,100}\b(?:to|into)\s+https?://", re.I)),
    ("secrecy", 0.25, re.compile(
        r"\b(?:do not|don't|never|without)\b[^.\n]{0,30}\b(?:tell|mention|reveal|inform|alert|notify|show|asking)\b"
        r"[^.\n]{0,30}\b(?:user|human|developer|anyone|operator)\b"
        r"|\bdo (?:this|it|so) (?:silently|quietly)\b|\bwithout (?:telling|asking|notifying|mentioning)\b", re.I)),
    ("note-for-agent", 0.3, re.compile(
        r"\((?:for|to) (?:the |any |all )?[\w -]{0,24}(?:agents?|assistants?)\)", re.I)),
    ("read-then-send", 0.4, _read_then_send),
    ("secret-in-url-template", 0.4, _secret_in_url_template),
    ("permission-waiver", 0.3, re.compile(
        r"\b(?:does(?:n't| not) care about privacy|no need to (?:ask|confirm|check with)|(?:do not|don't) (?:ask|wait) for "
        r"(?:permission|confirmation|approval)|put everything you find)\b", re.I)),
    ("send-to-url", 0.1, re.compile(r"\b" + _SEND_VERBS + r"\b[^.\n]{0,80}https?://", re.I)),
    ("hidden-comment", 0.3, _hidden_comment),
    ("invisible-characters", 0.25, re.compile(r"(?:[\u200b\u200c\u200d\u2060\ufeff][^\u200b\u200c\u200d\u2060\ufeff]{0,3}){3,}|[\U000e0000-\U000e007f]")),
    ("hidden-style", 0.15, re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?!\.)", re.I)),
    ("run-this", 0.15, re.compile(
        r"\b(?:run|execute|call|use)\b[^.\n]{0,30}\b(?:the following|this)\s+(?:command|tool|script)\b", re.I)),
)
_URGENCY = re.compile(r"\b(?:immediately|urgent(?:ly)?|right now|before (?:doing )?anything else|mandatory|critical)\b", re.I)


def injection_score(text: str) -> tuple[float, list[str]]:
    """How much the text reads like instructions aimed at an agent, from 0 to 1.

    Each marker contributes independently (a noisy-or), so one weak hint stays weak and
    several together add up. Documentation that merely mentions ``curl`` or ``.env``
    scores low; text that tells an assistant to send its credentials somewhere scores
    high. Returns the score and the names of the markers that fired.
    """
    if not text:
        return 0.0, []
    sample = text[:262_144]
    miss = 1.0
    fired: list[str] = []
    for name, weight, pattern in _INJECTION_MARKERS:
        if pattern(sample) if callable(pattern) else pattern.search(sample):
            fired.append(name)
            miss *= 1.0 - weight
    if fired and fired != ["send-to-url"] and _URGENCY.search(sample):
        fired.append("urgency")
        miss *= 0.9
    return round(1.0 - miss, 3), fired
