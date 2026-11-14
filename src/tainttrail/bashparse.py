"""What a shell command reads, writes, sends and runs, worked out without running it.

The guard has to judge a ``Bash`` call before it executes, from its text alone. This
module reads the command the way a careful reviewer would: which files go in, which
hosts are contacted, what is uploaded, whether something fetched is executed.

It is deliberately modest. It understands ordinary command lines for the common tools.
When a command hides what it will do (the program name is computed, a string is
decoded and executed, a config file supplies the arguments), the analysis says so with
``opaque=True`` and the command is treated as one that may send data anywhere. Failing
to understand a command must never make it look safe.
"""

from __future__ import annotations

import configparser
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MAX_DEPTH = 4
# A command longer than this is not parsed: it is treated as one that could do anything. Parsing
# time grows faster than the length for some shapes, and nobody types 64 KB of shell by hand.
MAX_COMMAND_CHARS = 65_536


@dataclass
class BashAnalysis:
    reads: list[str] = field(default_factory=list)        # file paths as written in the command
    writes: list[str] = field(default_factory=list)
    uploads: list[str] = field(default_factory=list)      # files whose content is sent out
    deletes: list[str] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)      # URLs downloaded
    destinations: list[tuple[str, str]] = field(default_factory=list)  # ("url"|"host"|"repo"|"email", value)
    derived: list[tuple[str, str]] = field(default_factory=list)       # (target file, source file or URL)
    env_reads: list[str] = field(default_factory=list)    # environment variables the command expands
    env_uploads: list[str] = field(default_factory=list)  # ... inside a command that sends data out
    env_auth: list[str] = field(default_factory=list)     # ... and only where a credential belongs (-u, Authorization:)
    env_dump: bool = False                                # prints the whole environment
    env_uploaded: bool = False                            # ... into a command that sends data out
    executes_download: bool = False                       # runs something it fetches in the same command
    executed: list[str] = field(default_factory=list)     # URLs or files executed
    staged: list[str] = field(default_factory=list)       # paths given to `git add` ("." means everything)
    encodes: bool = False                                 # an encoder or decoder sits in front of a sink
    is_sink: bool = False                                 # can move data off the machine
    sink_kinds: list[str] = field(default_factory=list)   # "http","shell-net","git","dns","email","publish","cloud","opaque"
    carries_payload: bool = False                         # the outbound call has room for chosen data
    untrusted_output: bool = False                        # prints text fetched from elsewhere
    sensitive_output: bool = False                        # prints a credential by design
    opaque: bool = False                                  # could not be read statically
    opaque_reasons: list[str] = field(default_factory=list)
    programs: list[str] = field(default_factory=list)
    summary: str = ""


# -- small helpers ---------------------------------------------------------------------------

_URL = re.compile(r"""\b(?:https?|wss?|ftp|sftp|ssh|git|s3|gs)://[^\s'"<>`|;)]+""", re.I)
_HOSTLIKE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,23}$", re.I)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|([A-Za-z_][A-Za-z0-9_]*))")
_SUB = re.compile(r"\x00S(\d+)\x00")
_HERE = re.compile(r"\x00H(\d+)\x00")
_REMOTE_SPEC = re.compile(r"^(?:([^@/\s:]+)@)?([A-Za-z0-9][A-Za-z0-9.-]*):(.*)$")
_FILE_EXT = re.compile(r"\.(?:py|js|ts|json|md|txt|sh|yml|yaml|toml|lock|log|csv|html|css|c|h|rs|go|java|rb|php)$", re.I)

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_INTERPRETERS = {"python", "python2", "python3", "py", "pypy", "pypy3", "node", "nodejs", "deno", "bun", "ruby",
                 "perl", "php", "lua", "rscript", "pwsh", "powershell", "osascript"}
_CODE_FLAG = {"python": "-c", "python2": "-c", "python3": "-c", "py": "-c", "pypy": "-c", "pypy3": "-c",
              "node": "-e", "nodejs": "-e", "deno": "eval", "bun": "-e", "ruby": "-e", "perl": "-e", "php": "-r",
              "lua": "-e", "rscript": "-e", "pwsh": "-Command", "powershell": "-Command", "osascript": "-e"}
_WRAPPERS = {"sudo", "doas", "env", "time", "nohup", "nice", "ionice", "timeout", "stdbuf", "command", "builtin",
             "exec", "setsid", "unbuffer", "chronic", "watch", "caffeinate"}
_KEYWORD_SKIP = {"then", "else", "elif", "do", "{", "!", "if", "while", "until", "fi", "done", "esac", "}"}
_ENCODERS = {"base64", "base32", "xxd", "od", "hexdump", "gzip", "bzip2", "xz", "zstd", "uuencode", "openssl"}
_NET_CODE = re.compile(
    r"requests\.|urllib|http\.client|httpx|aiohttp|socket\b|smtplib|ftplib|paramiko|fetch\s*\(|https?\.(?:request|get)"
    r"|XMLHttpRequest|net\.connect|axios|Net::HTTP|open-uri|LWP::|HTTP::Tiny|IO::Socket|curl_exec|fsockopen"
    r"|file_get_contents\s*\(\s*['\"]https?|urlopen|WebSocket", re.I)
_SHELL_FROM_CODE = re.compile(
    r"(?:os\.system|subprocess\.\w+|os\.popen|child_process\.\w+|execSync|spawnSync|system|exec|popen|shell_exec|passthru)"
    r"\s*\(\s*(?:\[?\s*)?(['\"])(.+?)\1", re.S)
_CODE_OPEN = re.compile(r"(?:open|readFile(?:Sync)?|File\.read|file_get_contents|Path)\s*\(\s*(['\"])([^'\"\n]{1,200})\1")
_ENV_IN_CODE = re.compile(r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\s*\(\s*|process\.env\.|process\.env\[\s*|ENV\[\s*|getenv\s*\(\s*)['"]?([A-Za-z_][A-Za-z0-9_]*)""")
_ENV_ALL_IN_CODE = re.compile(r"os\.environ\s*(?:\)|\.items|\.copy|,|$)|dict\(os\.environ\)|JSON\.stringify\(process\.env\)|process\.env\s*\)|ENV\.to_h|%ENV\b")


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _add(items: list, value) -> None:
    if value is None or value == "" or value in items:
        return
    items.append(value)


def _looks_like_host(text: str) -> bool:
    text = text.strip().rstrip(".")
    if _IPV4.match(text):
        return True
    return bool(_HOSTLIKE.match(text)) and not _FILE_EXT.search(text)


def _url_of(text: str) -> str | None:
    """A URL operand as the tool would read it: ``example.com/x`` means ``https://example.com/x``."""
    text = text.strip()
    if _URL.match(text):
        return text
    head = text.split("/", 1)[0].split(":", 1)[0]
    if _looks_like_host(head) or head == "localhost":
        return "https://" + text
    return None


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _url_has_room(url: str) -> bool:
    """Can this URL carry data of the sender's choosing: a query, or a long path segment?"""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    if parts.query or parts.username or parts.password:
        return True
    host = parts.hostname or ""
    if any(len(label) >= 20 for label in host.split(".")):
        return True
    return any(len(seg) >= 40 for seg in parts.path.split("/"))


def repo_from_url(url: str) -> str | None:
    """``git@github.com:Owner/Name.git`` or ``https://github.com/owner/name`` -> ``github.com/owner/name``."""
    url = url.strip()
    m = re.match(r"^(?:https?|ssh|git)://(?:[^@/\s]+@)?([^/:\s]+)(?::\d+)?/([^\s?#]+)", url) or \
        re.match(r"^(?:[^@/\s]+@)?([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}):([^\s?#]+)$", url)
    if not m:
        return None
    host, path = m.group(1).lower().rstrip("."), m.group(2).strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if "." not in host or "/" not in path:
        return None
    return f"{host}/{path.lower()}"


def git_remote_url(cwd: str | None, name: str) -> str | None:
    """The URL of a named remote, from ``.git/config`` of the nearest repository."""
    d = os.path.abspath(cwd or os.getcwd())
    for _ in range(40):
        path = os.path.join(d, ".git", "config")
        if os.path.isfile(path):
            parser = configparser.RawConfigParser(strict=False)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    parser.read_string("\n".join(line.strip() for line in fh))
            except (OSError, configparser.Error):
                return None
            section = f'remote "{name}"'
            for key in ("pushurl", "url"):
                if parser.has_option(section, key):
                    return parser.get(section, key)
            return None
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


# -- lexing ------------------------------------------------------------------------------------


class _Ctx:
    def __init__(self, cwd: str | None, depth: int = 0) -> None:
        self.cwd = cwd
        self.depth = depth
        self.dir: str | None = None                      # where an earlier `cd` in the command line went
        self.vars: dict[str, str] = {}
        self.locals: set[str] = set()                    # loop variables: set in the command, value unknown
        self.subs: list[tuple[str, BashAnalysis]] = []   # (kind, analysis) for each substitution
        self.heredocs: list[str] = []

    @property
    def here(self) -> str | None:
        """The directory the current simple command runs in, as far as it is known."""
        if self.dir is None or self.dir == _DIR_UNKNOWN:
            return self.cwd
        return os.path.join(self.cwd or "", os.path.expanduser(self.dir))


def _scan(command: str, ctx: _Ctx) -> str:
    """Replace substitutions with placeholders and turn newlines into ``;``.

    ``$(...)``, backticks and ``<(...)`` are analysed on their own and remembered; the
    placeholder keeps their position in the outer command. Single-quoted text is left
    alone.
    """
    out: list[str] = []
    i, n = 0, len(command)
    quote = ""
    while i < n:
        ch = command[i]
        if quote == "'":
            out.append(ch)
            if ch == "'":
                quote = ""
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            if command[i + 1] == "\n":   # line continuation
                i += 2
                continue
            out.append(command[i:i + 2])
            i += 2
            continue
        if ch == "'" and not quote:
            quote = "'"
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            quote = "" if quote == '"' else '"'
            out.append(ch)
            i += 1
            continue
        kind = ""
        if ch == "$" and command.startswith("$((", i):
            end = command.find("))", i)   # arithmetic, not a command
            end = n if end < 0 else end + 2
            out.append("0")
            i = end
            continue
        if ch == "$" and command.startswith("$(", i):
            kind, start = "cmd", i + 2
        elif ch in "<>" and command.startswith("(", i + 1) and not quote:
            kind, start = "proc", i + 2
        elif ch == "`":
            end = command.find("`", i + 1)
            end = n if end < 0 else end
            inner = command[i + 1:end]
            ctx.subs.append(("cmd", _analyze(inner, ctx.cwd, ctx.depth + 1, dict(ctx.vars))))
            out.append(f"\x00S{len(ctx.subs) - 1}\x00")
            i = end + 1
            continue
        if kind:
            depth, j, q = 1, start, ""
            while j < n and depth:
                c = command[j]
                if q:
                    if c == "\\" and q == '"':
                        j += 1
                    elif c == q:
                        q = ""
                elif c in "'\"":
                    q = c
                elif c == "\\":
                    j += 1
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                j += 1
            inner = command[start:j - 1] if depth == 0 else command[start:]
            ctx.subs.append((kind, _analyze(inner, ctx.cwd, ctx.depth + 1, dict(ctx.vars))))
            placeholder = f"\x00S{len(ctx.subs) - 1}\x00"
            out.append(placeholder if kind == "cmd" else f" {placeholder} ")
            i = j
            continue
        if ch == "\n" and not quote:
            out.append(" ; ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_HEREDOC_OPEN = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _lift_heredocs(command: str, ctx: _Ctx) -> str:
    """Take here-document bodies out of the command, leaving a marker where each one was announced.

    Line by line and in one pass. A single pattern that looks for each terminator from each
    ``<<`` scans to the end of the command once per unterminated here-document.
    """
    if "<<" not in command:
        return command
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_OPEN.search(line)
        if m is None or "<<<" in line[max(0, m.start() - 1):m.start() + 3]:
            out.append(line)
            i += 1
            continue
        word = m.group(2)
        end = next((j for j in range(i + 1, len(lines)) if lines[j].strip(" \t") == word), None)
        if end is None:          # never terminated: the shell would read to the end; leave the text alone
            out.extend(lines[i:])
            break
        ctx.heredocs.append("\n".join(lines[i + 1:end]))
        out.append(line[:m.start()] + f" \x00H{len(ctx.heredocs) - 1}\x00 " + line[m.end():])
        i = end + 1
    return "\n".join(out)


def _tokens(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


_OPERATORS = {";", "&", "&&", "||", "|", "|&", "(", ")", ";;"}


def _sequence(tokens: list[str]) -> list[tuple[str, list[list[str]]]]:
    """Tokens -> pipelines of simple commands, with the subshell brackets between them kept.

    Items are ``("pipeline", [[word, ...], ...])``, ``("(", [])`` and ``(")", [])``.
    """
    out: list[tuple[str, list[list[str]]]] = []
    current: list[list[str]] = [[]]

    def flush() -> None:
        nonlocal current
        cmds = [cmd for cmd in current if cmd]
        if cmds:
            out.append(("pipeline", cmds))
        current = [[]]

    for tok in tokens:
        if tok in ("|", "|&"):
            current.append([])
        elif tok in _OPERATORS or (set(tok) <= set(";&|()") and tok):
            flush()
            out.extend((ch, []) for ch in tok if ch in "()")
        else:
            current[-1].append(tok)
    flush()
    return out


def _split(tokens: list[str]) -> list[list[list[str]]]:
    """Tokens -> pipelines -> simple commands (each a list of words and redirection operators)."""
    return [cmds for kind, cmds in _sequence(tokens) if kind == "pipeline"]


# -- cd: where the rest of the command line runs ---------------------------------------------------

_DIR_UNKNOWN = "\x00unknown"
_REDIRECT_CHARS = set("<>&|")


def _cd_target(words: list[str]) -> str | None:
    """Where ``cd`` or ``pushd`` goes: a path, "" when it cannot be known, None for any other command."""
    if not words or words[0] not in ("cd", "pushd", "popd"):
        return None
    if words[0] == "popd":
        return ""
    target = None
    for w in words[1:]:
        if set(w) <= _REDIRECT_CHARS and ("<" in w or ">" in w):
            break
        if w == "--" or (len(w) == 2 and w[0] == "-" and w[1].isalpha()):
            continue
        target = w
        break
    if target is None:
        return "~"
    if target == "-" or any(ch in target for ch in "$`*?\x00"):
        return ""
    return target


def _join_dir(current: str | None, target: str) -> str:
    if target == "" or current == _DIR_UNKNOWN and not target.startswith(("/", "~")):
        return _DIR_UNKNOWN
    if current is None or target.startswith(("/", "~")):
        return target
    return posixpath.join(current, target)


def _rebase(path, directory: str):
    """A file operand as the hook's working directory sees it, after ``cd directory``."""
    if not isinstance(path, str) or not path or "://" in path or path[0] in "/~$-@\x00":
        return path
    head = path.split("/", 1)[0]
    if ":" in head:   # host:path
        return path
    return posixpath.normpath(posixpath.join(directory, path))


_PATH_LISTS = ("reads", "writes", "deletes", "uploads", "executed", "staged")


def _rebase_cmd(c: "_Cmd", directory: str) -> None:
    for name in _PATH_LISTS:
        setattr(c, name, [_rebase(x, directory) for x in getattr(c, name)])
    c.derived = [(_rebase(t, directory), _rebase(src, directory)) for t, src in c.derived]
    c.stdout_file = _rebase(c.stdout_file, directory)
    for inner in c.nested:
        for name in _PATH_LISTS:
            setattr(inner, name, [_rebase(x, directory) for x in getattr(inner, name)])
        inner.derived = [(_rebase(t, directory), _rebase(src, directory)) for t, src in inner.derived]


# -- one simple command ---------------------------------------------------------------------------


@dataclass
class _Cmd:
    program: str = ""
    raw_program: str = ""           # as written, with its directory
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    deletes: list[str] = field(default_factory=list)
    uploads: list[str] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)
    dests: list[tuple[str, str]] = field(default_factory=list)
    derived: list[tuple[str, str]] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)
    staged: list[str] = field(default_factory=list)
    env_reads: list[str] = field(default_factory=list)
    env_auth: list[str] = field(default_factory=list)
    env_dump: bool = False
    network: bool = False          # sends something to another machine
    sink_kind: str = ""
    payload: bool = False
    takes_stdin_as_data: bool = False   # a sink that forwards its stdin
    runs_stdin: bool = False            # an interpreter fed through stdin
    codec: str = ""                     # "encode" | "decode"
    prints_remote: bool = False
    prints_secret: bool = False
    passes_through: bool = True         # stdout carries (a transform of) stdin or of the files read
    stdout_file: str = ""
    literal_out: str = ""               # what echo/printf would print, when it is all literal
    nested: list[BashAnalysis] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)
    sub_idx: list[int] = field(default_factory=list)


def _opts(args: list[str], with_value: set[str], long_eq: bool = True) -> tuple[dict[str, list[str]], list[str]]:
    """Split arguments into options (with their values) and operands."""
    opts: dict[str, list[str]] = {}
    operands: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            operands.extend(args[i + 1:])
            break
        if a.startswith("--") and len(a) > 2:
            name, eq, value = a.partition("=")
            if eq and long_eq:
                opts.setdefault(name, []).append(value)
            elif name in with_value and i + 1 < len(args):
                opts.setdefault(name, []).append(args[i + 1])
                i += 1
            else:
                opts.setdefault(name, []).append("")
        elif a.startswith("-") and len(a) > 1 and not a[1:].replace(".", "").isdigit():
            if a in with_value:
                if i + 1 < len(args):
                    opts.setdefault(a, []).append(args[i + 1])
                    i += 1
                else:
                    opts.setdefault(a, []).append("")
            else:
                j = 1
                while j < len(a):
                    flag = "-" + a[j]
                    if flag in with_value:
                        rest = a[j + 1:]
                        if rest:
                            opts.setdefault(flag, []).append(rest)
                        elif i + 1 < len(args):
                            opts.setdefault(flag, []).append(args[i + 1])
                            i += 1
                        break
                    opts.setdefault(flag, []).append("")
                    j += 1
        else:
            operands.append(a)
        i += 1
    return opts, operands


def _vals(opts: dict[str, list[str]], *names: str) -> list[str]:
    return [v for n in names for v in opts.get(n, [])]


def _http_target(c: _Cmd, url: str) -> None:
    _add(c.dests, ("url", url))
    host = _host(url)
    if host:
        _add(c.dests, ("host", host))
    repo = repo_from_url(url) if host in ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org") else None
    if repo and repo.count("/") >= 2:
        _add(c.dests, ("repo", "/".join(repo.split("/")[:3])))
    if _url_has_room(url):
        c.payload = True


_CURL_VALUE = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json", "-F",
               "--form", "--form-string", "-T", "--upload-file", "-o", "--output", "-H", "--header", "-X", "--request",
               "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-K",
               "--config", "--url", "-x", "--proxy", "--cacert", "--cert", "--key", "-w", "--write-out",
               "--connect-timeout", "-m", "--max-time", "--retry", "--retry-delay", "--resolve", "--connect-to", "-E",
               "--oauth2-bearer", "--limit-rate", "-r", "--range", "-z", "-C", "--output-dir", "-D", "--dump-header",
               "--interface", "--unix-socket", "--aws-sigv4", "--proto", "--max-redirs", "--pinnedpubkey", "-Q"}


def _curl(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, _CURL_VALUE)
    c.network, c.sink_kind = True, "http"
    for value in _vals(opts, "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--json"):
        c.payload = True
        if value.startswith("@") and "--data-raw" not in opts:
            if value == "@-":
                c.takes_stdin_as_data = True
            else:
                _add(c.uploads, value[1:])
    for value in _vals(opts, "--data-urlencode"):
        c.payload = True
        _, at, path = value.partition("@")
        if at and path:
            _add(c.uploads, path)
    for value in _vals(opts, "-F", "--form"):
        c.payload = True
        _, eq, content = value.partition("=")
        if eq and content[:1] in ("@", "<"):
            _add(c.uploads, content[1:].split(";", 1)[0])
    for value in _vals(opts, "-T", "--upload-file"):
        c.payload = True
        if value in ("-", "."):
            c.takes_stdin_as_data = True
        else:
            _add(c.uploads, value)
    if _vals(opts, "-u", "--user", "-b", "--cookie", "--oauth2-bearer") or any(
            len(h) >= 40 for h in _vals(opts, "-H", "--header")):
        c.payload = True
    for value in _vals(opts, "-H", "--header", "-b", "--cookie"):
        if value.startswith("@"):
            _add(c.uploads, value[1:])
    for value in _vals(opts, "-K", "--config"):
        _add(c.reads, value)
        c.opaque.append("curl takes its arguments from a config file")
    urls = [u for u in (_url_of(x) for x in [*operands, *_vals(opts, "--url")]) if u]
    for url in urls:
        _http_target(c, url)
        _add(c.fetches, url)
    outs = [v for v in _vals(opts, "-o", "--output") if v not in ("-", "/dev/null", "/dev/stdout")]
    if "-O" in opts or "--remote-name" in opts or "--remote-name-all" in opts:
        outs += [u.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] for u in urls]
    for path in outs:
        _add(c.writes, path)
        for url in urls:
            _add(c.derived, (path, url))
    discards = any(v == "/dev/null" for v in _vals(opts, "-o", "--output"))
    c.prints_remote = bool(urls) and not outs and not discards
    c.passes_through = False
    if not urls and not c.opaque:
        c.opaque.append("curl has no readable URL")


_WGET_VALUE = {"-O", "--output-document", "-o", "--output-file", "-a", "-P", "--directory-prefix", "--post-data",
               "--post-file", "--body-data", "--body-file", "--method", "--header", "-U", "--user-agent", "-i",
               "--input-file", "--user", "--password", "-e", "--execute", "-t", "-T", "-w", "--limit-rate", "-Q",
               "--referer", "--load-cookies", "--save-cookies"}


def _wget(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, _WGET_VALUE)
    c.network, c.sink_kind = True, "http"
    for value in _vals(opts, "--post-file", "--body-file"):
        c.payload = True
        _add(c.uploads, value)
    if _vals(opts, "--post-data", "--body-data", "--user", "--password") or any(
            len(h) >= 40 for h in _vals(opts, "--header")):
        c.payload = True
    for value in _vals(opts, "-i", "--input-file"):
        _add(c.reads, value)
        c.opaque.append("wget takes its URLs from a file")
    urls = [u for u in (_url_of(x) for x in operands) if u]
    for url in urls:
        _http_target(c, url)
        _add(c.fetches, url)
    out = _vals(opts, "-O", "--output-document")
    if out and out[-1] == "-":
        c.prints_remote = bool(urls)
    else:
        targets = out or [u.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] or "index.html" for u in urls]
        for path in targets:
            _add(c.writes, path)
            for url in urls:
                _add(c.derived, (path, url))
    c.passes_through = False
    if not urls and not c.opaque:
        c.opaque.append("wget has no readable URL")


def _raw_socket(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, {"-p", "-s", "-w", "-i", "-e", "-c", "-x", "-X", "-q", "-g", "-G", "-O", "-I", "-T"})
    c.network, c.sink_kind, c.payload, c.takes_stdin_as_data = True, "shell-net", True, True
    c.passes_through = False
    hosts = [o for o in operands if _looks_like_host(o) or o == "localhost"]
    if "-l" in opts or "--listen" in opts:
        return
    if hosts:
        _add(c.dests, ("host", hosts[0].lower()))
    else:
        c.opaque.append(f"{c.program} has no readable host")


def _socat(c: _Cmd, args: list[str]) -> None:
    c.network, c.sink_kind, c.payload, c.takes_stdin_as_data = True, "shell-net", True, True
    c.passes_through = False
    found = False
    for a in args:
        m = re.match(r"^(?:TCP4?|TCP6|UDP4?|UDP6|OPENSSL|SSL|SCTP)(?:-CONNECT)?:([^:,\s]+):\d+", a, re.I)
        if m:
            _add(c.dests, ("host", m.group(1).lower()))
            found = True
        m = re.match(r"^(?:FILE|OPEN):([^,\s]+)", a, re.I)
        if m:
            _add(c.reads, m.group(1))
    if not found:
        c.opaque.append("socat has no readable remote address")


_SSH_VALUE = {"-p", "-i", "-l", "-o", "-L", "-R", "-D", "-F", "-J", "-b", "-c", "-e", "-m", "-S", "-W", "-w", "-E",
              "-B", "-I", "-O", "-Q", "-P"}


def _ssh(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, _SSH_VALUE)
    c.network, c.sink_kind, c.payload, c.takes_stdin_as_data = True, "shell-net", True, True
    c.passes_through = False
    if operands:
        _add(c.dests, ("host", operands[0].rsplit("@", 1)[-1].lower()))
    else:
        c.opaque.append("ssh has no readable host")
    for value in _vals(opts, "-i"):
        _add(c.reads, value)


def _copy_remote(c: _Cmd, args: list[str]) -> None:
    """scp and rsync: whichever side names a host is remote."""
    opts, operands = _opts(args, {"-P", "-i", "-o", "-F", "-J", "-l", "-c", "-S", "-e", "--rsh", "--exclude",
                                  "--include", "--files-from", "--password-file", "--port", "--bwlimit", "-T"})
    c.passes_through = False
    if len(operands) < 2:
        return

    def remote(spec: str) -> str | None:
        if spec.startswith(("rsync://", "ssh://", "scp://")):
            return _host(spec)
        m = _REMOTE_SPEC.match(spec)
        if m and not spec.startswith(("/", "./", "../", "~")) and (_looks_like_host(m.group(2)) or m.group(1)):
            return m.group(2).lower()
        return None

    *sources, target = operands
    target_host = remote(target)
    if target_host:
        c.network, c.sink_kind, c.payload = True, "shell-net", True
        _add(c.dests, ("host", target_host))
        for src in sources:
            if not remote(src):
                _add(c.uploads, src)
    else:
        for src in sources:
            host = remote(src)
            if host:
                c.network, c.sink_kind = True, "shell-net"
                _add(c.dests, ("host", host))
                _add(c.writes, target)
                _add(c.derived, (target, f"ssh://{host}/"))
            else:
                _add(c.reads, src)
                _add(c.writes, target)
                _add(c.derived, (target, src))
    for value in _vals(opts, "--files-from"):
        _add(c.reads, value)


def _git(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    """A git command. With ``-C DIR`` its file operands belong to DIR."""
    marks = {name: len(getattr(c, name)) for name in _PATH_LISTS}
    _git_inner(c, args, ctx)
    i, directory = 0, None
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            directory = args[i + 1] if directory is None else posixpath.join(directory, args[i + 1])
            i += 1
        elif args[i] == "-c":
            i += 1
        i += 1
    if directory and not any(ch in directory for ch in "$`\x00"):
        for name, n in marks.items():
            items = getattr(c, name)
            items[n:] = [_rebase(x, directory) for x in items[n:]]


def _git_inner(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    c.passes_through = False
    cwd = ctx.here
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            cwd = os.path.join(cwd or "", args[i + 1])
            i += 1
        elif args[i] == "-c":
            i += 1
        i += 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    opts, operands = _opts(rest, {"-o", "--repo", "--receive-pack", "--exec", "-b", "--branch", "--depth", "-m",
                                  "--message", "-F", "--file", "--upload-pack", "--reference", "--origin"})

    def target(spec: str) -> None:
        url = spec if ("://" in spec or "@" in spec or spec.count(":") == 1 and "/" in spec) else git_remote_url(cwd, spec)
        if not url:
            c.opaque.append(f"git remote {spec!r} is not defined in .git/config")
            return
        repo = repo_from_url(url)
        if repo:
            _add(c.dests, ("repo", repo))
        else:
            host = _host(url) or (url.split("@")[-1].split(":")[0] if ":" in url else None)
            if host:
                _add(c.dests, ("host", host.lower()))
            else:
                c.opaque.append("git target is not a readable URL")

    if sub == "push":
        c.network, c.sink_kind, c.payload = True, "git", True
        specs = [_vals(opts, "--repo")[-1]] if _vals(opts, "--repo") else operands[:1]
        target(specs[0] if specs else "origin")
    elif sub == "remote" and operands[:1] in (["add"], ["set-url"]):
        _add(c.writes, os.path.join(cwd or ".", ".git", "config"))
    elif sub in ("clone", "fetch", "pull", "ls-remote") or (sub == "submodule" and "update" in operands):
        spec = next((o for o in operands if "://" in o or "@" in o), None)
        if sub == "clone" and spec:
            url = spec
            _add(c.fetches, url)
            directory = next((o for o in operands if o != spec), "") or spec.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
            _add(c.writes, directory)
            _add(c.derived, (directory, url if "://" in url else "ssh://" + url.replace(":", "/", 1)))
    elif sub == "config":
        scope = "~/.gitconfig" if ("--global" in opts or "--system" in opts) else os.path.join(cwd or ".", ".git", "config")
        if len(operands) >= 2 or "--add" in opts or "--unset" in opts:
            _add(c.writes, scope)
    elif sub == "add":
        for path in operands:
            if path not in (".", "-A", "--all"):
                _add(c.staged, path)
        if not operands or "." in operands or "-A" in opts or "--all" in opts or "-u" in opts:
            _add(c.staged, ".")
    elif sub == "send-email":
        c.network, c.sink_kind, c.payload = True, "email", True
        for value in _vals(opts, "--to", "--cc", "--bcc"):
            _add(c.dests, ("email", value.lower()))
    elif sub == "credential" or (sub == "config" and any("credential" in o for o in operands) and len(operands) == 1):
        c.prints_secret = True


_GH_READ_ACTIONS = {"view", "list", "diff", "checks", "status", "watch"}
_GH_WRITE_ACTIONS = {"create", "comment", "edit", "close", "reopen", "merge", "review", "ready", "delete", "transfer",
                     "upload", "set", "fork", "rename", "sync", "lock", "pin", "develop"}


def _gh(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    c.passes_through = False
    opts, operands = _opts(args, {"-R", "--repo", "-b", "--body", "-F", "--body-file", "-t", "--title", "-f", "--field",
                                  "--raw-field", "-X", "--method", "--input", "-H", "--header", "-q", "--jq", "-a",
                                  "-l", "-m", "-d", "--desc", "-n", "--notes", "--notes-file", "-B", "--base", "--head",
                                  "-L", "--limit", "-S", "--search", "-s", "--state", "--json", "--template", "-e",
                                  "--env", "-o", "--org", "--hostname", "-p", "-w"})
    if not operands:
        return
    group = operands[0]
    action = operands[1] if len(operands) > 1 else ""

    def repo_target() -> None:
        named = _vals(opts, "-R", "--repo")
        if named:
            spec = named[-1]
            repo = repo_from_url(spec) if "://" in spec else (spec.lower() if spec.count("/") == 2 else f"github.com/{spec.lower()}")
            _add(c.dests, ("repo", repo))
            return
        url = git_remote_url(ctx.here, "origin")
        repo = repo_from_url(url) if url else None
        if repo:
            _add(c.dests, ("repo", repo))
        else:
            _add(c.dests, ("host", "github.com"))

    if group == "api":
        endpoint = action
        writes = bool(_vals(opts, "-f", "--field", "-F", "--raw-field", "--input")) or (
            (_vals(opts, "-X", "--method") or ["GET"])[-1].upper() != "GET")
        m = re.match(r"^/?repos/([^/\s]+)/([^/\s]+)", endpoint)
        if writes:
            c.network, c.sink_kind, c.payload = True, "git", True
            _add(c.dests, ("repo", f"github.com/{m.group(1).lower()}/{m.group(2).lower()}") if m else ("host", "api.github.com"))
            for value in _vals(opts, "--input"):
                if value != "-":
                    _add(c.uploads, value)
                else:
                    c.takes_stdin_as_data = True
            for value in _vals(opts, "-F", "--field"):
                _, eq, content = value.partition("=")
                if eq and content.startswith("@") and content != "@-":
                    _add(c.uploads, content[1:])
        else:
            c.prints_remote = True
        return
    if group == "gist" and action == "create":
        c.network, c.sink_kind, c.payload = True, "git", True
        _add(c.dests, ("host", "gist.github.com"))
        files = [o for o in operands[2:] if o != "-"]
        for f in files:
            _add(c.uploads, f)
        if not files or "-" in operands[2:]:
            c.takes_stdin_as_data = True
        return
    if group == "auth" and action in ("token", "status"):
        c.prints_secret = action == "token" or "--show-token" in opts or "-t" in opts
        return
    if group == "search":
        c.prints_remote = True
        return
    if action in _GH_READ_ACTIONS or (group == "run" and action in ("view", "list")):
        c.prints_remote = True
        return
    if action in _GH_WRITE_ACTIONS and group in ("issue", "pr", "release", "repo", "secret", "variable", "label",
                                                 "discussion", "gist", "workflow", "run"):
        c.network, c.sink_kind, c.payload = True, "git", True
        repo_target()
        for value in _vals(opts, "-F", "--body-file", "--notes-file"):
            if value == "-":
                c.takes_stdin_as_data = True
            else:
                _add(c.uploads, value)
        if group == "release" and action == "upload":
            for f in operands[3:]:
                _add(c.uploads, f.split("#", 1)[0])


def _is_remote_spec(spec: str) -> str | None:
    """A package spec that names a URL or a repository rather than a registry package."""
    if re.match(r"^(?:git\+|hg\+|svn\+)?(?:https?|ssh|git|file)://", spec):
        return spec.split("+", 1)[-1] if spec.split("+", 1)[0] in ("git", "hg", "svn") else spec
    if re.match(r"^(?:github|gitlab|bitbucket):[\w.-]+/[\w.-]+", spec):
        return "https://" + spec.replace("github:", "github.com/").replace("gitlab:", "gitlab.com/").replace("bitbucket:", "bitbucket.org/")
    if spec.startswith("git@"):
        return "ssh://" + spec.replace(":", "/", 1)
    return None


def _package_manager(c: _Cmd, args: list[str]) -> None:
    c.passes_through = False
    program = c.program
    opts, operands = _opts(args, {"-r", "--requirement", "-i", "--index-url", "--extra-index-url", "--registry", "-c",
                                  "--constraint", "-e", "--editable", "--tag", "--otp", "--git", "--repository-url",
                                  "--repository", "-u", "--username", "-p", "--password", "--find-links", "-f",
                                  "--target", "-t", "--prefix", "--from", "--with", "--python"})
    if program in ("uv",) and operands[:1] == ["pip"]:
        operands = operands[1:]
    if program in ("pnpm", "yarn", "bun") and operands[:1] == ["dlx"]:
        operands = ["exec-remote", *operands[1:]]
    if program in ("npx", "bunx", "uvx", "pipx"):
        operands = ["exec-remote", *[o for o in operands if o != "run"]]
    verb = operands[0] if operands else ""
    rest = operands[1:]
    if verb == "publish" or program == "twine" and verb == "upload":
        c.network, c.sink_kind, c.payload = True, "publish", True
        registry = (_vals(opts, "--registry", "--repository-url") or [None])[-1]
        host = _host(registry) if registry else {"twine": "upload.pypi.org"}.get(program, "registry.npmjs.org")
        _add(c.dests, ("host", host or "registry.npmjs.org"))
        if program == "twine":
            for f in rest:
                _add(c.uploads, f)
        return
    if verb in ("install", "add", "i", "ci", "download", "get", "exec-remote", "sync", "tool"):
        for value in _vals(opts, "-r", "--requirement", "-c", "--constraint"):
            _add(c.reads, value)
        for value in _vals(opts, "-i", "--index-url", "--extra-index-url", "--registry", "--find-links", "-f"):
            url = _url_of(value)
            if url:
                _add(c.fetches, url)
        for spec in [*rest, *_vals(opts, "--git", "--from", "-e", "--editable")]:
            url = _is_remote_spec(spec)
            if url:
                _add(c.fetches, url)
                _add(c.executed, url)   # install scripts and build back ends run code from it


def _container(c: _Cmd, args: list[str]) -> None:
    c.passes_through = False
    opts, operands = _opts(args, {"-u", "--username", "-p", "--password", "-f", "--file", "-t", "--tag", "-e", "--env",
                                  "-v", "--volume", "--name", "-w", "--workdir", "--network", "--platform"})
    verb = operands[0] if operands else ""
    if verb in ("push", "login"):
        c.network, c.sink_kind, c.payload = True, "publish", True
        ref = operands[1] if len(operands) > 1 else ""
        first = ref.split("/", 1)[0]
        host = first if ("." in first or ":" in first) and "/" in ref else ("docker.io" if verb == "push" or not ref else first)
        _add(c.dests, ("host", host.split(":", 1)[0].lower()))


def _cloud(c: _Cmd, args: list[str]) -> None:
    c.passes_through = False
    program = c.program
    opts, operands = _opts(args, {"--endpoint-url", "--profile", "--region", "--bucket", "--key", "--body", "--file",
                                  "--account-name", "--container-name", "--name", "-n", "-c", "--secret-id", "--query",
                                  "--output", "-m", "--cache-control", "--content-type", "--content-encoding", "--acl",
                                  "--exclude", "--include", "--storage-class", "--metadata", "--sse", "--expires",
                                  "--grants", "--content-disposition", "--metadata-directive", "--page-size"})
    words = " ".join(operands)
    if re.search(r"\b(?:secretsmanager\s+get-secret-value|ssm\s+get-parameters?\b.*|sts\s+get-session-token|"
                 r"configure\s+(?:get|export-credentials)|secrets\s+versions\s+access|auth\s+print-access-token|"
                 r"account\s+get-access-token|keyvault\s+secret\s+show)", words):
        c.prints_secret = True
    remote = [o for o in operands if re.match(r"^(?:s3|gs)://", o)]
    local = [o for o in operands if o not in remote]
    copying = any(v in operands for v in ("cp", "mv", "sync", "rsync", "put-object", "upload", "upload-batch"))
    if not copying:
        return
    endpoint = (_vals(opts, "--endpoint-url") or [None])[-1]
    target = operands[-1] if operands else ""
    if target in remote or program == "az" or "put-object" in operands:
        c.network, c.sink_kind, c.payload = True, "cloud", True
        if endpoint and _host(endpoint):
            _add(c.dests, ("host", _host(endpoint)))
        elif target in remote:
            scheme, bucket = target.split("://", 1)
            bucket = bucket.split("/", 1)[0]
            _add(c.dests, ("host", f"{bucket}.s3.amazonaws.com" if scheme == "s3" else "storage.googleapis.com"))
            if scheme == "gs":
                _add(c.dests, ("url", f"https://storage.googleapis.com/{bucket}"))
        elif _vals(opts, "--account-name"):
            _add(c.dests, ("host", f"{_vals(opts, '--account-name')[-1].lower()}.blob.core.windows.net"))
        elif _vals(opts, "--bucket"):
            _add(c.dests, ("host", f"{_vals(opts, '--bucket')[-1]}.s3.amazonaws.com"))
        else:
            c.opaque.append(f"{program} upload has no readable destination")
        sources = [o for o in local if o not in ("s3", "s3api", "storage", "blob", "cp", "mv", "sync", "rsync",
                                                 "put-object", "upload", "upload-batch", "-r", "-m")]
        for src in [*sources, *_vals(opts, "--body", "--file")]:
            _add(c.uploads, src)
    elif remote:
        for src in remote:
            _add(c.fetches, src)
        if target and target not in remote:
            _add(c.writes, target)
            _add(c.derived, (target, remote[0]))


def _mail(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, {"-s", "-a", "-A", "--attach", "-c", "-b", "-r", "-S", "-f", "-F", "--to", "--from",
                                  "--server", "--body", "--header", "-t", "-i", "-e", "-H", "-x"})
    c.network, c.sink_kind, c.payload, c.takes_stdin_as_data = True, "email", True, True
    c.passes_through = False
    addresses = [o for o in [*operands, *_vals(opts, "-c", "-b", "--to")] if "@" in o]
    for address in addresses:
        _add(c.dests, ("email", address.strip("<>").lower()))
    for value in _vals(opts, "-a", "-A", "--attach"):
        if not value.lower().startswith(("content-", "x-", "subject:", "from:")):
            _add(c.uploads, value)
    if not addresses:
        c.opaque.append(f"{c.program} has no readable recipient")


def _name_lookup(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, {"-c", "-i", "-I", "-t", "-W", "-w", "-s", "-p", "-q", "-x", "-b", "-k", "-y", "-f", "-m"})
    c.passes_through = False
    for o in operands:
        name = o.lstrip("@")
        computed = _SUB.search(name) or "$" in name
        if computed:
            # ping $(...).dns.example: the labels in front are data, the written suffix is the destination
            suffix = re.split(r"\x00S\d+\x00|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", name)[-1].lstrip(".-_")
            if _looks_like_host(suffix):
                c.network, c.sink_kind, c.payload = True, "dns", True
                _add(c.dests, ("host", suffix.lower().rstrip(".")))
        elif _looks_like_host(name):
            c.network, c.sink_kind = True, "dns"
            _add(c.dests, ("host", name.lower().rstrip(".")))
            if any(len(label) >= 20 for label in name.split(".")):
                c.payload = True   # a long label is room for data


def _openssl(c: _Cmd, args: list[str]) -> None:
    opts, operands = _opts(args, {"-connect", "-in", "-out", "-k", "-pass", "-K", "-iv", "-servername", "-CAfile",
                                  "-cert", "-key", "-inkey", "-keyout", "-passin", "-passout"}, long_eq=False)
    verb = operands[0] if operands else ""
    for value in _vals(opts, "-in"):
        _add(c.reads, value)
    for value in _vals(opts, "-out", "-keyout"):
        _add(c.writes, value)
    if verb == "s_client":
        c.network, c.sink_kind, c.payload, c.takes_stdin_as_data = True, "shell-net", True, True
        c.passes_through = False
        target = (_vals(opts, "-connect") or [""])[-1]
        if target:
            _add(c.dests, ("host", target.rsplit(":", 1)[0].strip("[]").lower()))
        else:
            c.opaque.append("openssl s_client has no readable host")
    elif verb in ("enc", "base64", "aes-256-cbc", "des3", "smime", "cms", "pkeyutl", "rsautl"):
        c.codec = "decode" if "-d" in opts else "encode"


def _scan_code(c: _Cmd, code: str, ctx: _Ctx) -> None:
    """Inline program text given to an interpreter: look for where it reads and where it sends."""
    urls = [u.rstrip(".,)'\"") for u in _URL.findall(code)]
    networked = bool(_NET_CODE.search(code))
    for m in _CODE_OPEN.finditer(code):
        if not m.group(2).startswith(("http://", "https://")):
            _add(c.reads, m.group(2))
    for m in _ENV_IN_CODE.finditer(code):
        _add(c.env_reads, m.group(1))
    if _ENV_ALL_IN_CODE.search(code):
        c.env_dump = True
    if networked:
        c.network, c.sink_kind, c.payload = True, "http", True
        # Code that opens files and talks to the network can send what it opened.
        for path in c.reads:
            _add(c.uploads, path)
        if urls:
            for url in urls:
                _http_target(c, url)
        else:
            c.opaque.append(f"{c.program} code talks to the network at an address that is not written out")
    m = _SHELL_FROM_CODE.search(code)
    if m and ctx.depth < MAX_DEPTH:
        c.nested.append(_analyze(m.group(2), ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
    elif re.search(r"subprocess|os\.system|child_process|\bexec\s*\(|\beval\s*\(|__import__|compile\s*\(", code) and not m:
        if re.search(r"\beval\s*\(|\bexec\s*\(|__import__|compile\s*\(|b64decode|fromhex|atob\s*\(|Buffer\.from", code):
            c.opaque.append(f"{c.program} code builds and runs other code")


def _heredoc_body(args: list[str], ctx: _Ctx) -> str | None:
    for a in args:
        m = _HERE.fullmatch(a)
        if m and int(m.group(1)) < len(ctx.heredocs):
            return ctx.heredocs[int(m.group(1))]
    return None


def _interpreter(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    c.passes_through = False
    flag = _CODE_FLAG.get(c.program, "-c")
    code = _heredoc_body(args, ctx)
    script = None
    i = 0
    while i < len(args) and code is None:
        a = args[i]
        if a == flag and i + 1 < len(args):
            code = args[i + 1]
            break
        if a == "-m" and i + 1 < len(args):
            module = args[i + 1]
            bind = next((args[j + 1] for j, x in enumerate(args[:-1]) if x in ("--bind", "-b")), "")
            # Bound to loopback, a preview server puts nothing on the network.
            if module in ("http.server", "SimpleHTTPServer") and bind not in ("127.0.0.1", "localhost", "::1"):
                c.network, c.sink_kind, c.payload = True, "shell-net", True
                c.opaque.append("serves the current directory over HTTP")
            script = "-m"
            break
        if a == "-":
            break
        if not a.startswith("-"):
            script = a
            break
        i += 1
    if code is not None:
        subs = [int(x) for x in _SUB.findall(code)]
        for idx in subs:
            _add(c.sub_idx, idx)
        if subs and not _SUB.sub("", code).strip():   # python -c "$(curl ...)": the code is another command's output
            c.runs_stdin = True
        else:
            _scan_code(c, code, ctx)
    elif script is None:
        c.runs_stdin = True
    elif script != "-m":
        m = _SUB.fullmatch(script.strip())
        if m:   # python <(curl ...)
            c.runs_stdin = True
            _add(c.sub_idx, int(m.group(1)))
        else:
            _add(c.executed, script)


def _shell(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    c.passes_through = False
    body = _heredoc_body(args, ctx)
    if body is not None:
        if ctx.depth < MAX_DEPTH:
            c.nested.append(_analyze(body, ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
        return
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and "c" in a[1:] and not a.startswith("--") and i + 1 < len(args):
            text = args[i + 1]
            subs = [int(x) for x in _SUB.findall(text)]
            for idx in subs:
                _add(c.sub_idx, idx)
            remainder = _SUB.sub("", text).strip().strip("\"'")
            if subs and not remainder:   # sh -c "$(curl ...)"
                c.runs_stdin = True
            elif ctx.depth < MAX_DEPTH:
                c.nested.append(_analyze(_SUB.sub(" ", text), ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
            return
        if not a.startswith("-"):
            m = _SUB.fullmatch(a.strip())
            if m:   # bash <(curl ...)
                c.runs_stdin = True
                _add(c.sub_idx, int(m.group(1)))
            else:
                _add(c.executed, a)
                _add(c.reads, a)
            return
        i += 1
    c.runs_stdin = True


_FIRST_ARG_IS_PROGRAM = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "jq", "yq"}
_PLAIN_READERS = {"cat", "tac", "head", "tail", "less", "more", "bat", "nl", "wc", "sort", "uniq", "cut", "paste",
                  "strings", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "cksum", "diff", "cmp", "comm",
                  "column", "fold", "rev", "expand", "zcat", "bzcat", "xzcat", "gunzip", "file"}
_READER_VALUE = {"-n", "-c", "-e", "-f", "-A", "-B", "-C", "-m", "-d", "-k", "-t", "-s", "-o", "-w", "--arg",
                 "--argjson", "-g", "--glob", "--type", "-F", "-v", "--max-count", "--include", "--exclude",
                 "--exclude-dir", "-j", "--color", "--lines", "--bytes"}


def _reader(c: _Cmd, args: list[str]) -> None:
    program = c.program
    opts, operands = _opts(args, _READER_VALUE if program not in ("cat", "tac", "wc", "strings", "file") else set())
    if program in _FIRST_ARG_IS_PROGRAM and not _vals(opts, "-e", "-f") and operands:
        operands = operands[1:]
    for value in _vals(opts, "-f") if program in ("grep", "egrep", "fgrep", "sed", "awk", "gawk", "jq") else []:
        _add(c.reads, value)
    for op in operands:
        if op != "-" and not op.startswith("\x00") and not re.fullmatch(r"[-+]\d+", op):
            _add(c.reads, op)
    if program == "sed" and any(k.startswith("-i") for k in opts):
        for op in operands:
            _add(c.writes, op)
    if program in ("base64", "base32", "xxd", "od", "hexdump", "gzip", "bzip2", "xz", "zstd", "gunzip", "zcat"):
        decode = program in ("gunzip", "zcat") or any(k in opts for k in ("-d", "--decode", "-D", "-r", "--decompress"))
        c.codec = "decode" if decode else "encode"


def _writer(c: _Cmd, args: list[str]) -> None:
    program = c.program
    opts, operands = _opts(args, {"-t", "--target-directory", "-m", "--mode", "-o", "--owner", "-g", "--group", "-S",
                                  "--suffix", "-s", "--size", "-r", "--reference"} if program != "chmod" else set())
    c.passes_through = program == "tee"
    if program in ("cp", "mv", "install", "ln"):
        target_dir = (_vals(opts, "-t", "--target-directory") or [None])[-1]
        if target_dir:
            sources, target = operands, target_dir
        elif len(operands) >= 2:
            *sources, target = operands
        else:
            return
        _add(c.writes, target)
        for src in sources:
            _add(c.reads, src)
            _add(c.derived, (target, src))
            if program == "mv":
                _add(c.deletes, src)
    elif program == "dd":
        for a in args:
            if a.startswith("if="):
                _add(c.reads, a[3:])
            elif a.startswith("of="):
                _add(c.writes, a[3:])
        srcs = [a[3:] for a in args if a.startswith("if=")]
        for a in args:
            if a.startswith("of=") and srcs:
                _add(c.derived, (a[3:], srcs[0]))
    elif program in ("rm", "rmdir", "shred", "unlink"):
        for op in operands:
            _add(c.deletes, op)
    elif program in ("chmod", "chown", "chgrp"):
        for op in operands[1:]:
            _add(c.writes, op)
    elif program == "crontab":
        if "-l" not in opts:
            _add(c.writes, "/var/spool/cron/crontabs/user")
        for op in operands:
            if op != "-":
                _add(c.reads, op)
    else:   # tee, touch, mkdir, truncate
        for op in operands:
            if op != "-":
                _add(c.writes, op)


def _archive(c: _Cmd, args: list[str]) -> None:
    program = c.program
    c.codec = "encode"
    if program == "tar":
        flags = "".join(a.lstrip("-") for a in args if not a.startswith("--") and (a.startswith("-") or a is args[0]))
        opts, operands = _opts([a if a.startswith("-") or i else "-" + a for i, a in enumerate(args)],
                               {"-f", "--file", "-C", "--directory", "-T", "--files-from", "-X", "--exclude"})
        archive = (_vals(opts, "-f", "--file") or [None])[-1]
        creating = "c" in flags or "--create" in opts or "r" in flags or "u" in flags
        if creating:
            for op in operands:
                _add(c.reads, op)
            if archive and archive != "-":
                _add(c.writes, archive)
                for op in operands:
                    _add(c.derived, (archive, op))
        else:
            c.codec = "decode"
            if archive and archive != "-":
                _add(c.reads, archive)
    elif program in ("zip", "7z", "7za", "rar"):
        opts, operands = _opts(args, {"-P", "--password", "-x", "-i", "-b", "-t"})
        ops = operands[1:] if program != "zip" and operands[:1] and operands[0] in ("a", "x", "e", "l", "u") else operands
        if ops:
            archive, *sources = ops
            _add(c.writes, archive)
            for src in sources:
                _add(c.reads, src)
                _add(c.derived, (archive, src))
    else:   # unzip, unrar
        c.codec = "decode"
        opts, operands = _opts(args, {"-d", "-P", "-x"})
        if operands:
            _add(c.reads, operands[0])


def _find(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    roots: list[str] = []
    for op in args:
        if op.startswith("-") or op in ("(", "!"):
            break
        roots.append(op)
    roots = roots or ["."]
    for i, a in enumerate(args):
        if a in ("-exec", "-execdir", "-ok") and ctx.depth < MAX_DEPTH:
            end = next((j for j in range(i + 1, len(args)) if args[j] in (";", "+", "\\;")), len(args))
            inner = _analyze(" ".join(shlex.quote(x) for x in args[i + 1:end]), ctx.cwd, ctx.depth + 1, dict(ctx.vars))
            # "{}" is each file found: whatever the inner command does to it, it does under the roots.
            for name in ("reads", "writes", "uploads", "deletes"):
                items = getattr(inner, name)
                if "{}" in items:
                    items.remove("{}")
                    for root in roots:
                        _add(items, root)
            c.nested.append(inner)
        elif a == "-delete":
            for root in roots:
                _add(c.deletes, root)
    for root in roots:
        _add(c.reads, root)


def _echo(c: _Cmd, args: list[str]) -> None:
    words = [a for a in args if not (a.startswith("-") and set(a[1:]) <= set("neE"))]
    text = " ".join(words)
    if not _SUB.search(text) and "$" not in text:
        c.literal_out = text
    c.passes_through = True


def _dispatch(c: _Cmd, args: list[str], ctx: _Ctx) -> None:
    p = c.program
    if p == "curl":
        _curl(c, args)
    elif p == "wget":
        _wget(c, args)
    elif p in ("http", "https", "xh", "httpie"):
        opts, operands = _opts(args, {"-a", "--auth", "-o", "--output", "--proxy", "-A"})
        c.network, c.sink_kind, c.passes_through = True, "http", False
        items = [o for o in operands if o.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")]
        if items and _url_of(items[0]):
            _http_target(c, _url_of(items[0]))
            _add(c.fetches, _url_of(items[0]))
            c.prints_remote = True
        if len(items) > 1 or len(operands) != len(items):
            c.payload = True
        for item in items[1:]:
            if "@" in item and not item.startswith("@"):
                _add(c.uploads, item.split("@", 1)[1])
            elif item.startswith("@"):
                _add(c.uploads, item[1:])
    elif p in ("nc", "ncat", "netcat", "telnet"):
        _raw_socket(c, args)
    elif p == "socat":
        _socat(c, args)
    elif p in ("ssh", "sftp", "mosh"):
        _ssh(c, args)
    elif p in ("scp", "rsync"):
        _copy_remote(c, args)
    elif p in ("ftp", "lftp", "tftp"):
        c.network, c.sink_kind, c.payload, c.passes_through = True, "shell-net", True, False
        hosts = [a for a in args if _looks_like_host(a) or "://" in a]
        if hosts:
            _add(c.dests, ("host", (_host(hosts[0]) or hosts[0]).lower()))
        else:
            c.opaque.append(f"{p} has no readable host")
    elif p == "git":
        _git(c, args, ctx)
    elif p == "gh":
        _gh(c, args, ctx)
    elif p in ("npm", "pnpm", "yarn", "bun", "npx", "bunx", "pip", "pip3", "uv", "uvx", "pipx", "poetry", "twine",
               "cargo", "go", "gem", "brew"):
        _package_manager(c, args)
    elif p in ("docker", "podman", "nerdctl"):
        _container(c, args)
    elif p in ("aws", "gsutil", "gcloud", "az", "s3cmd", "rclone", "mc"):
        _cloud(c, args)
    elif p in ("mail", "mailx", "sendmail", "mutt", "msmtp", "swaks", "s-nail"):
        _mail(c, args)
    elif p in ("dig", "nslookup", "host", "drill", "ping", "ping6", "traceroute", "tracepath", "whois"):
        _name_lookup(c, args)
    elif p == "openssl":
        _openssl(c, args)
    elif p in _SHELLS:
        _shell(c, args, ctx)
    elif p in _INTERPRETERS:
        _interpreter(c, args, ctx)
    elif p in ("source", "."):
        c.passes_through = False
        if args:
            m = _SUB.fullmatch(args[0].strip())
            if m:
                c.runs_stdin = True
                _add(c.sub_idx, int(m.group(1)))
            else:
                _add(c.reads, args[0])
                _add(c.executed, args[0])
    elif p == "eval":
        c.passes_through = False
        text = " ".join(args)
        subs = [int(x) for x in _SUB.findall(text)]
        for idx in subs:
            _add(c.sub_idx, idx)
        if subs and not _SUB.sub("", text).strip():
            c.runs_stdin = True
        elif subs or "$" in text:
            c.opaque.append("eval runs text that is not written out in the command")
        elif ctx.depth < MAX_DEPTH:
            c.nested.append(_analyze(text, ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
    elif p in ("printenv", "env", "set", "export", "declare", "typeset", "compgen"):
        c.passes_through = False
        names = [a for a in args if not a.startswith("-") and "=" not in a]
        if p == "printenv" and names:
            for name in names:
                _add(c.env_reads, name)
        elif p in ("printenv", "env") and not names or p == "set" and not args or \
                p in ("export", "declare", "typeset") and (not args or set(args) <= {"-p", "-x", "-px"}):
            c.env_dump = True
    elif p in ("echo", "printf"):
        _echo(c, args)
    elif p in _PLAIN_READERS or p in _FIRST_ARG_IS_PROGRAM or p in ("base64", "base32", "xxd", "od", "hexdump",
                                                                    "gzip", "bzip2", "xz", "zstd"):
        _reader(c, args)
    elif p in ("tar", "zip", "unzip", "7z", "7za", "rar", "unrar"):
        _archive(c, args)
    elif p in ("cp", "mv", "install", "ln", "dd", "tee", "touch", "mkdir", "truncate", "rm", "rmdir", "shred",
               "unlink", "chmod", "chown", "chgrp", "crontab"):
        _writer(c, args)
    elif p == "find":
        _find(c, args, ctx)
    elif p == "xargs":
        opts, operands = _opts(args, {"-I", "-n", "-P", "-d", "-L", "-s", "-E", "--max-args", "--max-procs", "-a"})
        if operands and ctx.depth < MAX_DEPTH:
            inner = " ".join(shlex.quote(x) for x in operands if x not in _vals(opts, "-I"))
            c.nested.append(_analyze(inner, ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
    elif p in ("kubectl", "oc") and "secret" in " ".join(args) and "get" in args:
        c.prints_secret = True
    elif p in ("pass", "op", "bw", "vault", "security", "secret-tool", "keyring") and any(
            a in ("show", "get", "read", "find-generic-password", "lookup", "item") for a in args):
        c.prints_secret = True
    else:
        c.passes_through = False
        if "/" in c.raw_program and not c.raw_program.startswith("-"):
            _add(c.executed, c.raw_program)   # ./tool or /tmp/x.sh: a file on disk is being run


_AUTH_HEADER = re.compile(
    r"^\s*(?:authorization|proxy-authorization|private-token|x-[\w-]*(?:key|token|auth|secret)[\w-]*|[\w-]*api-?key[\w-]*)\s*:", re.I)
_AUTH_FLAGS = {"-u", "--user", "--oauth2-bearer", "-p", "--password", "--token"}


def _auth_only_vars(raw_args: list[str], ctx: _Ctx) -> list[str]:
    """Variables that appear only where a credential belongs: ``-u``, ``--oauth2-bearer``, an auth header.

    That is authentication. A variable that also appears in the URL, a body or any other
    argument is data on its way out.
    """
    auth: list[str] = []
    data: list[str] = []

    def names(word: str) -> list[str]:
        found = [m.group(1) or m.group(2) for m in _VAR.finditer(word)]
        return [n for n in found if n not in ctx.vars and n not in ctx.locals]

    i = 0
    while i < len(raw_args):
        a = raw_args[i]
        nxt = raw_args[i + 1] if i + 1 < len(raw_args) else ""
        if a in ("-H", "--header") and nxt:
            (auth if _AUTH_HEADER.match(nxt) else data).extend(names(nxt))
            i += 2
            continue
        if a in _AUTH_FLAGS and nxt:
            auth.extend(names(nxt))
            i += 2
            continue
        data.extend(names(a))
        i += 1
    return [n for n in dict.fromkeys(auth) if n not in data]


def _expand(word: str, ctx: _Ctx, c: _Cmd) -> str:
    """Replace variables assigned earlier in the command; remember the ones that come from outside."""
    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        if name in ctx.vars:
            return ctx.vars[name]
        if name not in ctx.locals:
            _add(c.env_reads, name)
        return m.group(0)

    return _VAR.sub(repl, word)


def _simple(words: list[str], ctx: _Ctx) -> _Cmd | None:
    c = _Cmd()
    args: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if set(w) <= set("<>&|") and ("<" in w or ">" in w):
            target = words[i + 1] if i + 1 < len(words) else ""
            if args and args[-1].isdigit() and len(args[-1]) == 1:
                args.pop()   # the "2" of "2>"
            if w in ("<<<",):
                pass
            elif "<" in w and ">" not in w:
                if target and not target.startswith("\x00") and not (w.endswith("&") and target.isdigit()):
                    _add(c.reads, _expand(target, ctx, c))
                elif target.startswith("\x00S"):
                    args.append(target)   # < <(cmd)
            elif target and not ("&" in w and (target.isdigit() or target == "-")):
                path = _expand(target, ctx, c)
                if path not in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"):
                    m = re.match(r"^/dev/(?:tcp|udp)/([^/]+)/\d+$", path)
                    if m:
                        c.network, c.sink_kind, c.payload = True, "shell-net", True
                        _add(c.dests, ("host", m.group(1).lower()))
                    else:
                        _add(c.writes, path)
                        c.stdout_file = c.stdout_file or (path if w in (">", ">>", ">|", "&>", "&>>") else "")
            i += 2
            continue
        args.append(w)
        i += 1

    # leading assignments, wrappers and shell keywords
    while args:
        head = args[0]
        m = _ASSIGN.match(head)
        if m and not head.startswith("\x00"):
            value = _expand(m.group(2), ctx, c)
            if not _SUB.search(value) and "$" not in value:
                ctx.vars[m.group(1)] = value
            else:
                ctx.vars.pop(m.group(1), None)
                for idx in (int(x) for x in _SUB.findall(value)):
                    _add(c.sub_idx, idx)
            args.pop(0)
            continue
        base = _base(head)
        if head in _KEYWORD_SKIP:
            args.pop(0)
            continue
        if head in ("for", "select") and len(args) > 1:
            ctx.locals.add(args[1])
            return c if (c.reads or c.writes) else None
        if head in ("case", "function"):
            return c if (c.reads or c.writes) else None
        if base in _WRAPPERS:
            args.pop(0)
            value_opts = {"sudo": {"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U"}, "doas": {"-u", "-C"},
                          "env": {"-u", "--unset", "-C", "--chdir", "-S"}, "nice": {"-n"}, "ionice": {"-c", "-n", "-p"},
                          "timeout": {"-s", "-k", "--signal", "--kill-after"}, "stdbuf": {"-i", "-o", "-e"},
                          "watch": {"-n", "-d"}}.get(base, set())
            while args and (args[0].startswith("-") or (base == "env" and _ASSIGN.match(args[0]))):
                opt = args.pop(0)
                if opt in value_opts and args:
                    args.pop(0)
            if base == "timeout" and args:
                args.pop(0)   # the duration
            if base == "env" and not args:
                c.program = "env"
                c.env_dump = True
                c.passes_through = False
                return c
            continue
        if base in ("busybox", "toybox") and len(args) > 1:
            args.pop(0)
            continue
        break
    if not args:
        return c if (c.reads or c.writes or c.sub_idx or c.network) else None

    raw_program = args[0]
    expanded = _expand(raw_program, ctx, c)
    if raw_program == "export" and len(args) > 1:   # export NAME=value
        for a in args[1:]:
            m = _ASSIGN.match(a)
            if m and "$" not in m.group(2) and not _SUB.search(m.group(2)):
                ctx.vars[m.group(1)] = m.group(2)
    if _SUB.search(expanded) or "$" in expanded:
        c.program = "?"
        c.opaque.append("the program to run is computed, not written out")
        c.passes_through = False
        for idx in (int(x) for x in _SUB.findall(expanded)):
            _add(c.sub_idx, idx)
        return c
    c.program = _base(expanded)
    c.raw_program = expanded
    c.env_auth = _auth_only_vars(args[1:], ctx)
    rest = []
    for a in args[1:]:
        e = _expand(a, ctx, c)
        for idx in (int(x) for x in _SUB.findall(e)):
            _add(c.sub_idx, idx)
        rest.append(e)
    _dispatch(c, rest, ctx)
    return c


# -- composition --------------------------------------------------------------------------------------


def _is_known(item) -> bool:
    """False for a path that still holds an unexpanded variable or a substitution."""
    parts = item if isinstance(item, tuple) else (item,)
    return not any("$" in p or "\x00" in p for p in parts)


def _merge(out: BashAnalysis, inner: BashAnalysis) -> None:
    for name in ("reads", "writes", "uploads", "deletes", "fetches", "destinations", "derived", "env_reads",
                 "env_uploads", "env_auth", "executed", "staged", "sink_kinds", "opaque_reasons", "programs"):
        target = getattr(out, name)
        for item in getattr(inner, name):
            _add(target, item)
    for name in ("env_dump", "env_uploaded", "executes_download", "encodes", "is_sink", "carries_payload",
                 "untrusted_output", "sensitive_output", "opaque"):
        setattr(out, name, getattr(out, name) or getattr(inner, name))


def _pipeline(cmds: list[_Cmd], ctx: _Ctx, out: BashAnalysis) -> None:
    flow_files: list[str] = []      # files whose content is travelling down the pipe
    flow_urls: list[str] = []       # URLs whose content is travelling down the pipe
    flow_env = False
    flow_env_names: list[str] = []
    flow_decoded = False
    flow_encoded = False
    flow_literal = ""
    piped = False
    for pos, c in enumerate(cmds):
        last = pos == len(cmds) - 1
        _add(out.programs, c.program)
        # what the substitutions in this command's arguments bring in
        arg_files: list[str] = []
        arg_urls: list[str] = []
        arg_env = False
        for idx in c.sub_idx:
            kind, inner = ctx.subs[idx]
            _merge(out, inner)
            arg_files += inner.reads
            arg_urls += inner.fetches
            arg_env = arg_env or inner.env_dump
            if inner.sensitive_output:
                arg_env = True
        for nested in c.nested:
            _merge(out, nested)

        for name, items in (("reads", c.reads), ("writes", c.writes), ("deletes", c.deletes), ("uploads", c.uploads),
                            ("fetches", c.fetches), ("derived", c.derived), ("executed", c.executed),
                            ("staged", c.staged), ("env_reads", c.env_reads)):
            target = getattr(out, name)
            for item in items:
                if _is_known(item):
                    _add(target, item)
        for dest in c.dests:
            if _is_known(dest):
                _add(out.destinations, dest)
            else:
                c.opaque.append("the destination is computed, not written out")
        out.env_dump = out.env_dump or c.env_dump
        out.sensitive_output = out.sensitive_output or c.prints_secret
        if c.opaque:
            out.opaque = True
            for reason in c.opaque:
                _add(out.opaque_reasons, reason)

        if c.network:
            out.is_sink = True
            _add(out.sink_kinds, c.sink_kind or "shell-net")
            incoming = bool(flow_files or flow_urls or flow_env or arg_files or arg_env or flow_literal) or piped
            # A variable expanded into an outbound command is data riding along with it.
            if c.payload or incoming or c.uploads or c.env_reads:
                out.carries_payload = True
            for f in [*flow_files, *arg_files]:
                if _is_known(f):
                    _add(out.uploads, f)
            if flow_env or arg_env:
                out.env_uploaded = True
            for name in [*c.env_reads, *flow_env_names]:
                _add(out.env_uploads, name)
            for name in c.env_auth:
                if name not in flow_env_names:
                    _add(out.env_auth, name)
            if flow_encoded or flow_decoded:
                out.encodes = True

        if c.runs_stdin:
            sources = [*flow_urls, *arg_urls]
            if sources:
                out.executes_download = True
                for url in sources:
                    _add(out.executed, url)
            elif flow_decoded:
                out.opaque = True
                _add(out.opaque_reasons, "a decoded string is run as a program")
            elif flow_literal and ctx.depth < MAX_DEPTH:
                _merge(out, _analyze(flow_literal, ctx.cwd, ctx.depth + 1, dict(ctx.vars)))
            elif piped and (flow_files or flow_env):
                for f in flow_files:
                    _add(out.executed, f)
            elif c.sub_idx and not sources:
                inner_has_output = any(ctx.subs[i][1].programs for i in c.sub_idx)
                if inner_has_output:
                    out.opaque = True
                    _add(out.opaque_reasons, "text produced by another command is run as a program")

        # what flows on to the next stage
        produced_files = list(c.reads) if c.passes_through or c.codec else []
        if c.program in ("tee",):
            produced_files = []
        if c.passes_through or c.codec:
            flow_files = [*flow_files, *produced_files] if (piped or pos == 0) else produced_files
        else:
            flow_files = []
        if c.fetches and c.prints_remote:
            flow_urls = list(c.fetches)
        elif not (c.passes_through or c.codec):
            flow_urls = []
        if c.env_dump:
            flow_env = True
        elif not (c.passes_through or c.codec):
            flow_env = False
        flow_env_names = list(c.env_reads) if c.program in ("echo", "printf", "printenv") else (
            flow_env_names if (c.passes_through or c.codec) else [])
        if c.codec == "decode":
            flow_decoded = True
        elif c.codec == "encode":
            flow_encoded = True
        elif not c.passes_through:
            flow_decoded = flow_encoded = False
        flow_literal = c.literal_out if c.program in ("echo", "printf") else ""

        if c.stdout_file:
            if flow_env or c.env_dump:
                _add(out.derived, (c.stdout_file, "env:*"))   # the file now holds the environment
            for src in [*flow_files, *produced_files]:
                if src != c.stdout_file:
                    _add(out.derived, (c.stdout_file, src))
            for url in flow_urls or (c.fetches if c.prints_remote else []):
                _add(out.derived, (c.stdout_file, url))
        if last and not c.stdout_file and (flow_urls and not c.network or c.prints_remote) and not c.runs_stdin:
            out.untrusted_output = True
        piped = True


def _analyze(command: str, cwd: str | None, depth: int, variables: dict[str, str] | None = None) -> BashAnalysis:
    out = BashAnalysis()
    if depth > MAX_DEPTH or not command.strip():
        return out
    ctx = _Ctx(cwd, depth)
    ctx.vars = {"HOME": "~", "PWD": ".", **(variables or {})}
    text = _lift_heredocs(command, ctx)
    text = _scan(text, ctx)
    tokens = _tokens(text)
    # `cd DIR && command` is how agents write most commands. A file operand after it belongs to
    # DIR, not to the hook's working directory; a subshell's `cd` ends with the subshell.
    dirs: list[str | None] = [None]
    for kind, pipeline in _sequence(tokens):
        if kind == "(":
            dirs.append(dirs[-1])
            continue
        if kind == ")":
            if len(dirs) > 1:
                dirs.pop()
            continue
        ctx.dir = dirs[-1]
        cmds = []
        for words in pipeline:
            c = _simple(words, ctx)
            if c is None:
                continue
            if ctx.dir is not None and ctx.dir != _DIR_UNKNOWN:
                _rebase_cmd(c, ctx.dir)
            cmds.append(c)
        if len(pipeline) == 1:   # in a pipeline `cd` runs in a subshell and moves nothing
            target = _cd_target(pipeline[0])
            if target is not None:
                dirs[-1] = _join_dir(dirs[-1], target)
        if cmds:
            _pipeline(cmds, ctx, out)
    ctx.dir = None
    # substitutions that no command consumed (a bare "$(...)" or an assignment) still ran
    for kind, inner in ctx.subs:
        _merge(out, inner)
    if out.opaque:
        out.is_sink = True
        _add(out.sink_kinds, "opaque")
        out.carries_payload = True
    if out.executed and any(u in out.fetches or "://" in u for u in out.executed):
        out.executes_download = True
    return out


_NETWORK_WORDS = re.compile(r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|sftp|ftp|telnet|socat)\b")


def analyze_bash(command: str, cwd: str | None = None) -> BashAnalysis:
    """Work out what a shell command would do. Never raises.

    When the command cannot be tokenised (an unbalanced quote, for example), whatever
    URLs it contains are still reported and, if it names a network program, it is marked
    opaque so that it is treated as a possible sink.
    """
    command = command or ""
    if len(command) > MAX_COMMAND_CHARS:
        out = BashAnalysis(opaque=True, is_sink=True, carries_payload=True, sink_kinds=["opaque"])
        _add(out.opaque_reasons, f"the command is {len(command):,} characters long, too long to analyse")
        for url in _URL.findall(command)[:50]:
            _add(out.destinations, ("url", url.rstrip(".,)'\"")))
        out.summary = " ".join(command[:400].split())[:200]
        return out
    try:
        out = _analyze(command, cwd, 0)
    except Exception as exc:   # noqa: BLE001 - a parser bug must never make a command look safe
        out = BashAnalysis()
        for url in _URL.findall(command):
            url = url.rstrip(".,)'\"")
            _add(out.destinations, ("url", url))
            host = _host(url)
            if host:
                _add(out.destinations, ("host", host))
        out.opaque = True
        _add(out.opaque_reasons, f"the command could not be parsed ({type(exc).__name__})")
        if _NETWORK_WORDS.search(command) or out.destinations:
            out.is_sink = True
            _add(out.sink_kinds, "opaque")
            out.carries_payload = True
    out.summary = " ".join(command.split())[:200]
    return out
