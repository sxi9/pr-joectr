"""Locating the project, loading ``.tainttrail/config.toml`` and the fingerprint key."""

from __future__ import annotations

import fnmatch
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from . import defaults

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as _toml  # type: ignore[no-redef]

HOME_DIRNAME = ".tainttrail"
DB_FILENAME = "graph.rl"
KEY_FILENAME = "key"
CONFIG_FILENAME = "config.toml"
LOG_FILENAME = "guard.log"

ACTIONS = ("allow", "ask", "deny")


@dataclass
class Config:
    """Resolved settings for one project.

    ``root`` is the project directory; ``home`` is where TaintTrail keeps its state
    (``<root>/.tainttrail`` unless ``TAINTTRAIL_HOME`` is set).
    """

    root: Path
    home: Path
    mode: str = "guard"
    fail_closed: bool = False
    trusted_hosts: tuple[str, ...] = defaults.TRUSTED_HOSTS
    local_hosts: tuple[str, ...] = defaults.LOCAL_HOSTS
    sensitive_paths: tuple[str, ...] = defaults.SENSITIVE_PATHS
    sensitive_path_exceptions: tuple[str, ...] = defaults.SENSITIVE_PATH_EXCEPTIONS
    protected_paths: tuple[str, ...] = defaults.PROTECTED_PATHS
    untrusted_paths: tuple[str, ...] = defaults.UNTRUSTED_PATHS
    # Per-rule overrides: {"TT002": "deny", "TT009": "off"}.
    rules: dict[str, str] = field(default_factory=dict)
    max_content_bytes: int = defaults.MAX_CONTENT_BYTES
    max_chunks: int = defaults.MAX_CHUNKS_PER_CONTENT
    max_entities: int = defaults.MAX_ENTITIES_PER_CONTENT
    max_live_nodes: int = defaults.MAX_LIVE_NODES
    lock_timeout_ms: int = defaults.LOCK_TIMEOUT_MS
    # "auto" uses the `claude` CLI when it is on PATH; "none" keeps everything deterministic.
    llm: str = "auto"
    # Tell the agent at session start that it is being watched and what a block means.
    announce: bool = True
    # Why the config file could not be read, if it could not. The guard then runs on the
    # defaults (plus the mode and fail_closed lines, when those two are legible) and says so.
    config_error: str = ""

    @property
    def db_path(self) -> Path:
        override = os.environ.get("TAINTTRAIL_DB")
        return Path(override) if override else self.home / DB_FILENAME

    @property
    def log_path(self) -> Path:
        return self.home / LOG_FILENAME

    @property
    def config_path(self) -> Path:
        return self.home / CONFIG_FILENAME

    # -- path classification -------------------------------------------------

    def is_sensitive_path(self, path: str | os.PathLike[str]) -> bool:
        p = normalize_path(path, self.root)
        if self._is_own_secret(p):
            return True
        if _matches_any(p, self.sensitive_path_exceptions):
            return False
        return _matches_any(p, self.sensitive_paths)

    def _is_own_secret(self, p: str) -> bool:
        """The guard's key, its graph and its archive, wherever TAINTTRAIL_HOME and TAINTTRAIL_DB put them."""
        try:
            if p == normalize_path(self.db_path, self.root):
                return True
            home = normalize_path(self.home, self.root).rstrip("/")
        except (OSError, ValueError):
            return False
        if not home or not p.startswith(home + "/"):
            return False
        rest = p[len(home) + 1:]
        # ... and the queue of events that could not be recorded yet, which holds raw tool results.
        return rest == "key" or rest.endswith(".rl") or rest.startswith(("archive/", "pending/"))

    def is_protected_path(self, path: str | os.PathLike[str]) -> bool:
        return _matches_any(normalize_path(path, self.root), self.protected_paths)

    def is_untrusted_path(self, path: str | os.PathLike[str]) -> bool:
        return _matches_any(normalize_path(path, self.root), self.untrusted_paths)

    # -- host classification -------------------------------------------------

    def is_trusted_host(self, host: str) -> bool:
        return _host_in(host, self.trusted_hosts)

    def is_local_host(self, host: str) -> bool:
        h = host.strip().lower().strip("[]")
        if _host_in(h, self.local_hosts) or h.endswith(".localhost") or h.endswith(".local"):
            return True
        return _is_private_ip(h)

    def rule_action(self, rule_id: str, default: str) -> str:
        """Action for a rule after applying the mode and any per-rule override.

        Returns one of ``allow``, ``ask``, ``deny`` or ``off``.
        """
        override = self.rules.get(rule_id)
        if override in (*ACTIONS, "off"):
            return override  # type: ignore[return-value]
        if self.mode == "monitor":
            return "allow"
        if self.mode == "strict" and default == "ask":
            return "deny"
        return default

    def key(self) -> bytes:
        """The per-project HMAC key used to fingerprint content. Created on first use.

        The graph never stores secret values, only keyed hashes of them, so that the
        session graph can be shared as evidence without becoming a second copy of the
        secrets it protects.
        """
        env = os.environ.get("TAINTTRAIL_KEY")
        if env and len(env) >= MIN_ENV_KEY:
            return env.encode("utf-8")   # for tests and demos, where fingerprints have to be repeatable
        cached = self.__dict__.get("_key")
        if cached is not None:
            return cached
        key = self._file_key()
        self.__dict__["_key"] = key
        return key

    def _file_key(self) -> bytes:
        path = self.home / KEY_FILENAME
        key = _read_key(path)
        if key is not None:
            return key
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        # Written whole under another name, then linked into place: a hook killed half way cannot
        # leave an empty key file behind, and two hooks racing on first use agree on one key.
        temp = path.with_name(f"{KEY_FILENAME}.tmp-{os.getpid()}")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex())
        try:
            try:
                os.link(temp, path)
            except FileExistsError:
                theirs = _read_key(path)
                if theirs is not None:
                    return theirs
                os.replace(temp, path)   # empty, cut short or not hex: an unusable key is replaced
            except OSError:              # no hard links here
                os.replace(temp, path)
        finally:
            try:
                os.unlink(temp)
            except OSError:
                pass
        return key


MIN_ENV_KEY = 16


def _read_key(path: Path) -> bytes | None:
    """The key in a key file, or None when the file is missing, empty, cut short or not hex."""
    try:
        raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None
    return raw if len(raw) >= 16 else None


def find_root(cwd: str | os.PathLike[str] | None = None) -> Path:
    """The project a working directory belongs to.

    The nearest ancestor that has a ``.tainttrail`` directory or is a git repository
    root, then the directory itself. Nearest wins whichever of the two it is: a
    ``.tainttrail`` directory further up (in the home directory, say, once a session was
    started there) must not swallow every repository below it.
    """
    start = Path(cwd or os.getcwd()).expanduser()
    try:
        start = start.resolve()
    except OSError:
        pass
    for d in (start, *start.parents):
        if (d / HOME_DIRNAME).is_dir() or (d / ".git").exists():
            return d
    return start


def load_config(cwd: str | os.PathLike[str] | None = None) -> Config:
    """Resolve the project for ``cwd`` and read its config file if there is one."""
    env_home = os.environ.get("TAINTTRAIL_HOME")
    if env_home:
        home = Path(env_home).expanduser()
        root = Path(cwd).expanduser() if cwd else Path.cwd()
        try:
            root = root.resolve()
        except OSError:
            pass
    else:
        root = find_root(cwd)
        home = root / HOME_DIRNAME
    cfg = Config(root=root, home=home)
    path = home / CONFIG_FILENAME
    raw: dict[str, Any] = {}
    try:
        with open(path, "rb") as fh:
            raw = _toml.load(fh)
    except FileNotFoundError:
        # No config in this project: the user-level file, written by `init --scope user`, applies.
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        path = Path(base) / "tainttrail" / CONFIG_FILENAME
        try:
            with open(path, "rb") as fh:
                raw = _toml.load(fh)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            cfg.config_error = f"{path} could not be read ({exc}); the defaults are in use"
            raw = _salvage(path)
    except (OSError, ValueError) as exc:   # unreadable, or not TOML
        cfg.config_error = f"{path} could not be read ({exc}); the defaults are in use"
        raw = _salvage(path)
    try:
        _apply(cfg, raw)
    except (TypeError, ValueError, AttributeError) as exc:   # a string where a table belongs, and the like
        cfg = Config(root=root, home=home)
        cfg.config_error = f"{path} has a value of the wrong kind ({exc}); the defaults are in use"
        _apply(cfg, {k: raw[k] for k in ("mode", "fail_closed") if k in raw})
    env_key = os.environ.get("TAINTTRAIL_KEY")
    if env_key and len(env_key) < MIN_ENV_KEY and not cfg.config_error:
        cfg.config_error = (f"TAINTTRAIL_KEY is shorter than {MIN_ENV_KEY} characters and is ignored: a guessable "
                            "key makes fingerprints guessable. The project's own key is used")
    env_mode = os.environ.get("TAINTTRAIL_MODE")
    if env_mode in defaults.MODES:
        cfg.mode = env_mode
    return cfg


_SALVAGE = re.compile(r"""^\s*(mode|fail_closed)\s*=\s*("?)(monitor|guard|strict|true|false)\2\s*(?:\#.*)?$""", re.M)


def _salvage(path: Path) -> dict[str, Any]:
    """The two safety settings of a config file that does not parse, if their lines are legible.

    A typo elsewhere in the file must not turn ``fail_closed = true`` or ``mode = "strict"``
    back into the defaults without anyone noticing.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    out: dict[str, Any] = {}
    for name, _quote, value in _SALVAGE.findall(text):
        if name == "mode" and value in defaults.MODES:
            out["mode"] = value
        elif name == "fail_closed" and value in ("true", "false"):
            out["fail_closed"] = value == "true"
    return out


def _table(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"[{name}] must be a table")
    return value


def _apply(cfg: Config, raw: dict[str, Any]) -> None:
    mode = raw.get("mode")
    if mode in defaults.MODES:
        cfg.mode = mode
    if isinstance(raw.get("fail_closed"), bool):
        cfg.fail_closed = raw["fail_closed"]
    if isinstance(raw.get("announce"), bool):
        cfg.announce = raw["announce"]
    if raw.get("llm") in ("auto", "claude-cli", "none"):
        cfg.llm = raw["llm"]
    hosts = _table(raw, "hosts")
    cfg.trusted_hosts = _extend(cfg.trusted_hosts, hosts.get("trusted"), hosts.get("replace_trusted"))
    paths = _table(raw, "paths")
    cfg.sensitive_paths = _extend(cfg.sensitive_paths, paths.get("sensitive"))
    cfg.protected_paths = _extend(cfg.protected_paths, paths.get("protected"))
    cfg.untrusted_paths = _extend(cfg.untrusted_paths, paths.get("untrusted"))
    cfg.sensitive_path_exceptions = _extend(cfg.sensitive_path_exceptions, paths.get("not_sensitive"))
    rules = _table(raw, "rules")
    cfg.rules = {str(k).upper(): str(v).lower() for k, v in rules.items() if str(v).lower() in (*ACTIONS, "off")}
    limits = _table(raw, "limits")
    for name in ("max_content_bytes", "max_chunks", "max_entities", "lock_timeout_ms"):
        value = limits.get(name)
        if isinstance(value, int) and value > 0:
            setattr(cfg, name, value)
    live = limits.get("max_live_nodes")
    if isinstance(live, int) and not isinstance(live, bool) and live >= 0:
        cfg.max_live_nodes = live   # 0 keeps every session in the live graph


def _extend(base: tuple[str, ...], extra: Any, replace: Any = None) -> tuple[str, ...]:
    if isinstance(replace, list):
        base = tuple(str(x) for x in replace)
    if isinstance(extra, list):
        base = tuple(dict.fromkeys([*base, *(str(x) for x in extra)]))
    return base


def normalize_path(path: str | os.PathLike[str], root: Path | None = None) -> str:
    """Absolute POSIX form of a path, with ``~`` expanded and ``..`` collapsed.

    The file does not have to exist and symlinks are not followed: the guard must
    classify a path before anything touches it.
    """
    s = os.fspath(path).strip()
    if s.startswith("file://"):
        s = s[7:]
    s = os.path.expanduser(s)
    if not os.path.isabs(s):
        s = os.path.join(os.fspath(root or Path.cwd()), s)
    return PurePosixPath(os.path.normpath(s).replace(os.sep, "/")).as_posix()


def _glob_to_candidates(pattern: str) -> tuple[str, ...]:
    """``fnmatch`` has no ``**``; ``**/x`` must also match ``x`` at the top level."""
    pattern = os.path.expanduser(pattern)
    out = [pattern.replace("**/", "*/").replace("/**", "/*")]
    if "**/" in pattern:
        out.append(pattern.replace("**/", ""))
    return tuple(out)


def _matches_any(posix_path: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        for candidate in _glob_to_candidates(pattern):
            # fnmatch's ``*`` crosses ``/``, which is what makes ``*/x`` behave like ``**/x``.
            if fnmatch.fnmatchcase(posix_path, candidate):
                return True
            if candidate.endswith("/*") and posix_path == candidate[:-2]:
                return True
    return False


def _host_in(host: str, hosts: tuple[str, ...]) -> bool:
    h = host.strip().lower().rstrip(".").strip("[]")
    for entry in hosts:
        e = entry.strip().lower().rstrip(".")
        if e.startswith("*."):
            if h.endswith(e[1:]) or h == e[2:]:
                return True
        elif h == e:
            return True
    return False


# This machine and its own network: loopback, the private-use ranges, link-local, unique-local.
# Not everything the address registries call "not globally reachable": the documentation and
# benchmarking ranges (192.0.2.0/24, 2001:db8::/32 and the like) are somewhere else by definition.
_LOCAL_NETWORKS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/32",
                   "::1/128", "::/128", "fc00::/7", "fe80::/10")


def _is_private_ip(host: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in map(ipaddress.ip_network, _LOCAL_NETWORKS) if net.version == ip.version)
