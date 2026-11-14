"""Putting the guard into a project, and taking it out again.

``init`` writes three things: the TaintTrail config, a ``.gitignore`` entry for the
state directory, and the hook registration in Claude Code's settings file. The hook
command uses the absolute path of the interpreter that ran ``init``, because a hook that
depends on an activated virtualenv fails silently when the virtualenv is not active.
"""

from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

from .config import CONFIG_FILENAME, HOME_DIRNAME, Config

# Events the guard listens to, and whether they are filtered by tool name.
HOOK_EVENTS: tuple[tuple[str, bool], ...] = (
    ("SessionStart", False),
    ("UserPromptSubmit", False),
    ("PreToolUse", True),
    ("PostToolUse", True),
    ("PostToolUseFailure", True),
)
MARKER = "-m tainttrail hook"

DEFAULT_CONFIG = """\
# TaintTrail configuration. Every key is optional; the values shown are the defaults.

# monitor: record and report, never interfere.
# guard:   deny confirmed exfiltration, ask about what is only suspicious.
# strict:  deny whatever guard would ask about.
mode = "{mode}"

# What to do when the guard itself fails (a bug, a locked store). false lets the tool
# call through and writes the error to .tainttrail/guard.log. true blocks the call.
fail_closed = {fail_closed}

# Tell the agent at session start that it is being watched and what a block means.
announce = true

[hosts]
# Destinations that are ordinary in your work, in addition to the built-in list of
# registries and code hosts. A trusted host silences precautionary findings only;
# evidence that sensitive data is being sent is never silenced.
trusted = []

[paths]
# Globs, added to the built-in lists. "**" matches any number of directories.
sensitive = []      # files whose content is private, e.g. "**/customers.csv"
untrusted = []      # files third parties can write, e.g. "docs/imported/**" ("**" for a checkout you do not trust)
protected = []      # files that steer later sessions or run automatically
not_sensitive = []  # exceptions to the sensitive list

[rules]
# Override one rule: "allow", "ask", "deny" or "off". Example:
# TT002 = "deny"

[limits]
# The graph is opened and closed for every hook event, which costs about 45 ms per thousand
# nodes. Past this many session nodes the oldest sessions move to .tainttrail/archive/ as
# export files (`tainttrail ui --file <one>` opens them). 0 keeps every session live.
# max_live_nodes = 1500
"""


def settings_path(cfg: Config, scope: str = "project") -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    if scope == "local":
        return cfg.root / ".claude" / "settings.local.json"
    return cfg.root / ".claude" / "settings.json"


def hook_command(python: str | None = None) -> str:
    return f"{shlex.quote(python or sys.executable)} {MARKER} claude-code"


def _is_ours(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    text = str(handler.get("command") or "") + " " + " ".join(str(a) for a in handler.get("args") or [])
    return MARKER in text or "tainttrail hook" in text


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    return data


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".bak")
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def is_installed(path: Path) -> bool:
    """Whether a settings file registers the guard on PreToolUse."""
    try:
        data = _load(path)
    except (ValueError, OSError):
        return False
    groups = (data.get("hooks") or {}).get("PreToolUse") or []
    return any(_is_ours(h) for g in groups if isinstance(g, dict) for h in g.get("hooks") or [])


def register_hooks(data: dict[str, Any], command: str, *, fail_closed: bool = False) -> bool:
    """Add or refresh the guard's handlers in a settings object. Returns True if it changed."""
    before = json.dumps(data, sort_keys=True)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError('"hooks" in the settings file is not an object')
    for event, by_tool in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f'"hooks.{event}" in the settings file is not a list')
        handler: dict[str, Any] = {"type": "command", "command": command, "timeout": 10}
        if fail_closed and event == "PreToolUse":
            handler["onFailure"] = "block"   # covers what the script cannot catch: a missing interpreter, a kill
        placed = False
        for group in groups:
            if not isinstance(group, dict):
                continue
            kept = []
            for h in group.get("hooks") or []:
                if _is_ours(h):
                    if not placed:
                        kept.append(handler)
                        placed = True
                else:
                    kept.append(h)
            group["hooks"] = kept
        groups[:] = [g for g in groups if not isinstance(g, dict) or g.get("hooks")]
        if not placed:
            group = {"hooks": [handler]}
            if by_tool:
                group = {"matcher": "*", "hooks": [handler]}
            groups.append(group)
    return json.dumps(data, sort_keys=True) != before


def unregister_hooks(data: dict[str, Any]) -> bool:
    """Remove the guard's handlers and nothing else. Returns True if it changed."""
    before = json.dumps(data, sort_keys=True)
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event in list(hooks):
            groups = hooks[event]
            if not isinstance(groups, list):
                continue
            for group in groups:
                if isinstance(group, dict):
                    group["hooks"] = [h for h in group.get("hooks") or [] if not _is_ours(h)]
            hooks[event] = [g for g in groups if not isinstance(g, dict) or g.get("hooks")]
            if not hooks[event]:
                del hooks[event]
        if not hooks:
            del data["hooks"]
    return json.dumps(data, sort_keys=True) != before


def init(cfg: Config, *, scope: str = "project", python: str | None = None, mode: str = "guard",
         fail_closed: bool = False) -> list[str]:
    """Install the guard for a project. Safe to run again. Returns what was done, one line each."""
    done: list[str] = []
    cfg.home.mkdir(parents=True, exist_ok=True)
    conf = cfg.home / CONFIG_FILENAME
    if not conf.exists():
        conf.write_text(DEFAULT_CONFIG.format(mode=mode, fail_closed="true" if fail_closed else "false"),
                        encoding="utf-8")
        done.append(f"wrote {conf}")
    else:
        done.append(f"kept existing {conf}")

    if (cfg.root / ".git").exists():
        ignore = cfg.root / ".gitignore"
        text = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
        if not any(line.strip().rstrip("/") == HOME_DIRNAME for line in text.splitlines()):
            with open(ignore, "a", encoding="utf-8") as fh:
                fh.write(("" if not text or text.endswith("\n") else "\n") + f"{HOME_DIRNAME}/\n")
            done.append(f"added {HOME_DIRNAME}/ to {ignore}")

    path = settings_path(cfg, scope)
    data = _load(path)   # a file that does not parse is left alone: the error reaches the caller
    if register_hooks(data, hook_command(python), fail_closed=fail_closed):
        _save(path, data)
        done.append(f"registered the hooks in {path}")
    else:
        done.append(f"hooks already registered in {path}")
    return done


def uninstall(cfg: Config, *, scope: str = "project") -> list[str]:
    """Remove the hook registration. The recorded graph is left where it is."""
    path = settings_path(cfg, scope)
    if not path.exists():
        return [f"no settings file at {path}"]
    data = _load(path)
    if unregister_hooks(data):
        _save(path, data)
        return [f"removed the hooks from {path}", f"the recorded graph is still in {cfg.home}"]
    return [f"no TaintTrail hooks in {path}"]
