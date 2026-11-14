"""Putting the guard into a project, and taking it out again.

``init`` writes three things: the TaintTrail config, a ``.gitignore`` entry for the
state directory, and the hook registration in Claude Code's settings file. The hook
command uses the absolute path of the interpreter that ran ``init``, because a hook that
depends on an activated virtualenv fails silently when the virtualenv is not active.
"""

from __future__ import annotations

import json
import os
import re
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


# What the installer writes, and nothing looser: `<python> -m tainttrail hook claude-code` at the end
# of the command. A wrapper or an audit script that merely mentions "tainttrail hook" is someone
# else's handler and is left alone.
_OURS = re.compile(r"(?:^|\s)-m\s+tainttrail\s+hook(?:\s+claude-code)?\s*$")


def _is_ours(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    args = handler.get("args")
    text = str(handler.get("command") or "") + " " + " ".join(str(a) for a in args if isinstance(a, str)) \
        if isinstance(args, list) else str(handler.get("command") or "")
    return bool(_OURS.search(text.strip()))


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


def _handlers(group: Any) -> list[Any] | None:
    """The handler list of a hook group, or None when the group is not shaped like one.

    A group whose "hooks" is a single object or a string is somebody's mistake or somebody's
    extension; either way it is not ours to rewrite.
    """
    if not isinstance(group, dict):
        return None
    hooks = group.get("hooks")
    return hooks if isinstance(hooks, list) else None


def _sees_every_tool(group: dict[str, Any]) -> bool:
    return group.get("matcher") in (None, "", "*")


def is_installed(path: Path) -> bool:
    """Whether a settings file registers the guard on PreToolUse for every tool."""
    try:
        data = _load(path)
    except (ValueError, OSError):
        return False
    hooks = data.get("hooks")
    groups = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    if not isinstance(groups, list):
        return False
    return any(_is_ours(h) for g in groups if _handlers(g) is not None and _sees_every_tool(g) for h in _handlers(g) or [])


def register_hooks(data: dict[str, Any], command: str, *, fail_closed: bool = False) -> bool:
    """Add or refresh the guard's handlers in a settings object. Returns True if it changed.

    The guard gets a group of its own for each event, one that matches every tool. A handler
    of ours found in a narrower group (a hand edit, an older layout) is moved, because a guard
    that only sees Bash is not a guard.
    """
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
        kept_groups = []
        for group in groups:
            handlers = _handlers(group)
            if handlers is None or not any(_is_ours(h) for h in handlers):
                kept_groups.append(group)
                continue
            others = [h for h in handlers if not _is_ours(h)]
            if not placed and not others and (_sees_every_tool(group) or not by_tool):
                group["hooks"] = [handler]      # our own group, already in the right place: refresh it
                kept_groups.append(group)
                placed = True
            elif others:
                group["hooks"] = others         # someone else's group: take ours out, leave theirs
                kept_groups.append(group)
        groups[:] = kept_groups
        if not placed:
            groups.append({"matcher": "*", "hooks": [handler]} if by_tool else {"hooks": [handler]})
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
            kept = []
            for group in groups:
                handlers = _handlers(group)
                if handlers is None or not any(_is_ours(h) for h in handlers):
                    kept.append(group)
                    continue
                group["hooks"] = [h for h in handlers if not _is_ours(h)]
                if group["hooks"]:
                    kept.append(group)
            hooks[event] = kept
            if not hooks[event]:
                del hooks[event]
        if not hooks:
            del data["hooks"]
    return json.dumps(data, sort_keys=True) != before


def user_config_path() -> Path:
    """Defaults for every project that has no config file of its own."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tainttrail" / CONFIG_FILENAME


def init(cfg: Config, *, scope: str = "project", python: str | None = None, mode: str = "guard",
         fail_closed: bool = False) -> list[str]:
    """Install the guard. Safe to run again. Returns what was done, one line each.

    With scope "user" the hooks run in every project, so the mode and the fail-closed choice
    are written where every project reads them (the user-level config), not into the one
    project this command happened to be run in.
    """
    path = settings_path(cfg, scope)
    data = _load(path)   # first: a settings file that does not parse stops everything before anything is written
    changed = register_hooks(data, hook_command(python), fail_closed=fail_closed)

    done: list[str] = []
    text = DEFAULT_CONFIG.format(mode=mode, fail_closed="true" if fail_closed else "false")
    if scope == "user":
        conf = user_config_path()
        if not conf.exists():
            conf.parent.mkdir(parents=True, exist_ok=True)
            conf.write_text(text, encoding="utf-8")
            done.append(f"wrote {conf} (the defaults for every project without a config of its own)")
        else:
            done.append(f"kept existing {conf}")
    else:
        cfg.home.mkdir(parents=True, exist_ok=True)
        conf = cfg.home / CONFIG_FILENAME
        if not conf.exists():
            conf.write_text(text, encoding="utf-8")
            done.append(f"wrote {conf}")
        else:
            done.append(f"kept existing {conf}")
        if (cfg.root / ".git").exists():
            ignore = cfg.root / ".gitignore"
            existing = ignore.read_text(encoding="utf-8") if ignore.exists() else ""
            if not any(line.strip().rstrip("/") == HOME_DIRNAME for line in existing.splitlines()):
                with open(ignore, "a", encoding="utf-8") as fh:
                    fh.write(("" if not existing or existing.endswith("\n") else "\n") + f"{HOME_DIRNAME}/\n")
                done.append(f"added {HOME_DIRNAME}/ to {ignore}")

    if changed:
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
