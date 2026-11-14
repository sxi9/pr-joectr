"""Scripted sessions: attacks the guard must stop and ordinary work it must leave alone.

A scenario is a list of sessions, each a list of steps (a user prompt, or a tool call
with the result it would return). ``replay`` plays them as real Claude Code hook
payloads through the hook adapter into a fresh project, so the whole path is
exercised: adapter, analyzers, graph, rules.

The scenarios model a fooled agent on purpose. A model may well refuse these
instructions; the guard exists for the time it does not. Every value in them is a
canary and every host is reserved; replay contacts nothing.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import time
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

from .config import CONFIG_FILENAME, HOME_DIRNAME, load_config

# attack, benign and known_gaps were written from public incident reports before the replay
# harness existed. variant and ordinary came out of a review: 64 ordinary multi-step sessions
# written to find false alarms, and 11 attacks aimed at the edges the resulting fixes moved.
GROUPS = ("attack", "variant", "benign", "ordinary", "known_gaps")
DATA_FILES = ("scenarios.json", "attack_variants.json", "ordinary_sessions.json")
DEFAULT_ORIGIN = "git@github.com:tt-demo-victim/webapp.git"


@dataclass
class StepResult:
    index: int                      # position in the scenario, counting prompts, from 1
    session: str
    kind: str                       # "prompt" | "tool"
    tool: str = ""
    summary: str = ""
    expect: str = ""                # what the scenario asks for
    accept: list[str] = field(default_factory=list)
    action: str = "allow"           # what the guard decided
    rules: list[str] = field(default_factory=list)       # rules that asked or denied
    noted: list[str] = field(default_factory=list)       # rules that only recorded
    expected_rules: list[str] = field(default_factory=list)
    leaks: list[str] = field(default_factory=list)       # canaries this step would send out
    ran: bool = True                # False when the call was denied
    enforced: bool = True           # False for a session that ran in monitor mode
    ok: bool = True
    reason: str = ""                # what the guard told the agent


@dataclass
class ScenarioResult:
    id: str
    title: str
    group: str
    guard: bool
    steps: list[StepResult]
    root: Path
    sessions: list[str]
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    @property
    def blocked_at(self) -> int | None:
        return next((s.index for s in self.steps if s.action == "deny"), None)

    @property
    def asked_at(self) -> list[int]:
        return [s.index for s in self.steps if s.action == "ask"]

    @property
    def leaked(self) -> list[str]:
        """Canaries that left the machine: carried by calls that ran without a prompt."""
        return [v for s in self.steps if s.ran and s.action == "allow" for v in s.leaks]

    @property
    def held(self) -> list[str]:
        return [v for s in self.steps if s.action == "deny" for v in s.leaks]

    @property
    def needs_approval(self) -> list[str]:
        return [v for s in self.steps if s.action == "ask" for v in s.leaks]


@contextlib.contextmanager
def _env(**values: str | None) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _catalog() -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for name in DATA_FILES:
        data = json.loads(resources.files("tainttrail").joinpath("data", name).read_text(encoding="utf-8"))
        for group in GROUPS:
            if group in data:
                merged.setdefault(group, []).extend(data[group])
    return merged


def list_scenarios() -> list[dict[str, Any]]:
    """Every packaged scenario with its group, in file order."""
    data = _catalog()
    out = []
    for group in GROUPS:
        for sc in data.get(group, []):
            out.append({**sc, "group": group})
    return out


def load_scenario(ref: str) -> dict[str, Any]:
    """A scenario by id, by unique id prefix, or from a JSON file path."""
    if os.path.isfile(ref):
        with open(ref, encoding="utf-8") as fh:
            sc = json.load(fh)
        sc.setdefault("group", "custom")
        return sc
    scenarios = list_scenarios()
    for sc in scenarios:
        if sc["id"] == ref:
            return sc
    matches = [sc for sc in scenarios if sc["id"].startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    exact_prefix = [sc for sc in matches if sc["id"].split("-", 1)[0] == ref]
    if len(exact_prefix) == 1:
        return exact_prefix[0]
    if matches:
        raise LookupError(f"{ref!r} matches several scenarios: " + ", ".join(sc["id"] for sc in matches))
    raise LookupError(f"no scenario {ref!r}; `tainttrail demo list` shows them")


def _expand(value: Any, root: Path, files: dict[str, str]) -> Any:
    if isinstance(value, str):
        value = value.replace("{root}", root.as_posix())
        for name, content in files.items():
            token = "{file:" + name + "}"
            if token in value:
                value = value.replace(token, content)
        return value
    if isinstance(value, dict):
        return {k: _expand(v, root, files) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, root, files) for v in value]
    return value


def wrap_response(tool: str, tool_input: dict[str, Any], response: Any) -> Any:
    """Give a scenario's plain-text result the shape Claude Code reports for that tool."""
    if not isinstance(response, str):
        return response
    text = response
    if tool in ("Read", "NotebookRead"):
        lines = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        return {"type": "text", "file": {"filePath": tool_input.get("file_path", ""), "content": text,
                                         "numLines": lines, "startLine": 1, "totalLines": lines}}
    if tool == "Bash":
        return {"stdout": text, "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
    if tool == "WebFetch":
        return {"bytes": len(text.encode()), "code": 200, "codeText": "OK", "result": text, "durationMs": 1,
                "url": tool_input.get("url", "")}
    if tool == "WebSearch":
        return {"query": tool_input.get("query", ""), "results": [text], "durationSeconds": 0.1}
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return {"type": "update", "filePath": tool_input.get("file_path", ""), "structuredPatch": []}
    if tool == "Grep":
        return {"mode": "content", "numFiles": 0, "filenames": [], "content": text, "numLines": text.count("\n")}
    if tool in ("Glob", "LS"):
        return {"filenames": [ln for ln in text.splitlines() if ln], "numFiles": text.count("\n"), "truncated": False}
    if tool in ("Task", "Agent"):
        return {"status": "completed", "content": [{"type": "text", "text": text}]}
    if tool.startswith("mcp__"):
        return [{"type": "text", "text": text}]
    return text


def prepare_project(scenario: dict[str, Any], root: Path, *, guard: bool = True) -> dict[str, str]:
    """Write the scenario's fixture files, a git remote and the TaintTrail config into ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    files = {name: str(content).replace("{root}", root.as_posix()) for name, content in (scenario.get("files") or {}).items()}
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git = root / ".git"
    git.mkdir(exist_ok=True)
    remotes = scenario.get("git_remotes") or {"origin": DEFAULT_ORIGIN}
    (git / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        + "".join(f'[remote "{name}"]\n\turl = {url}\n' for name, url in remotes.items()), encoding="utf-8")
    home = root / HOME_DIRNAME
    home.mkdir(exist_ok=True)
    mode = scenario.get("mode") or ("guard" if guard else "monitor")
    (home / CONFIG_FILENAME).write_text(f'mode = "{mode}"\nannounce = false\n', encoding="utf-8")
    return files


def replay(scenario: dict[str, Any], root: Path, *, guard: bool = True) -> ScenarioResult:
    """Play a scenario through the Claude Code hook adapter into a project at ``root``.

    With ``guard=False`` the project runs in monitor mode: everything is recorded, nothing
    is stopped, and the result shows what would have left the machine. A step the guard
    asks about is treated as approved so that the rest of the scenario still plays; a
    denied step does not run and gets no result.
    """
    from .hooks import claude_code
    from . import report
    from .store import open_store

    started = time.perf_counter()
    root = Path(root).resolve()
    files = prepare_project(scenario, root, guard=guard)
    steps: list[StepResult] = []
    session_ids: list[str] = []
    counter = 0
    index = 0

    def fire(payload: dict[str, Any]) -> dict[str, Any] | None:
        out = io.StringIO()
        claude_code.main(io.StringIO(json.dumps(payload)), out)
        text = out.getvalue().strip()
        return json.loads(text) if text else None

    with _env(CLAUDE_PROJECT_DIR=root.as_posix(), TAINTTRAIL_HOME=None, TAINTTRAIL_DB=None, TAINTTRAIL_MODE=None,
              TAINTTRAIL_DISABLE=None):
        for session in scenario.get("sessions", []):
            sid = f"{scenario['id']}-{session.get('id', 's')}"
            session_ids.append(sid)
            # A session may run under its own mode: "this one ran before the guard was enforcing".
            mode = session.get("mode") or scenario.get("mode") or ("guard" if guard else "monitor")
            (root / HOME_DIRNAME / CONFIG_FILENAME).write_text(f'mode = "{mode}"\nannounce = false\n', encoding="utf-8")
            enforcing = mode != "monitor"
            base = {"session_id": sid, "transcript_path": f"{root.as_posix()}/.transcript-{sid}.jsonl",
                    "cwd": root.as_posix(), "permission_mode": "default"}
            fire({**base, "hook_event_name": "SessionStart", "source": "startup"})
            for raw in session.get("steps", []):
                index += 1
                step = _expand(raw, root, files)
                x = step.get("x") or {}
                if "prompt" in step:
                    fire({**base, "hook_event_name": "UserPromptSubmit", "prompt": step["prompt"]})
                    steps.append(StepResult(index=index, session=sid, kind="prompt", summary=step["prompt"],
                                            enforced=enforcing))
                    continue
                counter += 1
                tool, tool_input = step["tool"], step.get("input") or {}
                call = {**base, "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"toolu_{counter:04d}"}
                if step.get("agent_id"):
                    call.update(agent_id=step["agent_id"], agent_type=step.get("agent_type", "general-purpose"))
                out = fire({**call, "hook_event_name": "PreToolUse"}) or {}
                hso = out.get("hookSpecificOutput") or {}
                action = hso.get("permissionDecision") or "allow"
                result = StepResult(
                    index=index, session=sid, kind="tool", tool=tool, expect=step.get("expect") or "",
                    accept=list(x.get("accept") or []), action=action, expected_rules=list(step.get("rules") or []),
                    leaks=list(step.get("leaks") or []), ran=action != "deny",
                    reason=hso.get("permissionDecisionReason") or "", enforced=enforcing)
                if result.ran:   # Claude Code reports every call that ran, with or without output
                    fire({**call, "hook_event_name": "PostToolUse",
                          "tool_response": wrap_response(tool, tool_input, step.get("response", ""))})
                steps.append(result)

    cfg = load_config(root)
    with open_store(cfg, read_only=True) as store:
        for sid in session_ids:
            calls = [r for r in report.timeline(store, sid) if r["kind"] == "call"]
            mine = [s for s in steps if s.session == sid and s.kind == "tool"]
            for step, row in zip(mine, calls):
                step.summary = row["summary"] or step.tool
                found = report.findings(store, session_id=sid)
                for f in found:
                    if f["target_id"] == row["id"] or f["target_id"] == row["id"] + ":out":
                        (step.rules if f["action"] in ("ask", "deny") else step.noted).append(f["rule"])
                step.rules = sorted(set(step.rules))
                step.noted = sorted(set(step.noted) - set(step.rules))

    for step in steps:
        if step.kind != "tool" or not guard or not step.enforced:
            continue
        allowed = {step.expect, *step.accept} - {""}
        if allowed and step.action not in allowed:
            step.ok = False
        if step.ok and step.expected_rules and step.action in ("ask", "deny") and step.action == step.expect:
            if not set(step.expected_rules) & set(step.rules):
                step.ok = False
    return ScenarioResult(id=scenario["id"], title=scenario.get("title", ""), group=scenario.get("group", ""),
                          guard=guard, steps=steps, root=root, sessions=session_ids,
                          elapsed_ms=round((time.perf_counter() - started) * 1000, 1))
