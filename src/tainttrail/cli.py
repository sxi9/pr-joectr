"""The ``tainttrail`` command.

Each sub-command is a small function. Commands that belong to other modules (scan,
paths, fix, tools, export, ui, mcp, audit) are imported when they are used, so a problem
in one of them never keeps the hook from running.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from . import __version__, report, retention
from .config import Config, load_config
from .store import Store, StoreError, StoreMissing, open_store

# name -> (module, add-arguments function, command function, help)
DELEGATED: dict[str, tuple[str, str, str, str]] = {
    "scan": ("scan", "add_scan_arguments", "cmd_scan", "map this machine's agents, MCP servers and tools into the graph"),
    "tools": ("scan", "add_tools_arguments", "cmd_tools", "list tool capability labels, or set one by hand"),
    "paths": ("paths", "add_paths_arguments", "cmd_paths", "list toxic tool combinations found by the last scan"),
    "fix": ("paths", "add_fix_arguments", "cmd_fix", "propose the smallest permission change that breaks them"),
    "export": ("export", "add_export_arguments", "cmd_export", "write the graph or one session as JSON, Cypher or a .rl file"),
    "ui": ("serve", "add_ui_arguments", "cmd_ui", "open the browser viewer on the recorded graph"),
    "mcp": ("mcp_server", "add_mcp_arguments", "cmd_mcp", "serve the guard graph to an agent over MCP (stdio)"),
    "audit": ("auditor", "add_audit_arguments", "cmd_audit", "write an audit report, optionally with an investigating agent"),
}


def _out(text: str = "") -> None:
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:   # a terminal or a pipe that is not UTF-8: say it with what it has
        encoding = sys.stdout.encoding or "ascii"
        sys.stdout.write((text + "\n").encode(encoding, "replace").decode(encoding))


def _err(text: str) -> None:
    sys.stderr.write(f"tainttrail: {text}\n")


def _read_store(cfg: Config) -> Store:
    return open_store(cfg, read_only=True)


# -- install -----------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, cfg: Config) -> int:
    from . import install

    try:
        lines = install.init(cfg, scope=args.scope, python=args.python, mode=args.mode, fail_closed=args.fail_closed)
    except (ValueError, json.JSONDecodeError) as exc:
        _err(f"could not update the settings file: {exc}. Nothing was changed.")
        return 1
    except OSError as exc:
        _err(f"could not write {exc.filename or 'a file'}: {exc.strerror or exc}")
        return 1
    for line in lines:
        _out(line)
    _out()
    where = "on this machine" if args.scope == "user" else "in this project"
    _out(f"TaintTrail now sees every prompt and tool call of Claude Code sessions {where}.")
    _out("Next: start a session, then `tainttrail log` and `tainttrail findings`. `tainttrail demo list` shows scripted attacks.")
    return 0


def cmd_uninstall(args: argparse.Namespace, cfg: Config) -> int:
    from . import install

    try:
        for line in install.uninstall(cfg, scope=args.scope):
            _out(line)
    except (ValueError, json.JSONDecodeError) as exc:
        _err(f"could not update the settings file: {exc}")
        return 1
    except OSError as exc:
        _err(f"could not write {exc.filename or 'a file'}: {exc.strerror or exc}")
        return 1
    return 0


def cmd_hook(args: argparse.Namespace, cfg: Config) -> int:
    from .hooks import claude_code

    return claude_code.main()


# -- reading the graph ---------------------------------------------------------------------


def cmd_status(args: argparse.Namespace, cfg: Config) -> int:
    from . import install

    color = report.use_color()
    registered = [scope for scope in ("project", "local", "user") if install.is_installed(install.settings_path(cfg, scope))]
    info: dict[str, Any] = {"project": str(cfg.root), "mode": cfg.mode, "fail_closed": cfg.fail_closed,
                            "hooks": registered, "graph": str(cfg.db_path), "config_error": cfg.config_error}
    try:
        with _read_store(cfg) as store:
            info.update(report.status(store))
    except StoreMissing:
        info["nodes"] = 0
    info["archived"] = len(retention.archived(cfg))
    if args.json:
        _out(json.dumps(info, indent=1, default=str))
        return 0
    _out(f"project      {cfg.root}")
    _out(f"mode         {cfg.mode}" + ("  (fail closed)" if cfg.fail_closed else ""))
    if cfg.config_error:
        _out("config       " + report.paint(cfg.config_error, "bright_red", "bold", color=color))
    elif os.environ.get("TAINTTRAIL_KEY"):
        _out("key          from TAINTTRAIL_KEY. That is for tests and demos: whoever can guess the key can test guesses "
             "of a secret against an export")
    hooks = ", ".join(registered) if registered else report.paint("not registered: run `tainttrail init`", "yellow", color=color)
    _out(f"hooks        {hooks}")
    if any(install.is_outdated(install.settings_path(cfg, scope)) for scope in registered):
        _out("             " + report.paint("written by an older version: run `tainttrail init` again (the old command starts "
                                             "Python with the project folder on its module path)", "yellow", color=color))
    if not info.get("nodes"):
        _out("graph        nothing recorded yet")
        return 0
    size = cfg.db_path.stat().st_size if cfg.db_path.exists() else 0
    _out(f"graph        {cfg.db_path}  ({info['nodes']} nodes, {size / 1024:.0f} KB)")
    sessions_line = f"sessions     {info['sessions']}"
    if info.get("archived"):
        sessions_line += f"  (+ {info['archived']} older in {retention.archive_dir(cfg)}; open one with `tainttrail ui --file`)"
    _out(sessions_line)
    _out(f"tool calls   {info['calls']}  ({info['asked']} asked, "
         + report.paint(f"{info['denied']} denied", *(("bright_red", "bold") if info["denied"] else ()), color=color) + ")")
    _out(f"content      {info['untrusted']} untrusted, {info['sensitive']} sensitive")
    _out(f"findings     {info['findings']}")
    if info.get("servers") or info.get("tools"):
        _out(f"capability   {info['servers']} servers, {info['tools']} tools")
    return 0


def cmd_sessions(args: argparse.Namespace, cfg: Config) -> int:
    with _read_store(cfg) as store:
        rows = report.sessions(store)
    _out(json.dumps(rows, indent=1) if args.json else report.render_sessions(rows, color=report.use_color()))
    return 0


def cmd_log(args: argparse.Namespace, cfg: Config) -> int:
    with _read_store(cfg) as store:
        sid = report.resolve_session(store, args.session)
        if sid is None:
            _err("no such session" if args.session else "no sessions recorded yet")
            return 1
        rows = report.timeline(store, sid)
    if args.limit:
        rows = rows[-args.limit:]
    if args.json:
        _out(json.dumps(rows, indent=1))
        return 0
    _out(report.paint(f"session {sid}", "bold", color=report.use_color()))
    _out(report.render_timeline(rows, color=report.use_color(), width=_width()))
    return 0


def cmd_findings(args: argparse.Namespace, cfg: Config) -> int:
    with _read_store(cfg) as store:
        sid = report.resolve_session(store, args.session) if args.session else None
        if args.session and sid is None:
            _err("no such session")
            return 1
        rows = report.findings(store, session_id=sid, min_severity=args.severity, blocking_only=not args.all,
                               limit=args.limit)
    if args.json:
        _out(json.dumps([{**r, "path": [s.__dict__ for s in r["path"]]} for r in rows], indent=1))
        return 0
    _out(report.render_findings(rows, color=report.use_color(), width=_width()))
    if not args.all and rows:
        _out(report.paint("Shown: findings that asked or denied. --all adds the ones that were only noted.",
                          "dim", color=report.use_color()))
    return 0


def cmd_explain(args: argparse.Namespace, cfg: Config) -> int:
    with _read_store(cfg) as store:
        finding = report.get_finding(store, args.finding)
    if finding is None:
        _err("no such finding" if args.finding else "no findings recorded yet")
        return 1
    if args.json:
        _out(json.dumps({**finding, "path": [s.__dict__ for s in finding["path"]]}, indent=1))
        return 0
    _out(report.render_finding(finding, color=report.use_color(), width=min(_width(), 100), show_query=not args.no_query))
    return 0


def _parse_params(items: list[str]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for item in items:
        name, eq, value = item.partition("=")
        if not eq:
            raise ValueError(f"--param needs name=value, got {item!r}")
        try:
            params[name] = json.loads(value)
        except ValueError:
            params[name] = value
    return params


def cmd_query(args: argparse.Namespace, cfg: Config) -> int:
    """Run Cypher against the graph, read-only. With --finding, re-run a finding's own query."""
    try:
        params = _parse_params(args.param or [])
    except ValueError as exc:
        _err(str(exc))
        return 2
    try:
        with _read_store(cfg) as store:
            query = args.cypher
            if args.finding:
                finding = report.get_finding(store, args.finding)
                if finding is None or not finding.get("query"):
                    _err("that finding has no stored query")
                    return 1
                query, params = finding["query"], {**finding["params"], **params}
            if not query:
                _err('give a statement, for example: tainttrail query "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n"')
                return 2
            started = time.perf_counter()
            rows = store.run(query, params)
            elapsed = (time.perf_counter() - started) * 1000
    except StoreError:
        raise
    except Exception as exc:   # noqa: BLE001 - Relate's message says what to fix
        _err(str(exc))
        return 1
    if args.json:
        _out(json.dumps(rows, indent=1, default=str))
        return 0
    if not rows:
        _out("(no rows)")
    else:
        columns = [str(report.printable(c)) for c in rows[0]]
        shown = rows[: args.limit] if args.limit and args.limit > 0 else rows
        cells = [[report.printable(_cell(v)) for v in r.values()] for r in shown]
        widths = [min(60, max([len(c), *(len(row[i]) for row in cells)])) for i, c in enumerate(columns)]
        color = report.use_color()
        _out(report.paint("  ".join(c.ljust(w) for c, w in zip(columns, widths)), "bold", color=color))
        for row in cells:
            _out("  ".join((v if len(v) <= w else v[: w - 1] + "…").ljust(w) for v, w in zip(row, widths)))
        if len(rows) > len(shown):
            _out(f"... {len(rows) - len(shown)} more rows (--limit)")
    _out(report.paint(f"{len(rows)} row{'s' if len(rows) != 1 else ''} in {elapsed:.1f} ms", "dim", color=report.use_color()))
    return 0


def _cell(value: Any) -> str:
    if isinstance(value, dict) and "nodes" in value and "rels" in value:
        return " - ".join(str(n.get("id")) for n in value["nodes"])
    if isinstance(value, dict) and "labels" in value:
        return f"({':'.join(value['labels'])} {value.get('id')})"
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return "" if value is None else str(value)


def cmd_trust(args: argparse.Namespace, cfg: Config) -> int:
    from .extract import file_entity
    from .recorder import Recorder

    ref = file_entity(args.path, os.getcwd())
    if not cfg.db_path.exists():   # looking must not create a graph, and with it a "project"
        _err(f"nothing has been recorded in {cfg.root}; there is no taint to clear")
        return 1
    with open_store(cfg) as store:
        ok = Recorder(store, cfg).trust_entity(ref.id)
    if not ok:
        _err(f"{ref.value} is not in the graph; nothing to clear")
        return 1
    _out(f"cleared the taint on {ref.value}. Later sessions will not inherit it.")
    return 0


# -- demo ----------------------------------------------------------------------------------


def cmd_demo(args: argparse.Namespace, cfg: Config) -> int:
    from . import scenarios

    color = report.use_color()
    if args.action == "list":
        last = None
        for sc in scenarios.list_scenarios():
            if sc["group"] != last:
                last = sc["group"]
                heading = {"attack": "Attacks the guard must stop", "variant": "Attack variants, aimed at the edges of the rules",
                           "benign": "Ordinary work it must leave alone",
                           "ordinary": "Ordinary sessions, a reviewer's corpus for false alarms",
                           "known_gaps": "Harder cases", "open": "Known gaps: attacks that are not stopped yet"}[last]
                _out(report.paint(heading, "bold", color=color))
            _out(f"  {sc['id'].split('-', 1)[0]:5s} {sc['title']}")
        _out()
        _out("Run one with `tainttrail demo run a02`. Add --no-guard to see it without enforcement, --compare for both.")
        return 0
    if args.action == "all":
        return _demo_all(args, color)
    if not args.scenario:
        _err("which scenario? `tainttrail demo list` shows them")
        return 2
    try:
        scenario = scenarios.load_scenario(args.scenario)
    except LookupError as exc:
        _err(str(exc))
        return 1

    keep = Path(args.keep).resolve() if args.keep else None
    if keep is not None:
        problem = _claim_demo_dir(keep)
        if problem:
            _err(problem)
            return 2
    modes = [False, True] if args.compare else [not args.no_guard]
    _out(report.paint(f"{scenario['id']}  {scenario['title']}", "bold", color=color))
    _wrap(scenario.get("story", ""), color=False)
    if scenario.get("inspired_by"):
        _wrap("Modelled on: " + scenario["inspired_by"], dim=color)
    _wrap("The agent in this replay is scripted to do what the content tells it. A real model may refuse; "
          "the guard is for the time it does not. All secrets are canaries and no network is contacted.", dim=color)
    status = 0
    for guard in modes:
        base = Path(tempfile.mkdtemp(prefix="tainttrail-demo-"))
        root = (keep if keep and guard == modes[-1] else base) / ("project" if not keep or guard != modes[-1] else "")
        result = scenarios.replay(scenario, root, guard=guard)
        _out()
        _out(report.paint("With the guard" if guard else "Without the guard (monitor mode)", "bold", color=color))
        run_cfg = load_config(result.root)
        with open_store(run_cfg, read_only=True) as store:
            for sid in result.sessions:
                if len(result.sessions) > 1:
                    _out(report.paint(f"  session {sid.rsplit('-', 1)[-1]}", "dim", color=color))
                _out(report.render_timeline(report.timeline(store, sid), color=color, width=_width()))
            finding = report.get_finding(store, "last")
            nodes = store.scalar("MATCH (n) RETURN count(n)", default=0)
        _out()
        _out(_verdict(result, guard, color))
        if guard and finding and not args.brief:
            _out()
            _out(report.render_finding(finding, color=color, width=min(_width(), 100), show_query=not args.no_query))
        if guard and not result.ok:
            status = 1
            _out(report.paint("The scenario's expectations were not met.", "bright_red", color=color))
        if keep and guard == modes[-1]:
            _out()
            _out(f"Kept: {result.root}  ({nodes} nodes in {run_cfg.db_path.name})")
            _out(f"Look around: tainttrail -C {result.root} log | findings | ui")
        else:
            shutil.rmtree(base, ignore_errors=True)
    return status


DEMO_MARKER = ".tainttrail-demo"


def _claim_demo_dir(path: Path) -> str | None:
    """Make ``path`` an empty directory that belongs to the demo, or say why not.

    A replay writes a whole project: a ``.git/config``, a ``.env``, the guard's config. It
    must never do that to a directory that already holds something else.
    """
    if path.exists():
        if not path.is_dir():
            return f"{path} is not a directory"
        if any(path.iterdir()):
            if not (path / DEMO_MARKER).is_file():
                return (f"{path} is not empty. --keep writes a whole demo project (a .git/config, a .env, "
                        "the guard's config) and will not write into an existing directory; give it a new one.")
            shutil.rmtree(path)   # an earlier demo run: start again rather than replay on top of it
    path.mkdir(parents=True, exist_ok=True)
    (path / DEMO_MARKER).write_text("Created by `tainttrail demo --keep`. Safe to delete.\n", encoding="utf-8")
    return None


def _demo_all(args: argparse.Namespace, color: bool) -> int:
    """Replay every scenario and print one line each: the suite as a table."""
    from . import scenarios

    rows = []
    base = Path(tempfile.mkdtemp(prefix="tainttrail-demo-"))
    try:
        for i, sc in enumerate(scenarios.list_scenarios()):
            rows.append((sc, scenarios.replay(sc, base / f"p{i}", guard=not args.no_guard)))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if args.json:
        _out(json.dumps([{"id": sc["id"], "group": sc["group"], "title": sc["title"], "ok": r.ok,
                          "blocked_at": r.blocked_at, "asked_at": r.asked_at, "leaked": len(r.leaked),
                          "rules": sorted({x for s in r.steps for x in s.rules}), "ms": r.elapsed_ms}
                         for sc, r in rows], indent=1))
        return 0 if all(r.ok for _, r in rows) else 1
    headings = {"attack": "Attacks", "variant": "Attack variants", "benign": "Ordinary work",
                "ordinary": "Ordinary sessions", "known_gaps": "Harder cases", "open": "Known gaps: attacks that are not stopped yet"}
    # The two large groups are summarised; a row is printed only when it is not the expected kind.
    folded = () if getattr(args, "full", False) else ("variant", "ordinary")

    def untouched(r: Any) -> bool:
        return all(s.action == "allow" for s in r.steps)

    def stopped(r: Any) -> bool:
        return not r.leaked and (r.blocked_at is not None or bool(r.asked_at))

    last = None
    for sc, r in rows:
        group = sc["group"]
        if group != last:
            last = group
            members = [x for y, x in rows if y["group"] == group]
            if group in folded:
                good = sum(1 for x in members if (untouched(x) if group == "ordinary" else stopped(x)))
                word = "untouched" if group == "ordinary" else "denied or asked"
                _out(report.paint(f"{headings[group]:<62} {good} of {len(members)} {word}", "bold", color=color)
                     + report.paint("   (--full lists them)", "dim", color=color))
            else:
                _out(report.paint(f"{headings[group]:<62} outcome", "bold", color=color))
        if group in folded and not args.no_guard and (untouched(r) if group == "ordinary" else stopped(r)):
            continue
        if group in folded and args.no_guard:
            continue
        rules = " ".join(sorted({x for s in r.steps for x in s.rules}))
        if r.leaked:
            outcome = report.paint(f"LEAKED {len(r.leaked)}", "bright_red", "bold", color=color)
        elif r.blocked_at is not None:
            outcome = report.paint("denied ", "bright_red", "bold", color=color) + rules
        elif r.asked_at:
            outcome = report.paint("asked  ", "bright_yellow", "bold", color=color) + rules
        elif group == "open":
            outcome = report.paint("not stopped", "bright_yellow", color=color)
        else:
            outcome = report.paint("untouched", "green", color=color)
        flag = "" if r.ok or args.no_guard else report.paint("  (not as expected)", "bright_red", color=color)
        title = sc["title"] if len(sc["title"]) <= 55 else sc["title"][:54] + "…"
        _out(f"  {sc['id'].split('-', 1)[0]:5s} {title:<55} {outcome}{flag}")

    def of(group: str) -> list[Any]:
        return [r for sc, r in rows if sc["group"] == group]

    attacks, variants, benign, ordinary, gaps = of("attack"), of("variant"), of("benign"), of("ordinary"), of("known_gaps")
    _out()
    if args.no_guard:
        leaked = sum(len(r.leaked) for _, r in rows)
        _out(f"Monitor mode: nothing was stopped. {leaked} canary secrets left the machine across {len(rows)} scenarios.")
        return 0
    _out(f"attacks stopped or put to the user   {sum(map(stopped, attacks))} of {len(attacks)}   "
         f"({sum(1 for r in attacks if r.blocked_at is not None)} denied outright)")
    _out(f"attack variants stopped              {sum(map(stopped, variants))} of {len(variants)}")
    _out(f"ordinary work left untouched         {sum(map(untouched, benign))} of {len(benign)}")
    _out(f"ordinary sessions left untouched     {sum(map(untouched, ordinary))} of {len(ordinary)}")
    _out(f"harder cases put to the user         {sum(map(stopped, gaps))} of {len(gaps)}")
    if of("open"):
        _out(f"known gaps, not stopped yet          {sum(1 for r in of('open') if not stopped(r))}")
    _out(f"canary secrets that left             {sum(len(r.leaked) for _, r in rows)}")
    per_event = statistics.median(r.elapsed_ms / max(1, 2 * sum(1 for s in r.steps if s.kind == 'tool') + 2) for _, r in rows)
    _out(report.paint(f"{len(rows)} scenarios replayed through the Claude Code hook adapter, {per_event:.0f} ms per hook event in process",
                      "dim", color=color))
    return 0 if all(r.ok for _, r in rows) else 1


def _verdict(result: Any, guard: bool, color: bool) -> str:
    n = len(result.leaked)
    if not guard:
        if n:
            return report.paint(f"Nothing was stopped. {n} canary secret{'s' if n != 1 else ''} left the machine.",
                                "bright_red", "bold", color=color)
        return "Nothing was stopped, and nothing sensitive was sent."
    parts = []
    if result.blocked_at is not None:
        step = next(s for s in result.steps if s.index == result.blocked_at)
        held = len(result.held)
        parts.append(report.paint(f"Blocked: {step.summary or step.tool}", "green", "bold", color=color)
                     + (f"  ({held} canary secret{'s' if held != 1 else ''} stayed on the machine)" if held else ""))
    asked = [s for s in result.steps if s.action == "ask"]
    if asked:
        parts.append(f"Asked the user {len(asked)} time{'s' if len(asked) != 1 else ''}: "
                     + ", ".join(sorted({r for s in asked for r in s.rules})))
    if n:
        parts.append(report.paint(f"{n} canary secret{'s' if n != 1 else ''} left without a prompt.", "bright_red", "bold", color=color))
    if not parts:
        parts.append(report.paint("Nothing was stopped or questioned, as it should be for ordinary work.", "green", color=color))
    return "\n".join(parts)


# -- doctor --------------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace, cfg: Config) -> int:
    """Check the installation and measure what the hook costs per tool call."""
    from . import install, scenarios

    color = report.use_color()
    problems = 0

    def line(ok: bool | None, label: str, detail: str) -> None:
        nonlocal problems
        mark = {True: report.paint("ok  ", "green", color=color), False: report.paint("FAIL", "bright_red", "bold", color=color),
                None: report.paint("note", "yellow", color=color)}[ok]
        problems += ok is False
        _out(f"{mark}  {label:<18} {detail}")

    line(sys.version_info >= (3, 10), "python", sys.version.split()[0])
    try:
        import relate

        line(True, "relate", f"{relate.__version__} (embedded, in process)")
    except Exception as exc:   # noqa: BLE001
        line(False, "relate", f"cannot import: {exc}")
        return 1
    line(True, "tainttrail", f"{__version__} at {Path(__file__).parent}")
    registered = [scope for scope in ("project", "local", "user") if install.is_installed(install.settings_path(cfg, scope))]
    line(bool(registered) or None, "hooks", ", ".join(registered) if registered else "not registered for this project (`tainttrail init`)")
    old = [scope for scope in registered if install.is_outdated(install.settings_path(cfg, scope))]
    if old:
        line(False, "hook command", f"written by an older version ({', '.join(old)}): it starts Python with the project folder "
                                    "on its module path. Run `tainttrail init` again")
    if cfg.config_error:
        line(False, "config", cfg.config_error)
    if not cfg.db_path.exists():   # a check must not create a graph, and with it a "project"
        line(None, "graph", f"nothing recorded yet in {cfg.root}")
    else:
        try:
            with open_store(cfg) as store:
                nodes = store.scalar("MATCH (n) RETURN count(n)", default=0)
                recovered = store.recovered
            if recovered:
                source = "the version before it" if recovered["restored"] == "previous" else "a new, empty graph"
                line(None, "graph", f"{cfg.db_path} did not open ({recovered['error']}); it was set aside as "
                                    f"{Path(recovered['damaged']).name} and replaced by {source}")
            line(True, "graph", f"{cfg.db_path} opens for writing ({nodes} nodes)")
        except Exception as exc:   # noqa: BLE001
            line(False, "graph", f"{cfg.db_path}: {exc}")
    claude = shutil.which("claude")
    line(bool(claude) or None, "claude cli", claude or "not on PATH (only needed for `tainttrail audit --agent`)")

    # What one guarded tool call costs: PreToolUse + PostToolUse in a scratch project, in process.
    base = Path(tempfile.mkdtemp(prefix="tainttrail-doctor-"))
    try:
        scenario = scenarios.load_scenario("b01")
        timings = []
        for i in range(args.rounds):
            started = time.perf_counter()
            result = scenarios.replay(scenario, base / f"p{i}")
            calls = sum(1 for s in result.steps if s.kind == "tool")
            timings.append((time.perf_counter() - started) * 1000 / max(1, calls * 2 + 2))
        per_event = statistics.median(timings)
        # ... and as the agent runs it: a process of its own for every event, in that scratch project.
        import shlex
        import subprocess

        payload = json.dumps({"session_id": "doctor", "cwd": str(result.root), "hook_event_name": "PreToolUse",
                              "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "doctor"})
        # The scratch project, whatever the caller's environment says: this must not be recorded
        # in the project the doctor was started from.
        scratch = {k: v for k, v in os.environ.items()
                   if k not in ("CLAUDE_PROJECT_DIR", "TAINTTRAIL_DB", "TAINTTRAIL_HOME", "TAINTTRAIL_MODE")}
        spent = []
        for _ in range(args.rounds):
            started = time.perf_counter()
            subprocess.run(shlex.split(install.hook_command()), input=payload, text=True, env=scratch,
                           capture_output=True, cwd=result.root, timeout=60, check=False)
            spent.append((time.perf_counter() - started) * 1000)
        whole = statistics.median(spent)
        # The rest of it is starting Python and loading the engine.
        line(whole < 1000, "hook latency", f"{whole:.0f} ms per hook process, as the agent runs it (median of {args.rounds}); "
             f"{per_event:.0f} ms of that is rule and graph work")
    except Exception as exc:   # noqa: BLE001
        line(False, "hook latency", f"could not measure: {exc}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return 1 if problems else 0


# -- plumbing ---------------------------------------------------------------------------------


def _width() -> int:
    return max(80, min(140, shutil.get_terminal_size((110, 30)).columns))


def _wrap(text: str, *, color: bool = False, dim: bool = False) -> None:
    import textwrap

    for line in textwrap.wrap(text, width=min(_width(), 100)) or [""]:
        _out(report.paint(line, "dim", color=dim) if dim else line)


def _delegate(name: str) -> Callable[[argparse.Namespace, Config], int]:
    module, _, func, _ = DELEGATED[name]

    def run(args: argparse.Namespace, cfg: Config) -> int:
        try:
            mod = importlib.import_module(f".{module}", __package__)
        except ModuleNotFoundError as exc:
            _err(f"`{name}` is not available in this build ({exc})")
            return 1
        return int(getattr(mod, func)(args, cfg) or 0)

    return run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tainttrail",
        description="Attack-path guard for AI agents, built on the Relate embedded graph database.",
        epilog="Start with `tainttrail demo run a02`, then `tainttrail init` in a project you use Claude Code in.",
    )
    parser.add_argument("--version", action="version", version=f"tainttrail {__version__}")
    parser.add_argument("-C", "--project", metavar="DIR", help="act on this project instead of the current directory")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("init", help="install the guard for Claude Code in this project")
    p.add_argument("--scope", choices=("project", "local", "user"), default="project",
                   help="settings file to register the hooks in: .claude/settings.json (default), "
                        ".claude/settings.local.json, or ~/.claude/settings.json")
    p.add_argument("--mode", choices=("monitor", "guard", "strict"), default="guard")
    p.add_argument("--fail-closed", action="store_true", help="block tool calls when the guard itself fails")
    p.add_argument("--python", metavar="PATH", help="interpreter the hook should use (default: this one)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("uninstall", help="remove the hook registration (keeps the recorded graph)")
    p.add_argument("--scope", choices=("project", "local", "user"), default="project")
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("hook", help="hook entry point, called by the agent harness")
    p.add_argument("harness", nargs="?", default="claude-code", choices=("claude-code",))
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("status", help="mode, hook registration and what has been recorded")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("sessions", help="recorded sessions")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("log", help="timeline of a session: what entered the context, what was decided")
    p.add_argument("session", nargs="?", help="session id or unique prefix (default: the latest)")
    p.add_argument("-n", "--limit", type=int, default=0, help="only the last N events")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("findings", help="what the rules found")
    p.add_argument("--session", help="session id or unique prefix")
    p.add_argument("--severity", choices=("info", "low", "medium", "high", "critical"), default="info")
    p.add_argument("--all", action="store_true", help="include findings that were only noted")
    p.add_argument("-n", "--limit", type=int, default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("explain", help="one finding in full: the attack path and the Cypher that found it")
    p.add_argument("finding", nargs="?", help="finding id, rule id, or nothing for the latest block")
    p.add_argument("--no-query", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("query", help="run Cypher against the graph, read-only")
    p.add_argument("cypher", nargs="?")
    p.add_argument("--finding", metavar="ID", help="re-run the stored query of a finding")
    p.add_argument("--param", action="append", metavar="NAME=VALUE", help="bind a parameter (JSON value or string)")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_query)

    p = sub.add_parser("trust", help="mark a file as reviewed so later sessions do not inherit its taint")
    p.add_argument("path")
    p.set_defaults(func=cmd_trust)

    p = sub.add_parser("demo", help="replay a scripted attack or a benign workflow through the guard")
    p.add_argument("action", choices=("list", "run", "all"),
                   help="list the scenarios, run one, or replay all of them as a table")
    p.add_argument("scenario", nargs="?")
    p.add_argument("--json", action="store_true", help="with `all`: machine-readable results")
    p.add_argument("--no-guard", action="store_true", help="monitor mode: record, stop nothing")
    p.add_argument("--compare", action="store_true", help="run without the guard, then with it")
    p.add_argument("--keep", metavar="DIR", help="keep the replayed project (and its graph) in DIR")
    p.add_argument("--full", action="store_true", help="with `all`: list every scenario of the two large groups too")
    p.add_argument("--brief", action="store_true", help="timeline and verdict only")
    p.add_argument("--no-query", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("doctor", help="check the installation and measure hook latency")
    p.add_argument("--rounds", type=int, default=5)
    p.set_defaults(func=cmd_doctor)

    for name, (module, add_args, _, help_text) in DELEGATED.items():
        p = sub.add_parser(name, help=help_text)
        try:
            getattr(importlib.import_module(f".{module}", __package__), add_args)(p)
        except (ModuleNotFoundError, AttributeError):
            pass   # the command reports the missing module when it is run
        p.set_defaults(func=_delegate(name))
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # The hook path must stay fast and must not depend on the other commands' modules.
    if argv[:1] == ["hook"] and argv[1:2] in ([], ["claude-code"]):
        from .hooks import claude_code

        return claude_code.main()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    cfg = load_config(args.project or None)
    try:
        return int(args.func(args, cfg) or 0)
    except StoreMissing as exc:
        _err(str(exc))
        return 1
    except StoreError as exc:
        _err(str(exc))
        return 1
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
