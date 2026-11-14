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

from . import __version__, report
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
    sys.stdout.write(text + "\n")


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
    for line in lines:
        _out(line)
    _out()
    _out("TaintTrail now sees every prompt and tool call of Claude Code sessions in this project.")
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
                            "hooks": registered, "graph": str(cfg.db_path)}
    try:
        with _read_store(cfg) as store:
            info.update(report.status(store))
    except StoreMissing:
        info["nodes"] = 0
    if args.json:
        _out(json.dumps(info, indent=1, default=str))
        return 0
    _out(f"project      {cfg.root}")
    _out(f"mode         {cfg.mode}" + ("  (fail closed)" if cfg.fail_closed else ""))
    hooks = ", ".join(registered) if registered else report.paint("not registered: run `tainttrail init`", "yellow", color=color)
    _out(f"hooks        {hooks}")
    if not info.get("nodes"):
        _out("graph        nothing recorded yet")
        return 0
    size = cfg.db_path.stat().st_size if cfg.db_path.exists() else 0
    _out(f"graph        {cfg.db_path}  ({info['nodes']} nodes, {size / 1024:.0f} KB)")
    _out(f"sessions     {info['sessions']}")
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
        columns = list(rows[0])
        cells = [[_cell(r[c]) for c in columns] for r in rows[: args.limit]]
        widths = [min(60, max(len(c), *(len(row[i]) for row in cells))) for i, c in enumerate(columns)]
        color = report.use_color()
        _out(report.paint("  ".join(c.ljust(w) for c, w in zip(columns, widths)), "bold", color=color))
        for row in cells:
            _out("  ".join((v if len(v) <= w else v[: w - 1] + "…").ljust(w) for v, w in zip(row, widths)))
        if len(rows) > args.limit:
            _out(f"... {len(rows) - args.limit} more rows (--limit)")
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
                heading = {"attack": "Attacks the guard must stop", "benign": "Ordinary work it must leave alone",
                           "known_gaps": "Harder cases"}[last]
                _out(report.paint(heading, "bold", color=color))
            _out(f"  {sc['id'].split('-', 1)[0]:5s} {sc['title']}")
        _out()
        _out("Run one with `tainttrail demo run a02`. Add --no-guard to see it without enforcement, --compare for both.")
        return 0
    if not args.scenario:
        _err("which scenario? `tainttrail demo list` shows them")
        return 2
    try:
        scenario = scenarios.load_scenario(args.scenario)
    except LookupError as exc:
        _err(str(exc))
        return 1

    keep = Path(args.keep).resolve() if args.keep else None
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
    try:
        with open_store(cfg) as store:
            nodes = store.scalar("MATCH (n) RETURN count(n)", default=0)
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
        line(per_event < 150, "hook latency", f"{per_event:.0f} ms per event in process (median of {args.rounds}); "
             "a real hook adds interpreter start-up, about 70 ms")
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
    p.add_argument("action", choices=("list", "run"))
    p.add_argument("scenario", nargs="?")
    p.add_argument("--no-guard", action="store_true", help="monitor mode: record, stop nothing")
    p.add_argument("--compare", action="store_true", help="run without the guard, then with it")
    p.add_argument("--keep", metavar="DIR", help="keep the replayed project (and its graph) in DIR")
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
    if argv[:1] == ["hook"]:
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
