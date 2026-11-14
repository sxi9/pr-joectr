"""``tainttrail ui``: the offline viewer, served from this machine only.

The viewer is a static web app (``viewer/``) that loads Relate's WebAssembly build and
replays an export of the graph in the browser. This module exports the project's graph to
a temporary directory and serves the viewer files plus that one ``graph.json`` on the
loopback interface, or writes the same files to a directory that any static host can
serve. Instead of the project's graph it can show a file (``--file``: an export, an
archived session, or a Relate store) or the bundled sample (``--sample``).

The server is deliberately small and strict. It answers GET and HEAD for a fixed set of
file types below two fixed roots, binds to ``127.0.0.1`` only, refuses a request whose
``Host`` header is not a loopback name (so a web page cannot reach it through DNS
rebinding), and sends a Content-Security-Policy that allows same-origin scripts and
WebAssembly and nothing else. The graph holds text that an attacker wrote; the viewer
renders it as text and the policy is the second line of defence.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import shutil
import signal
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote

from . import __version__
from .config import Config

VIEWER_DIR = Path(__file__).resolve().parent / "viewer"
SAMPLE_GRAPH = VIEWER_DIR / "sample" / "graph.json"
GRAPH_NAME = "graph.json"
MARKER_NAME = "tainttrail-viewer.txt"
LOOPBACK = "127.0.0.1"
EXPORT_FORMAT = "tainttrail-export/1"  # export.FORMAT, repeated so that --sample needs no store
MAX_EXPORT_FILE_BYTES = 64 * 1024 * 1024  # the limit the viewer itself applies to a file it is given

# Pinned on purpose. ``mimetypes`` reads the host's own tables, and a host that maps .js to
# text/plain makes browsers refuse module scripts ("Failed to load module script").
MIME: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".wasm": "application/wasm",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
}
# Files without an extension that belong to the app: the licence of the vendored engine.
PLAIN_NAMES = frozenset({"LICENSE", "NOTICE"})

# Same-origin scripts, styles and fetches; WebAssembly may be compiled ('wasm-unsafe-eval');
# no inline script or style, no frames, no forms, nothing from another origin.
CSP = (
    "default-src 'none'; "
    "script-src 'self' 'wasm-unsafe-eval'; "
    "worker-src 'self'; "
    "connect-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", CSP),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("X-Frame-Options", "DENY"),
)

# One path segment of a file we serve: starts with a letter or digit, then letters, digits,
# dot, dash and underscore. No dotfiles, no "..", no separators, no control characters.
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_LOOPBACK_HOST = re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?", re.IGNORECASE | re.ASCII)


class UiError(Exception):
    """A problem to report to the person at the terminal; the message is the whole story."""


def content_type(name: str) -> str | None:
    """The MIME type a file is served with, or None when the server does not serve it."""
    name = name.rsplit("/", 1)[-1]
    if name in PLAIN_NAMES:
        return "text/plain; charset=utf-8"
    dot = name.rfind(".")
    if dot <= 0:
        return None
    return MIME.get(name[dot:].lower())


def split_request_path(raw: str) -> list[str] | None:
    """The segments of a request target, or None when it is not a plain path below ``/``.

    Percent-decoding happens once, before the checks, so an encoded ``..`` or separator is
    judged in its decoded form; a second layer of encoding stays literal and matches no file.
    """
    path = raw.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        return None  # absolute-form target, or garbage
    try:
        path = unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if path == "/":
        return ["index.html"]
    segments = path[1:].split("/")
    if len(segments) > 12 or not all(_SEGMENT.match(s) for s in segments):
        return None
    return segments


def resolve_file(segments: list[str], viewer_dir: Path, graph_file: Path | None) -> Path | None:
    """The file to serve for a request, or None.

    Symbolic links are followed and the result must still lie inside the viewer directory,
    so a link placed in the tree cannot point the server at another file.
    """
    if content_type(segments[-1]) is None:
        return None
    if segments == [GRAPH_NAME] and graph_file is not None:
        return graph_file if graph_file.is_file() else None
    try:
        root = viewer_dir.resolve(strict=True)
        target = root.joinpath(*segments).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target


def _host_is_loopback(host_header: str | None) -> bool:
    """True for ``127.0.0.1[:port]``, ``localhost[:port]`` and ``[::1][:port]``, and nothing else.

    A request without a Host header cannot come from a browser, so it is not a rebinding
    attempt and is let through.
    """
    if host_header is None:
        return True
    return _LOOPBACK_HOST.fullmatch(host_header.strip(" \t")) is not None


class ViewerHandler(BaseHTTPRequestHandler):
    """GET and HEAD for the viewer's files and the one exported graph. Nothing else."""

    timeout = 30  # seconds a connection may stay silent before its thread lets go of it
    # Set per server by make_server().
    viewer_dir: Path = VIEWER_DIR
    graph_file: Path | None = None
    verbose = False

    def do_GET(self) -> None:  # noqa: N802 - the base class dispatches on this name
        self._respond(body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(body=False)

    def _respond(self, *, body: bool) -> None:
        if self.request_version == "HTTP/0.9":
            # A bare "GET /path" line: the answer could carry no status line and no header,
            # so no content type and no policy. No browser asks this way; nothing is served.
            self.close_connection = True
            return
        hosts = self.headers.get_all("Host") or []
        if len(hosts) > 1:
            # Which one a browser meant cannot be known, and a browser sends exactly one.
            self._plain(400, "Bad request: more than one Host header.\n", body)
            return
        if not _host_is_loopback(hosts[0] if hosts else None):
            self._plain(403, "Forbidden: this server answers only to 127.0.0.1 and localhost.\n", body)
            return
        segments = split_request_path(self.path)
        target = resolve_file(segments, self.viewer_dir, self.graph_file) if segments else None
        if target is None:
            self._plain(404, "Not found.\n", body)
            return
        try:
            data = target.read_bytes()
        except OSError:
            self._plain(404, "Not found.\n", body)
            return
        self._send(200, content_type(segments[-1]) or "application/octet-stream", data, body)

    def _plain(self, status: int, text: str, body: bool) -> None:
        self._send(status, "text/plain; charset=utf-8", text.encode("utf-8"), body)

    def _send(self, status: int, mime: str, data: bytes, body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        if body:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the browser went away mid-transfer; nothing to do

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Errors the base class raises itself (bad request line, unsupported method).

        The stock page echoes parts of the request; a fixed line of text does not.
        """
        try:
            self._plain(code, f"{code} {message or 'Error'}\n", self.command != "HEAD")
        except (OSError, ValueError):
            pass
        self.close_connection = True

    def version_string(self) -> str:
        """The Server header: a name, and not which Python on which system is behind it."""
        return "tainttrail-ui"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base class signature
        if self.verbose:
            super().log_message(format, *args)


class _Server(ThreadingHTTPServer):
    daemon_threads = True  # a stuck connection must not keep the process alive after Ctrl+C

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that drops its connection is not worth a traceback on the terminal."""
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def make_server(graph_file: Path | None, *, port: int = 0, viewer_dir: Path = VIEWER_DIR,
                verbose: bool = False) -> ThreadingHTTPServer:
    """A server for the viewer and one graph file, bound to the loopback interface.

    There is no parameter for the address on purpose: the graph is evidence about one
    machine and must not be reachable from another. ``port=0`` picks a free port; read it
    from ``server.server_address``. The caller runs ``serve_forever()`` and closes it.
    """
    handler = type("BoundViewerHandler", (ViewerHandler,), {
        "viewer_dir": Path(viewer_dir), "graph_file": Path(graph_file) if graph_file else None,
        "verbose": verbose,
    })
    return _Server((LOOPBACK, port), handler)


def server_url(server: ThreadingHTTPServer) -> str:
    return f"http://{LOOPBACK}:{server.server_address[1]}/"


# -- the files of the app ------------------------------------------------------------------


def viewer_files(viewer_dir: Path = VIEWER_DIR) -> list[str]:
    """Relative POSIX paths of every file that belongs to the static app, sorted.

    The same rule the server applies: a servable type, and every path segment a plain
    name. Build helpers and caches that sit next to the app are left out by it.
    """
    root = Path(viewer_dir)
    out: list[str] = []
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if rel == GRAPH_NAME or not path.is_file():
            continue
        if content_type(path.name) is None or not all(_SEGMENT.match(s) for s in rel.split("/")):
            continue
        out.append(rel)
    return sorted(out)


def write_static_copy(graph_json: str, target: Path, *, viewer_dir: Path = VIEWER_DIR) -> list[str]:
    """Write the viewer and one graph into ``target`` as a self-contained static site.

    Returns the relative paths written. Refuses a directory that holds anything other than
    an earlier copy, so a mistyped path cannot scatter files over someone's work.
    """
    target = Path(target)
    if target.exists() and not target.is_dir():
        raise UiError(f"{target} exists and is not a directory")
    if target.resolve().is_relative_to(Path(viewer_dir).resolve()):
        raise UiError(f"{target} is inside the installed viewer; choose a directory elsewhere")
    if target.is_dir() and any(target.iterdir()) and not (target / MARKER_NAME).is_file():
        raise UiError(f"{target} is not empty and was not written by `tainttrail ui --export-dir`; "
                      "choose a new or empty directory")
    files = viewer_files(viewer_dir)
    if "index.html" not in files:
        raise UiError(f"the viewer files are missing from {viewer_dir}; reinstall tainttrail")
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()

    def place(rel: str) -> Path:
        """Where a file of the copy goes. An earlier copy may hold links by now; nothing is written through one."""
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.parent.resolve().is_relative_to(root):
            raise UiError(f"{dest.parent} leads outside {target}; remove it or choose another directory")
        if dest.is_symlink():
            dest.unlink()
        return dest

    for rel in files:
        shutil.copyfile(Path(viewer_dir) / rel, place(rel))
    place(GRAPH_NAME).write_text(graph_json, encoding="utf-8")
    place(MARKER_NAME).write_text(
        f"Static copy of the TaintTrail viewer {__version__}, written by `tainttrail ui --export-dir`.\n"
        "Serve this directory over http or https; it does not work from file://.\n"
        "The server must send a JavaScript MIME type for .js files and should send\n"
        "application/wasm for .wasm files. Nothing here contacts another host.\n",
        encoding="utf-8",
    )
    # GitHub Pages runs Jekyll unless this file exists; Jekyll is not needed here.
    place(".nojekyll").write_text("", encoding="utf-8")
    return sorted([*files, GRAPH_NAME, MARKER_NAME])


# -- the graph to show ---------------------------------------------------------------------


def _printable(text: object, limit: int = 200) -> str:
    """Text that is safe to print: a session id or a file name comes from outside, and a
    control character in one could repaint the terminal it is printed to."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))[:limit]


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _export_file_text(path: Path) -> str:
    """The text of an export file (``tainttrail export``, or an archived session), checked.

    The checks are the ones the viewer makes, made here so that a wrong file is reported at
    the terminal instead of on a start screen in the browser.
    """
    name = _printable(path)
    try:
        if path.stat().st_size > MAX_EXPORT_FILE_BYTES:
            raise UiError(f"{name} is larger than {MAX_EXPORT_FILE_BYTES // (1024 * 1024)} MB, more than the viewer "
                          "loads. Export one session instead: tainttrail export --session last")
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UiError(f"{name} is not a TaintTrail export: it is not UTF-8 text") from exc
    except OSError as exc:
        raise UiError(f"cannot read {name}: {exc.strerror or exc}") from exc
    try:
        # NaN and Infinity are refused: Python reads them, a browser does not.
        doc = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise UiError(f"{name} is not a TaintTrail export: it is not valid JSON") from exc
    meta = doc.get("meta") if isinstance(doc, dict) else None
    found = meta.get("format") if isinstance(meta, dict) else None
    if found != EXPORT_FORMAT:
        seen = f", found {_printable(found, 60)!r}" if isinstance(found, str) else ""
        raise UiError(f"{name} is not a TaintTrail export: expected the format {EXPORT_FORMAT!r}{seen}. "
                      "Create one with: tainttrail export --out graph.json")
    if not isinstance(doc.get("nodes"), list) or not isinstance(doc.get("rels"), list):
        raise UiError(f'{name} is not a complete export: it has no "nodes" and "rels" lists')
    return text


def _finite(value: Any) -> Any:
    """The value with NaN and the infinities written as text, as the viewer stores them."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, list):
        return [_finite(v) for v in value]
    if isinstance(value, dict):
        return {k: _finite(v) for k, v in value.items()}
    return value


def _store_text(path: Path, *, session: str | None, project: str, root: Path | None, timeout_ms: int,
                missing: str) -> str:
    """Export a Relate store, or one session of it, as JSON text."""
    import relate  # imported late: the sample and an export file need no engine

    from . import report
    from .export import export_graph
    from .store import Store, StoreError, StoreMissing

    try:
        # Open, export, close: a store admits one opener, and the server then runs for minutes.
        with Store(path, read_only=True, timeout_ms=timeout_ms) as store:
            session_id = None
            if session:
                session_id = report.resolve_session(store, session)
                if session_id is None:
                    ids = [str(row["id"]) for row in report.sessions(store)]
                    matching = [i for i in ids if i.startswith(session)]
                    if len(matching) > 1:
                        raise UiError(f"{session!r} is the start of {len(matching)} session ids "
                                      f"({', '.join(_printable(i, 60) for i in matching[:5])}); give more of the id")
                    known = ", ".join(_printable(i, 60) for i in ids[:5]) or "none recorded"
                    raise UiError(f"no session matches {session!r} (sessions: {known})")
            # The project directory is written as /project and the home directory as ~, as
            # `tainttrail export` writes them: a static copy is made to be put somewhere else.
            export = export_graph(store, session_id=session_id, project=project, root=root)
    except StoreMissing as exc:
        raise UiError(missing) from exc
    except LookupError as exc:
        if type(exc) is not LookupError:  # a KeyError or IndexError is a bug, not a missing session
            raise
        raise UiError(str(exc)) from exc
    except (StoreError, relate.Error, OSError) as exc:
        raise UiError(f"could not read the graph at {_printable(path)}: {exc}") from exc
    try:
        return json.dumps(export, sort_keys=True, allow_nan=False)
    except ValueError:  # a NaN or an infinity in the store: valid for Python, not for a browser
        return json.dumps(_finite(export), sort_keys=True, allow_nan=False)


def _is_store(path: str | os.PathLike[str]) -> bool:
    """Whether ``--file`` names a Relate store (a ``.rl`` file, or a directory store) rather than an export."""
    return Path(path).suffix.lower() == ".rl" or Path(path).is_dir()


def graph_text(cfg: Config, *, session: str | None = None, sample: bool = False,
               file: str | os.PathLike[str] | None = None) -> str:
    """The JSON text of what the viewer shows.

    The project's graph or one session of it, the bundled sample, or ``file``: an export
    (JSON, as ``tainttrail export`` and the session archive write it) or a Relate store
    (``.rl``).
    """
    if sample:
        try:
            return SAMPLE_GRAPH.read_text(encoding="utf-8")
        except OSError as exc:
            raise UiError(f"the bundled sample graph is missing ({exc}); reinstall tainttrail") from exc
    if file is not None:
        path = Path(file)
        if not _is_store(path):
            return _export_file_text(path)
        # An evidence file from `tainttrail export --format rl`: its paths were rewritten when it was made.
        return _store_text(path, session=session, project=path.stem, root=None, timeout_ms=cfg.lock_timeout_ms,
                           missing=f"cannot read {_printable(path)}: there is no such file")
    return _store_text(
        cfg.db_path, session=session, project=cfg.root.name, root=cfg.root, timeout_ms=cfg.lock_timeout_ms,
        missing=(f"nothing has been recorded for this project yet (no graph at {cfg.db_path}). "
                 "Run an agent session with the guard installed, or run "
                 "`tainttrail ui --sample` to see the bundled sample."))


# -- command ---------------------------------------------------------------------------------


def _port(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port number: {text!r}") from None
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError("a port is a number from 0 to 65535 (0 picks a free one)")
    return value


def add_ui_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session", metavar="ID",
                        help="show one session (an id, a unique prefix of one, or 'last'); "
                             "default is the whole graph")
    parser.add_argument("--file", metavar="PATH",
                        help="show this file instead of the project's graph: an export written by "
                             "`tainttrail export`, an archived session from .tainttrail/archive/, "
                             "or a Relate store (.rl)")
    parser.add_argument("--sample", action="store_true",
                        help="show the bundled sample graph instead of this project's "
                             "(synthetic data; useful before anything has been recorded)")
    parser.add_argument("--port", type=_port, default=0, metavar="N",
                        help="port on 127.0.0.1 (default: a free port chosen by the system)")
    parser.add_argument("--no-open", action="store_true", help="print the URL but do not open a browser")
    parser.add_argument("--export-dir", metavar="DIR",
                        help="instead of serving, write a self-contained copy of the viewer with the "
                             "graph into DIR (for any static host) and exit")
    parser.add_argument("--verbose", action="store_true", help="log every request to stderr")


def cmd_ui(args: argparse.Namespace, cfg: Config, *,
           on_ready: Callable[[ThreadingHTTPServer, str], None] | None = None) -> int:
    """Serve the viewer for this project until interrupted, or write a static copy of it.

    ``on_ready`` is called with the server and its URL just before the serving loop starts;
    tests use it to learn the port and to stop the loop.
    """
    sample = bool(getattr(args, "sample", False))
    session = getattr(args, "session", None)
    file = getattr(args, "file", None)
    if sample and (session or file):
        print(f"tainttrail ui: --sample and {'--file' if file else '--session'} cannot be combined", file=sys.stderr)
        return 2
    if file and session and not _is_store(file):
        print("tainttrail ui: --session and --file cannot be combined for an export file: it is shown whole",
              file=sys.stderr)
        return 2
    try:
        text = graph_text(cfg, session=session, sample=sample, file=file or None)
    except UiError as exc:
        print(f"tainttrail ui: {exc}", file=sys.stderr)
        return 1

    export_dir = getattr(args, "export_dir", None)
    if export_dir:
        try:
            written = write_static_copy(text, Path(export_dir))
        except UiError as exc:
            print(f"tainttrail ui: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"tainttrail ui: could not write the static copy: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {len(written)} files to {export_dir}")
        if not sample:
            print(f"{GRAPH_NAME} in it is the recorded graph: commands, file names and excerpts of what the agent "
                  "read. Put the copy only where those may be seen.")
        print("Serve that directory with any static web server, for example:")
        print(f"  python -m http.server --bind {LOOPBACK} --directory {shlex.quote(str(export_dir))}")
        return 0

    if sample:
        what = "the bundled sample graph (synthetic data)"
    elif session:  # name the session that was found, not the word that found it ("last")
        what = f"session {_printable(json.loads(text)['meta'].get('session') or session)}"
    elif file:
        what = _printable(file)
    else:
        what = f"the graph of {_printable(cfg.root.name) or 'this project'}"
    with tempfile.TemporaryDirectory(prefix="tainttrail-ui-") as tmp:
        graph_file = Path(tmp) / GRAPH_NAME
        try:
            graph_file.write_text(text, encoding="utf-8")
            server = make_server(graph_file, port=int(getattr(args, "port", 0) or 0),
                                 verbose=bool(getattr(args, "verbose", False)))
        except OSError as exc:
            print(f"tainttrail ui: could not listen on {LOOPBACK}:{getattr(args, 'port', 0)}: {exc}",
                  file=sys.stderr)
            return 1
        url = server_url(server)
        previous = _interrupt_on_signals()
        try:
            print(f"TaintTrail viewer: {url}", flush=True)
            print(f"Showing {what}. Served on this machine only; press Ctrl+C to stop.", flush=True)
            if not getattr(args, "no_open", False):
                _open_browser(url)
            if on_ready is not None:
                on_ready(server, url)
            server.serve_forever()
        except KeyboardInterrupt:
            try:
                print()
            except OSError:
                pass  # the terminal went away (SIGHUP); the clean-up below still runs
        finally:
            server.server_close()
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return 0


def _interrupt_on_signals() -> dict[int, Any]:
    """Treat ``kill`` and a closed terminal like Ctrl+C, so the temporary export is removed.

    Returns the handlers to restore. Empty where handlers cannot be set (a thread other than
    the main one); a platform without one of the signals simply skips it.
    """

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    previous: dict[int, Any] = {}
    for name in ("SIGTERM", "SIGHUP"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            if signal.getsignal(signum) is signal.SIG_IGN:
                continue  # started under nohup or the like: someone asked for the signal to be ignored
            handler = signal.signal(signum, stop)
        except (ValueError, OSError):
            continue
        if handler is not None:  # None: a handler that was not installed from Python; leave ours in place
            previous[signum] = handler
    return previous


# Browsers that draw in the terminal. Python's ``webbrowser`` falls back to them on a machine
# without a display. They cannot run the viewer (it needs JavaScript and WebAssembly), and they
# would take over the terminal the server is printing to.
_TEXT_BROWSERS = frozenset({"www-browser", "links", "links2", "elinks", "lynx", "w3m"})


def _text_browser() -> str | None:
    """The name of the browser that would be started, when it is a text-mode one."""
    try:
        controller = webbrowser.get()
    except webbrowser.Error:
        return None
    words = str(getattr(controller, "name", "") or "").split()
    name = os.path.basename(words[0]) if words else ""
    return name if name in _TEXT_BROWSERS else None


def _open_browser(url: str) -> None:
    """Open the default browser without blocking and without failing the command."""

    def run() -> None:
        try:
            text_browser = _text_browser()
            if text_browser:
                print(f"Not starting {text_browser}: the viewer needs a graphical browser. "
                      "Open the URL above in one.", file=sys.stderr)
            elif not webbrowser.open(url):
                print("No browser could be opened; open the URL above yourself.", file=sys.stderr)
        except Exception:  # noqa: BLE001 - a missing or broken browser must not stop the server
            print("No browser could be opened; open the URL above yourself.", file=sys.stderr)

    threading.Thread(target=run, name="tainttrail-open-browser", daemon=True).start()


def main(argv: list[str] | None = None) -> int:
    """``python -m tainttrail.serve``: the same command, usable before the CLI exists."""
    from .config import load_config

    parser = argparse.ArgumentParser(prog="tainttrail ui", description="Open the TaintTrail viewer in a browser.")
    add_ui_arguments(parser)
    args = parser.parse_args(argv)
    return cmd_ui(args, load_config())


if __name__ == "__main__":
    sys.exit(main())
