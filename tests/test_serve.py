"""`tainttrail ui`: the static server, the static copy, the command and the bundled sample.

The server tests speak real HTTP to a real server on a free loopback port. Hostile request
targets are written to a raw socket, because a client library would tidy them up first.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import importlib.util
import inspect
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import pytest

from sim import attack_session
from tainttrail import serve
from tainttrail.config import Config
from tainttrail.export import FORMAT, export_graph, write_rl
from tainttrail.extract import find_secrets
from tainttrail.store import Store

VIEWER = serve.VIEWER_DIR
SECRET = "canary-outside-the-web-root-0001"


# -- helpers ---------------------------------------------------------------------------------


@contextlib.contextmanager
def running(graph_file: Path | None, viewer_dir: Path = VIEWER):
    server = serve.make_server(graph_file, viewer_dir=viewer_dir)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def fetch(server, path: str, *, method: str = "GET", host: str | None = "") -> tuple[int, dict[str, str], bytes]:
    """One request through http.client. ``host=None`` sends no Host header at all."""
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host is not None:
            conn.putheader("Host", host or f"127.0.0.1:{port}")
        conn.endheaders()
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


def raw(server, target: bytes, *, method: bytes = b"GET") -> tuple[int, bytes]:
    """Send a request line exactly as given and return (status, everything after the headers)."""
    port = server.server_address[1]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(method + b" " + target + b" HTTP/1.1\r\nHost: 127.0.0.1:" + str(port).encode() + b"\r\n\r\n")
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    assert match, f"not an HTTP response: {data[:80]!r}"
    return int(match.group(1)), body


@pytest.fixture()
def web(tmp_path) -> Path:
    """A small web root with one file of every served type, a secret beside it, and traps inside."""
    root = tmp_path / "web"
    (root / "sub" / "deep").mkdir(parents=True)
    files = {
        "index.html": "<!doctype html><title>t</title>", "app.js": "export {};", "mod.mjs": "export {};",
        "style.css": "body{}", "data.json": "{}", "engine.wasm": "\0asm", "pic.svg": "<svg/>", "notes.md": "# n",
        "LICENSE": "licence text", "sub/x.js": "export {};", "sub/deep/y.json": "[]",
        "tool.py": "print('not served')", "page.php": "<?php", "archive.tar.gz": "x", ".hidden.json": "{}",
        "sub/.env": "TOKEN=x", "UPPER.JS": "export {};",
    }
    for name, text in files.items():
        (root / name).write_text(text)
    (tmp_path / "secret.txt").write_text(SECRET)
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "key.json").write_text(json.dumps({"k": SECRET}))
    (root / "link.txt").symlink_to(tmp_path / "secret.txt")          # a link that leaves the root
    (root / "linkdir").symlink_to(tmp_path / "secrets", target_is_directory=True)
    (root / "inside.js").symlink_to(root / "app.js")                 # a link that stays inside
    return root


@pytest.fixture()
def graph_file(tmp_path) -> Path:
    path = tmp_path / "export" / "graph.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"meta": {"format": FORMAT}, "nodes": [], "rels": [], "marker": "from-the-export"}))
    return path


def _args(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    serve.add_ui_arguments(parser)
    return parser.parse_args(list(argv))


# -- MIME types and headers ---------------------------------------------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/", "text/html; charset=utf-8"),
    ("/index.html", "text/html; charset=utf-8"),
    ("/app.js", "text/javascript; charset=utf-8"),
    ("/mod.mjs", "text/javascript; charset=utf-8"),
    ("/style.css", "text/css; charset=utf-8"),
    ("/data.json", "application/json; charset=utf-8"),
    ("/engine.wasm", "application/wasm"),
    ("/pic.svg", "image/svg+xml"),
    ("/notes.md", "text/markdown; charset=utf-8"),
    ("/LICENSE", "text/plain; charset=utf-8"),
    ("/sub/x.js", "text/javascript; charset=utf-8"),
    ("/sub/deep/y.json", "application/json; charset=utf-8"),
    ("/UPPER.JS", "text/javascript; charset=utf-8"),
    ("/graph.json", "application/json; charset=utf-8"),
])
def test_files_are_served_with_pinned_mime_types(web, graph_file, path, expected):
    with running(graph_file, web) as server:
        status, headers, body = fetch(server, path)
    assert status == 200
    assert headers["content-type"] == expected
    assert int(headers["content-length"]) == len(body) > 0


def test_the_real_viewer_and_its_engine_are_served(graph_file):
    """Module scripts need a JavaScript type and the engine wants application/wasm."""
    wanted = {
        "/": "text/html", "/app.js": "text/javascript", "/worker.js": "text/javascript", "/db.js": "text/javascript",
        "/views/finding.js": "text/javascript", "/style.css": "text/css", "/theme.js": "text/javascript",
        "/relate/relate.js": "text/javascript", "/relate/trap.js": "text/javascript",
        "/relate/snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js": "text/javascript",
        "/relate/LICENSE": "text/plain", "/sample/graph.json": "application/json",
    }
    with running(graph_file) as server:
        for path, mime in wanted.items():
            status, headers, body = fetch(server, path)
            assert (status, headers["content-type"].split(";")[0]) == (200, mime), path
            assert body, path
        status, headers, body = fetch(server, "/relate/relate_bg.wasm")
    assert status == 200 and headers["content-type"] == "application/wasm"
    assert body[:4] == b"\0asm" and len(body) == (VIEWER / "relate" / "relate_bg.wasm").stat().st_size


def test_graph_json_is_the_export_and_wins_over_a_file_in_the_viewer(web, graph_file):
    (web / "graph.json").write_text('{"marker": "a stray file in the web root"}')
    with running(graph_file, web) as server:
        status, _, body = fetch(server, "/graph.json")
        assert status == 200 and body == graph_file.read_bytes()
        assert json.loads(body)["marker"] == "from-the-export"
        graph_file.unlink()                       # the export vanished: no fallback to the stray file
        assert fetch(server, "/graph.json")[0] == 404
    with running(None, web) as server:            # a plain static root serves its own graph.json
        assert json.loads(fetch(server, "/graph.json")[2])["marker"] == "a stray file in the web root"


@pytest.mark.parametrize("path,status", [("/index.html", 200), ("/graph.json", 200), ("/nope.js", 404), ("/../x", 404)])
def test_every_response_forbids_caching_sniffing_and_foreign_content(web, graph_file, path, status):
    with running(graph_file, web) as server:
        got, headers, _ = fetch(server, path)
    assert got == status
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self' 'wasm-unsafe-eval'" in csp
    assert "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp and "*" not in csp
    assert headers["referrer-policy"] == "no-referrer"


def test_head_sends_headers_without_a_body(web, graph_file):
    with running(graph_file, web) as server:
        status, headers, body = fetch(server, "/app.js", method="HEAD")
    assert status == 200 and body == b""
    assert headers["content-type"].startswith("text/javascript") and headers["content-length"] == str(len("export {};"))


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
def test_only_get_and_head_are_answered(web, graph_file, method):
    with running(graph_file, web) as server:
        status, headers, body = fetch(server, "/index.html", method=method)
    assert status in (405, 501)
    assert b"<!doctype" not in body and headers["x-content-type-options"] == "nosniff"


# -- path traversal -------------------------------------------------------------------------------

TRAVERSALS = [
    b"/../secret.txt", b"/..%2fsecret.txt", b"/..%2Fsecret.txt", b"/%2e%2e/secret.txt", b"/%2E%2E%2Fsecret.txt",
    b"/.%2e/secret.txt", b"/%2e./secret.txt", b"/sub/../../secret.txt", b"/sub/..%2f..%2fsecret.txt",
    b"/sub/deep/../../../secret.txt", b"/..\\secret.txt", b"/..%5csecret.txt", b"/sub%5c..%5c..%5csecret.txt",
    b"/%252e%252e/secret.txt", b"/%252e%252e%252fsecret.txt", b"//secret.txt", b"///etc/passwd", b"/etc/passwd",
    b"/%2fetc%2fpasswd", b"/....//secret.txt", b"/..;/secret.txt", b"/.../secret.txt", b"/graph.json/../../secret.txt",
    b"/index.html/../../secret.txt", b"/link.txt", b"/linkdir/key.json", b"/linkdir/../secret.txt",
    b"/%c0%ae%c0%ae/secret.txt", b"/%ff%fe/secret.txt", b"/secret.txt%00.json", b"/index.html%00",
    b"/C:/Windows/win.ini", b"/c%3a/secret.txt", b"http://127.0.0.1/../secret.txt", b"secret.txt", b"*",
    b"/~/secret.txt", b"/%7e/.ssh/id_rsa", b"/sub/%2e%2e/%2e%2e/secret.txt", b"/?/../secret.txt/..",
]


@pytest.mark.parametrize("target", TRAVERSALS, ids=[t.decode("latin-1") for t in TRAVERSALS])
def test_no_request_target_reaches_outside_the_web_root(web, graph_file, target):
    with running(graph_file, web) as server:
        status, body = raw(server, target)
    assert SECRET.encode() not in body
    if target == b"/?/../secret.txt/..":
        assert status == 200, "a query string is ignored, the path is still /"
    else:
        assert status in (400, 404), f"{target!r} answered {status}"


def test_a_secret_next_to_the_real_viewer_is_out_of_reach(graph_file):
    """serve.py itself sits one directory above the viewer: it must not be downloadable."""
    with running(graph_file) as server:
        for target in (b"/../serve.py", b"/..%2fserve.py", b"/%2e%2e/__init__.py", b"/sample/make_sample.py",
                       b"/sample/../../serve.py", b"/relate/../../store.py"):
            status, body = raw(server, target)
            assert status == 404 and b"import" not in body, target


@pytest.mark.parametrize("path", ["/tool.py", "/page.php", "/archive.tar.gz", "/.hidden.json", "/sub/.env", "/sub",
                                  "/sub/", "/sub/deep", "/index.html/", "/./index.html", "/sub/./x.js", "/missing.js",
                                  "/INDEX.HTML.bak", "/app.js.map", "/" + "a" * 300 + ".js", "/a/" * 20 + "x.js"])
def test_what_is_not_part_of_the_app_is_not_served(web, graph_file, path):
    with running(graph_file, web) as server:
        status, headers, body = fetch(server, path)
    assert status == 404
    assert headers["content-type"].startswith("text/plain") and body == b"Not found.\n", "no directory listing, no echo"


def test_a_link_is_followed_only_while_it_stays_inside(web, graph_file):
    with running(graph_file, web) as server:
        assert fetch(server, "/inside.js")[0] == 200
        assert fetch(server, "/link.txt")[0] == 404
        assert fetch(server, "/linkdir/key.json")[0] == 404


def test_a_very_long_request_line_does_not_crash_the_server(web, graph_file):
    with running(graph_file, web) as server:
        status, _ = raw(server, b"/" + b"a" * 100_000)
        assert status in (400, 404, 414)
        assert fetch(server, "/index.html")[0] == 200, "and it keeps serving"


@pytest.mark.parametrize("path,status", [
    ("/%69ndex.html", 200),          # an encoded letter is the same file
    ("/sub%2Fx.js", 200),            # an encoded separator is a separator, judged after decoding
    ("/sub%2f..%2fapp.js", 404), ("/%2569ndex.html", 404), ("/index.html%20", 404), ("/index.html.", 404),
    ("/index.html::$DATA", 404), ("/index.html;x=1", 404), ("/index.html%0d%0aSet-Cookie:x=1", 404),
    ("/app.js%3F", 404), ("/app.js%23", 404), ("/ app.js", 400), ("/a%20pp.js", 404), ("/sub/x.js/", 404),
    ("/sub//x.js", 404), ("/.", 404), ("/..", 404), ("/...", 404), ("/sub/..", 404), ("/-app.js", 404),
    ("/_app.js", 404), ("/app.js?/../../secret.txt", 200), ("/app.js#/../../secret.txt", 200),
    ("/CON", 404), ("/aux.js", 404), ("/graph.json.", 404), ("/Graph.json", 404), ("/graph.json/", 404),
])
def test_odd_spellings_of_a_path(web, graph_file, path, status):
    with running(graph_file, web) as server:
        got, body = raw(server, path.encode())
    assert got == status, path
    assert SECRET.encode() not in body and b"Set-Cookie" not in body


def test_head_of_an_error_has_headers_and_no_body(web, graph_file):
    with running(graph_file, web) as server:
        status, headers, body = fetch(server, "/missing.js", method="HEAD")
        assert (status, body) == (404, b"") and headers["content-length"] == str(len("Not found.\n"))
        status, headers, body = fetch(server, "/graph.json", method="HEAD", host="attacker.example")
        assert (status, body) == (403, b"") and int(headers["content-length"]) > 0


GARBAGE = [
    b"", b"\r\n", b"\r\n\r\n", b"GET\r\n\r\n", b"GET /\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"GET / FTP/1.0\r\n\r\n",
    b"GET / HTTP/1.1 extra\r\n\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 64,   # a TLS hello
    b"\x00\x01\x02\x03\xff\xfe\r\n\r\n", b"GET /\xff\xfe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + b"X: y\r\n" * 300 + b"\r\n",
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX: " + b"a" * 70_000 + b"\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nno colon here\r\n\r\n", b"GET / HTTP/1.1\r\n: empty name\r\n\r\n",
    b"get / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b"G\xc3\x89T / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 999999999\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"POST /graph.json HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nabcd",
    b"GET /graph.json HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nGET /graph.json HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
]


def test_garbage_on_the_socket_neither_stops_the_server_nor_prints_a_traceback(web, graph_file, capfd):
    with running(graph_file, web) as server:
        port = server.server_address[1]
        for payload in GARBAGE:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                data = b""
                while chunk := sock.recv(65536):
                    data += chunk
            assert b"Traceback" not in data and SECRET.encode() not in data, payload[:40]
            assert data == b"" or data.startswith(b"HTTP/1.") or b"<!doctype" in data, payload[:40]
        # A connection that is cut in the middle of a response, and one that never speaks.
        cut = socket.create_connection(("127.0.0.1", port), timeout=10)
        cut.sendall(b"GET /engine.wasm HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        cut.close()
        silent = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            assert fetch(server, "/index.html")[0] == 200, "a silent client does not hold the others up"
        finally:
            silent.close()
    err = capfd.readouterr().err
    assert "Traceback" not in err and "Exception" not in err, err[-600:]


@pytest.mark.parametrize("line", [b"GET /graph.json\r\n", b"GET /graph.json\r\n\r\n", b"GET /index.html\r\nHost: 127.0.0.1\r\n\r\n",
                                  b"GET //graph.json\n"])
def test_a_request_without_a_protocol_version_gets_nothing(web, graph_file, line):
    """HTTP/0.9: the answer would have no status line and no headers, so no policy and no type."""
    with running(graph_file, web) as server:
        with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=10) as sock:
            sock.sendall(line)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        assert data == b"", data[:80]
        assert fetch(server, "/graph.json")[0] == 200


def test_many_clients_at_once_get_the_right_files(graph_file):
    wanted = ["/", "/app.js", "/worker.js", "/style.css", "/graph.json", "/relate/relate.js", "/sample/graph.json",
              "/relate/relate_bg.wasm"]
    expected = {"/": (VIEWER / "index.html").read_bytes(), "/graph.json": graph_file.read_bytes(),
                **{p: (VIEWER / p.lstrip("/")).read_bytes() for p in wanted if p not in ("/", "/graph.json")}}
    results: list[tuple[str, int, bool]] = []
    with running(graph_file) as server:
        def get(path: str) -> None:
            status, _, body = fetch(server, path)
            results.append((path, status, body == expected[path]))
        threads = [threading.Thread(target=get, args=(wanted[i % len(wanted)],)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
    assert len(results) == 40 and all(status == 200 and same for _, status, same in results), \
        [r for r in results if r[1] != 200 or not r[2]]


def test_split_request_path_and_content_type():
    split = serve.split_request_path
    assert split("/") == ["index.html"]
    assert split("/app.js?v=1#top") == ["app.js"]
    assert split("/relate/snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js")[-1] == "opfs.js"
    assert split("/a%20b.js") is None, "a space is not part of any file name here"
    for bad in ("", "app.js", "/a//b.js", "/../a.js", "/a/./b.js", "/.git/config", "/a\\b.js", "/a\x00.js",
                "/%zz.js", "/%e4.js", "/-flag.js", "http://127.0.0.1/app.js"):
        assert split(bad) is None, bad
    assert serve.content_type("x.WASM") == "application/wasm" and serve.content_type("LICENSE") == "text/plain; charset=utf-8"
    for name in ("x.py", "x", ".json", "Makefile", "x.json.bak", "x.exe", "license"):
        assert serve.content_type(name) is None, name


# -- who may talk to the server -------------------------------------------------------------------


@pytest.mark.parametrize("host,status", [
    ("", 200), ("localhost:{port}", 200), ("LOCALHOST", 200), ("[::1]:{port}", 200), ("127.0.0.1", 200),
    ("attacker.example", 403), ("attacker.example:{port}", 403), ("127.0.0.1.attacker.example:{port}", 403),
    ("localhost.attacker.example", 403), ("127.0.0.1:{port}@attacker.example", 403), ("0.0.0.0:{port}", 403),
    ("[::1]evil:{port}", 403), ("localhost:80:80", 403),
])
def test_a_foreign_host_header_is_refused(web, graph_file, host, status):
    """DNS rebinding: a web page that resolves its own name to 127.0.0.1 still sends that name."""
    with running(graph_file, web) as server:
        got, _, body = fetch(server, "/graph.json", host=host.format(port=server.server_address[1]))
    assert got == status
    if status == 403:
        assert b"from-the-export" not in body


LOOK_ALIKE_HOSTS = [
    "127.0.0.1.", "localhost.", "127.1", "127.0.1", "2130706433", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1",
    "127.0.0.01", "127.0.0.2", "[::ffff:127.0.0.1]", "[0:0:0:0:0:0:0:1]", "[::1", "::1", "[::1]]", "localhost6",
    "ip6-localhost", "localhost.localdomain", "127.0.0.1:", "127.0.0.1:99999999", "127.0.0.1:80a",
    "127.0.0.1:-1", "127.0.0.1 :80", "127.0.0.1: 80", "127.0.0.1/", "127.0.0.1/x", "127.0.0.1?x", "127.0.0.1#x",
    "127.0.0.1#@attacker.example", "localhost@attacker.example", "attacker.example#localhost",
    "attacker.example/127.0.0.1", "127.0.0.1,attacker.example", "attacker.example,127.0.0.1",
    "127.0.0.1 attacker.example", "localhost\\.attacker.example", "127-0-0-1.attacker.example",
    "127.0.0.1.nip.io", "localtest.me", "LOCALHOST.attacker.example", "xn--localhost-.example", "localhos",
    "l\xf6calhost", "127\xb70.0.1", "http://127.0.0.1", "//127.0.0.1", "", " ", ".", ":", ":80", "*", "null",
]


@pytest.mark.parametrize("host", LOOK_ALIKE_HOSTS, ids=[repr(h) for h in LOOK_ALIKE_HOSTS])
def test_a_name_that_only_looks_like_loopback_is_refused(web, graph_file, host):
    """Exactly three names are this machine: 127.0.0.1, localhost and [::1], with an optional port."""
    with running(graph_file, web) as server:
        port = server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(b"GET /graph.json HTTP/1.1\r\nHost: " + host.encode("latin-1") + b"\r\n\r\n")
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
    assert data.startswith((b"HTTP/1.0 403", b"HTTP/1.0 400")), data[:60]
    assert b"from-the-export" not in data


@pytest.mark.parametrize("first,second", [("127.0.0.1:{port}", "attacker.example"), ("attacker.example", "127.0.0.1:{port}"),
                                          ("localhost", "localhost")])
def test_two_host_headers_are_refused(web, graph_file, first, second):
    """A browser sends one Host header. With two, which one was meant cannot be known."""
    with running(graph_file, web) as server:
        port = server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(f"GET /graph.json HTTP/1.1\r\nHost: {first.format(port=port)}\r\n"
                         f"Host: {second.format(port=port)}\r\n\r\n".encode())
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
    assert data.startswith((b"HTTP/1.0 400", b"HTTP/1.0 403")), data[:60]
    assert b"from-the-export" not in data and b"nosniff" in data


def test_a_request_without_a_host_header_is_not_a_browser_and_is_served(web, graph_file):
    with running(graph_file, web) as server:
        assert fetch(server, "/index.html", host=None)[0] == 200


def test_the_server_listens_on_loopback_only(web, graph_file):
    assert "host" not in inspect.signature(serve.make_server).parameters, "no way to ask for another address"
    assert "bind" not in inspect.signature(serve.make_server).parameters
    with running(graph_file, web) as server:
        assert server.server_address[0] == "127.0.0.1"
        assert serve.server_url(server) == f"http://127.0.0.1:{server.server_address[1]}/"
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))          # no packet is sent; this only picks the outgoing address
            address = probe.getsockname()[0]
        except OSError:
            address = "127.0.0.1"
        finally:
            probe.close()
        if not address.startswith("127."):
            with pytest.raises(OSError):
                socket.create_connection((address, server.server_address[1]), timeout=2).close()


# -- the static copy ------------------------------------------------------------------------------------

_SPECIFIER = re.compile(r"""(?:\bfrom\s+|\bimport\s+|\bimport\s*\(\s*|new\s+URL\(\s*)['"](\.{1,2}/[^'"]+)['"]""")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_static_copy_is_complete_and_self_contained(tmp_path):
    target = tmp_path / "site"
    written = serve.write_static_copy('{"meta": {"format": "tainttrail-export/1"}, "nodes": [], "rels": []}', target)
    on_disk = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    assert sorted([*written, ".nojekyll"]) == on_disk
    assert set(serve.viewer_files()) < set(written) and {"graph.json", serve.MARKER_NAME} < set(written)
    for rel in serve.viewer_files():
        assert (target / rel).read_bytes() == (VIEWER / rel).read_bytes(), rel
    for needed in ("index.html", "app.js", "worker.js", "style.css", "theme.js", "relate/relate.js",
                   "relate/relate_bg.wasm", "relate/trap.js", "relate/LICENSE", "relate/VENDORED.md",
                   "relate/snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js", "sample/graph.json"):
        assert needed in written, needed
    assert not [f for f in on_disk if f.endswith((".py", ".pyc")) or "__pycache__" in f]
    assert json.loads((target / "graph.json").read_text())["meta"]["format"] == FORMAT

    # Everything the page loads is in the copy: the tags of index.html and every relative import.
    html = (target / "index.html").read_text()
    for ref in re.findall(r"""(?:src|href)=["'](\./[^"'#]+)["']""", html):
        assert (target / ref).is_file(), ref
    for script in [p for p in target.rglob("*.js")]:
        for spec in _SPECIFIER.findall(script.read_text()):
            assert (script.parent / spec).resolve().is_file(), f"{script.relative_to(target)} imports {spec}"


def test_static_copy_refuses_to_scatter_files_over_other_work(tmp_path):
    busy = tmp_path / "project"
    busy.mkdir()
    (busy / "thesis.tex").write_text("years of work")
    with pytest.raises(serve.UiError, match="not empty"):
        serve.write_static_copy("{}", busy)
    assert sorted(p.name for p in busy.iterdir()) == ["thesis.tex"], "nothing was written"
    a_file = tmp_path / "file.txt"
    a_file.write_text("x")
    with pytest.raises(serve.UiError, match="not a directory"):
        serve.write_static_copy("{}", a_file)

    target = tmp_path / "new" / "nested" / "site"            # missing parents are created
    serve.write_static_copy('{"n": 1}', target)
    serve.write_static_copy('{"n": 2}', target)              # an earlier copy may be replaced
    assert json.loads((target / "graph.json").read_text()) == {"n": 2}
    empty = tmp_path / "empty"
    empty.mkdir()
    serve.write_static_copy("{}", empty)
    assert (empty / "index.html").is_file()


def test_static_copy_does_not_write_through_links_left_in_an_earlier_copy(tmp_path):
    """An earlier copy is replaced in place. If someone has put links into it since, the new
    files must not land where the links point."""
    target = tmp_path / "site"
    serve.write_static_copy('{"n": 1}', target)
    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch")
    for name in ("graph.json", "app.js", serve.MARKER_NAME, ".nojekyll"):
        (target / name).unlink()
        (target / name).symlink_to(victim)
    serve.write_static_copy('{"n": 2}', target)
    assert victim.read_text() == "do not touch"
    assert json.loads((target / "graph.json").read_text()) == {"n": 2}
    assert not any((target / name).is_symlink() for name in ("graph.json", "app.js", serve.MARKER_NAME, ".nojekyll"))
    assert (target / "app.js").read_bytes() == (VIEWER / "app.js").read_bytes()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    shutil.rmtree(target / "views")
    (target / "views").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(serve.UiError, match="leads outside"):
        serve.write_static_copy('{"n": 3}', target)
    assert list(elsewhere.iterdir()) == [], "nothing was written through the linked directory"


# -- the command ----------------------------------------------------------------------------------------


def test_arguments_and_their_defaults():
    args = _args()
    assert (args.session, args.sample, args.port, args.no_open, args.export_dir) == (None, False, 0, False, None)
    args = _args("--session", "last", "--port", "8123", "--no-open", "--export-dir", "out")
    assert (args.session, args.port, args.no_open, args.export_dir) == ("last", 8123, True, "out")
    for bad in ("70000", "-1", "http"):
        with pytest.raises(SystemExit):
            _args("--port", bad)
    assert not any(a.dest in ("host", "bind", "address") for a in _parser_actions()), "the address is not configurable"


def _parser_actions():
    parser = argparse.ArgumentParser()
    serve.add_ui_arguments(parser)
    return parser._actions  # noqa: SLF001 - reading argparse's own list is the only way to enumerate options


def test_export_dir_writes_the_project_graph(cfg: Config, tmp_path, capsys):
    with Store(cfg.db_path) as store:
        attack_session(store, cfg)
    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--export-dir", str(target)), cfg) == 0
    out = capsys.readouterr().out
    assert "wrote" in out and str(target) in out
    assert "recorded graph" in out and "only where those may be seen" in out, "a copy of real sessions comes with a word of care"
    export = json.loads((target / "graph.json").read_text())
    assert export["meta"]["format"] == FORMAT and export["meta"]["project"] == cfg.root.name
    assert export["meta"]["session"] is None, "the whole graph by default"
    rules = sorted(n["props"]["rule"] for n in export["nodes"] if "Finding" in n["labels"])
    assert rules == ["TT001", "TT009"]
    assert (target / "index.html").is_file() and (target / "relate" / "relate_bg.wasm").is_file()


def test_session_option_takes_an_id_a_prefix_or_last(cfg: Config, tmp_path, capsys):
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, session="alpha-1")
        attack_session(store, cfg, session="beta-2", ts=1_900_000_000_000)
    for i, (ref, expected) in enumerate([("last", "beta-2"), ("alpha-1", "alpha-1"), ("al", "alpha-1")]):
        target = tmp_path / f"site{i}"
        assert serve.cmd_ui(_args("--session", ref, "--export-dir", str(target)), cfg) == 0
        export = json.loads((target / "graph.json").read_text())
        assert export["meta"]["session"] == expected
        assert {n["id"] for n in export["nodes"] if "Session" in n["labels"]} == {expected}
    capsys.readouterr()
    assert serve.cmd_ui(_args("--session", "nope", "--export-dir", str(tmp_path / "x")), cfg) == 1
    err = capsys.readouterr().err
    assert "no session matches 'nope'" in err and "alpha-1" in err
    assert not (tmp_path / "x").exists(), "nothing is written when the session does not exist"


def test_without_a_graph_the_command_says_what_to_do(cfg: Config, tmp_path, capsys):
    assert serve.cmd_ui(_args("--export-dir", str(tmp_path / "site")), cfg) == 1
    err = capsys.readouterr().err
    assert "nothing has been recorded" in err and "--sample" in err
    assert not cfg.db_path.exists(), "looking for a graph must not create one"
    assert serve.cmd_ui(_args("--sample", "--session", "last"), cfg) == 2
    assert "cannot be combined" in capsys.readouterr().err


def test_a_store_that_cannot_be_read_is_reported_not_raised(cfg: Config, tmp_path, capsys):
    cfg.db_path.parent.mkdir(parents=True)
    cfg.db_path.write_bytes(b"this is not a Relate store" * 64)
    assert serve.cmd_ui(_args("--export-dir", str(tmp_path / "site")), cfg) == 1
    err = capsys.readouterr().err
    assert "could not read the graph" in err and "Traceback" not in err
    assert not (tmp_path / "site").exists()


def test_sample_option_uses_the_bundled_graph(cfg: Config, tmp_path):
    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--sample", "--export-dir", str(target)), cfg) == 0
    assert json.loads((target / "graph.json").read_text()) == json.loads(serve.SAMPLE_GRAPH.read_text())
    assert not cfg.db_path.exists(), "the sample needs no store"


def _serve_in_thread(args, cfg):
    """Run cmd_ui in a thread; returns (thread, result box, server, url) once it is listening."""
    box: dict = {}
    listening = threading.Event()

    def on_ready(server, url):
        box.update(server=server, url=url)
        listening.set()

    thread = threading.Thread(target=lambda: box.update(code=serve.cmd_ui(args, cfg, on_ready=on_ready)), daemon=True)
    thread.start()
    assert listening.wait(15), "the server did not start"
    return thread, box


def test_ui_serves_the_project_graph_and_cleans_up(cfg: Config, capsys, monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(serve.webbrowser, "open", lambda url: opened.append(url) or True)
    with Store(cfg.db_path) as store:
        attack_session(store, cfg)
    thread, box = _serve_in_thread(_args("--no-open"), cfg)
    server, url = box["server"], box["url"]
    try:
        assert re.fullmatch(r"http://127\.0\.0\.1:\d+/", url) and server.server_address[0] == "127.0.0.1"
        status, headers, body = fetch(server, "/graph.json")
        export = json.loads(body)
        assert status == 200 and headers["content-type"].startswith("application/json")
        assert export["meta"]["format"] == FORMAT and export["meta"]["counts"]["nodes"] == len(export["nodes"])
        assert any(n["props"].get("rule") == "TT001" for n in export["nodes"])
        assert fetch(server, "/")[0] == 200 and fetch(server, "/relate/relate.js")[0] == 200
        # The store was closed before serving began: the guard can still write while the viewer is up.
        with Store(cfg.db_path, timeout_ms=1000) as store:
            store.write("CREATE (:Session {id: 'written-while-serving'})")
        temp_graph = server.RequestHandlerClass.graph_file
        assert temp_graph.is_file() and cfg.root not in temp_graph.parents
    finally:
        server.shutdown()
        thread.join(10)
    assert box["code"] == 0
    assert not temp_graph.exists() and not temp_graph.parent.exists(), "the temporary export is removed"
    out = capsys.readouterr().out
    assert url in out and "this machine only" in out and f"the graph of {cfg.root.name}" in out
    assert opened == [], "--no-open means no browser"


def test_ui_opens_the_browser_unless_told_not_to(cfg: Config, monkeypatch, capsys):
    opened = threading.Event()
    urls: list[str] = []
    monkeypatch.setattr(serve.webbrowser, "open", lambda url: (urls.append(url), opened.set(), True)[2])
    thread, box = _serve_in_thread(_args("--sample"), cfg)
    try:
        assert opened.wait(10), "the browser was not opened"
        assert urls == [box["url"]]
    finally:
        box["server"].shutdown()
        thread.join(10)
    assert box["code"] == 0 and "sample" in capsys.readouterr().out


def test_ui_names_the_session_it_found(cfg: Config, capsys):
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, session="alpha-1")
    thread, box = _serve_in_thread(_args("--session", "last", "--no-open"), cfg)
    try:
        assert json.loads(fetch(box["server"], "/graph.json")[2])["meta"]["session"] == "alpha-1"
    finally:
        box["server"].shutdown()
        thread.join(10)
    assert "Showing session alpha-1." in capsys.readouterr().out


def test_ui_reports_a_port_that_is_taken(cfg: Config, capsys):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        port = taken.getsockname()[1]
        assert serve.cmd_ui(_args("--sample", "--no-open", "--port", str(port)), cfg) == 1
    assert f"127.0.0.1:{port}" in capsys.readouterr().err


def test_ui_honours_a_given_port(cfg: Config):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    thread, box = _serve_in_thread(_args("--sample", "--no-open", "--port", str(port)), cfg)
    try:
        assert box["url"] == f"http://127.0.0.1:{port}/"
    finally:
        box["server"].shutdown()
        thread.join(10)


# -- showing a file: an export, an archived session, an evidence store -------------------------


def _strict_json(text: str) -> dict:
    """Parse the way a browser does: NaN and Infinity are not JSON."""
    def refuse(name):
        raise ValueError(f"{name} is not JSON")
    return json.loads(text, parse_constant=refuse)


def test_file_option_shows_an_export_file_as_it_is(cfg: Config, tmp_path, capsys):
    """`tainttrail status` and the config comments point people at `tainttrail ui --file <archive>`."""
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, session="old-session")
        archived = export_graph(store, session_id="old-session", keep_paths=True, project=cfg.root.name, root=cfg.root)
    archived["meta"]["archived"] = True
    archive = cfg.home / "archive" / "20261114T091200Z-old-session.json"
    archive.parent.mkdir(parents=True)
    archive.write_text(json.dumps(archived, separators=(",", ":")), encoding="utf-8")
    cfg.db_path.unlink()                      # the live graph is not needed to open an archive

    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--file", str(archive), "--export-dir", str(target)), cfg) == 0
    assert json.loads((target / "graph.json").read_text()) == archived
    assert not cfg.db_path.exists(), "showing a file opens no store"

    thread, box = _serve_in_thread(_args("--file", str(archive), "--no-open"), cfg)
    try:
        status, headers, body = fetch(box["server"], "/graph.json")
        assert status == 200 and headers["content-type"].startswith("application/json")
        assert json.loads(body) == archived
    finally:
        box["server"].shutdown()
        thread.join(10)
    assert box["code"] == 0 and f"Showing {archive}." in capsys.readouterr().out


def test_file_option_opens_what_retention_archives(cfg: Config, tmp_path):
    """The real thing: sessions moved out of the live graph by tainttrail.retention, opened one by one."""
    retention = pytest.importorskip("tainttrail.retention")
    with Store(cfg.db_path) as store:
        for i in range(5):
            attack_session(store, cfg, session=f"session-{i}", ts=1_800_000_000_000 + i * 3_600_000)
        with store.transaction():
            archived = retention.prune(store, cfg, budget=1)
        left = {row["id"] for row in store.run("MATCH (s:Session) RETURN s.id AS id")}
    assert archived, "nothing was archived: the budget of one node should have moved the oldest sessions out"
    files = retention.archived(cfg)
    assert len(files) == len(archived) and all(f.suffix == ".json" for f in files)
    for i, record in enumerate(archived):
        assert record["id"] not in left
        target = tmp_path / f"site{i}"
        assert serve.cmd_ui(_args("--file", record["file"], "--export-dir", str(target)), cfg) == 0
        export = json.loads((target / "graph.json").read_text())
        assert export["meta"]["format"] == FORMAT and export["meta"]["session"] == record["id"]
        assert {n["id"] for n in export["nodes"] if "Session" in n["labels"]} == {record["id"]}
        assert any(n["props"].get("rule") == "TT001" for n in export["nodes"]), "the finding went into the archive with its session"
        ids = {n["id"] for n in export["nodes"]}
        assert all(r["start"] in ids and r["end"] in ids for r in export["rels"])


def test_file_option_accepts_what_the_viewer_accepts_and_says_why_not(cfg: Config, tmp_path, capsys, monkeypatch):
    good = {"meta": {"format": FORMAT}, "nodes": [], "rels": []}
    cases = {
        "missing.json": (None, "cannot read"),
        "not-json.json": ("{\"meta\": ", "not valid JSON"),
        "empty.json": ("", "not valid JSON"),
        "binary.json": (b"\xff\xfe\x00\x01" * 8, "not UTF-8"),
        "nan.json": ('{"meta": {"format": "%s"}, "nodes": [{"x": NaN}], "rels": []}' % FORMAT, "not valid JSON"),
        "infinity.json": ('{"meta": {"format": "%s"}, "nodes": [], "rels": [], "x": -Infinity}' % FORMAT, "not valid JSON"),
        "deep.json": ("[" * 200_000, "not valid JSON"),
        "list.json": ("[1, 2]", "not a TaintTrail export"),
        "null.json": ("null", "not a TaintTrail export"),
        "string.json": ('"tainttrail-export/1"', "not a TaintTrail export"),
        "other.json": ('{"hello": "world"}', "not a TaintTrail export"),
        "meta-list.json": ('{"meta": [], "nodes": [], "rels": []}', "not a TaintTrail export"),
        "format-2.json": ('{"meta": {"format": "tainttrail-export/2"}, "nodes": [], "rels": []}', "found 'tainttrail-export/2'"),
        "format-case.json": ('{"meta": {"format": "TaintTrail-Export/1"}, "nodes": [], "rels": []}', "not a TaintTrail export"),
        "format-escape.json": (json.dumps({"meta": {"format": "\x1b[2Jx"}, "nodes": [], "rels": []}), "not a TaintTrail export"),
        "no-rels.json": ('{"meta": {"format": "%s"}, "nodes": []}' % FORMAT, 'no "nodes" and "rels" lists'),
        "nodes-map.json": ('{"meta": {"format": "%s"}, "nodes": {}, "rels": []}' % FORMAT, 'no "nodes" and "rels" lists'),
    }
    for name, (content, words) in cases.items():
        path = tmp_path / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        elif content is not None:
            path.write_text(content, encoding="utf-8")
        assert serve.cmd_ui(_args("--file", str(path), "--export-dir", str(tmp_path / "site")), cfg) == 1, name
        err = capsys.readouterr().err
        assert words in err and "Traceback" not in err and "\x1b" not in err, (name, err)
        assert not (tmp_path / "site").exists(), name

    with_bom = tmp_path / "bom.json"
    with_bom.write_bytes(b"\xef\xbb\xbf" + json.dumps(good).encode())
    assert serve.cmd_ui(_args("--file", str(with_bom), "--export-dir", str(tmp_path / "bom-site")), cfg) == 0
    assert _strict_json((tmp_path / "bom-site" / "graph.json").read_text()) == good, "a byte order mark is not part of the JSON"

    monkeypatch.setattr(serve, "MAX_EXPORT_FILE_BYTES", 64)
    big = tmp_path / "big.json"
    big.write_text(json.dumps({**good, "padding": "x" * 200}))
    assert serve.cmd_ui(_args("--file", str(big), "--export-dir", str(tmp_path / "big-site")), cfg) == 1
    assert "larger than" in capsys.readouterr().err


def test_file_option_opens_an_evidence_store(cfg: Config, tmp_path, capsys, sample):
    """`tainttrail export --format rl` writes one session as a store; the viewer can show that file."""
    evidence = tmp_path / "incident.rl"
    write_rl(sample, evidence)
    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--file", str(evidence), "--export-dir", str(target)), cfg) == 0
    export = json.loads((target / "graph.json").read_text())
    assert export["meta"]["format"] == FORMAT and export["meta"]["project"] == "incident"
    assert {n["id"] for n in export["nodes"]} == {n["id"] for n in sample["nodes"]}
    assert len(export["rels"]) == len(sample["rels"])
    assert not cfg.db_path.exists(), "the project's own store is not touched"

    one = tmp_path / "one"
    first = sample["meta"]["sessions"][0]["id"]
    assert serve.cmd_ui(_args("--file", str(evidence), "--session", first[:8], "--export-dir", str(one)), cfg) == 0
    assert json.loads((one / "graph.json").read_text())["meta"]["session"] == first

    capsys.readouterr()
    assert serve.cmd_ui(_args("--file", str(tmp_path / "nope.rl"), "--export-dir", str(tmp_path / "x")), cfg) == 1
    assert "there is no such file" in capsys.readouterr().err
    broken = tmp_path / "broken.rl"
    broken.write_bytes(b"not a store" * 100)
    assert serve.cmd_ui(_args("--file", str(broken), "--export-dir", str(tmp_path / "x")), cfg) == 1
    err = capsys.readouterr().err
    assert "could not read the graph" in err and "Traceback" not in err and not (tmp_path / "x").exists()


def test_options_that_name_different_graphs_cannot_be_combined(cfg: Config, tmp_path, capsys):
    export = tmp_path / "g.json"
    export.write_text(json.dumps({"meta": {"format": FORMAT}, "nodes": [], "rels": []}))
    for argv in (["--sample", "--session", "last"], ["--sample", "--file", str(export)],
                 ["--file", str(export), "--session", "last"], ["--sample", "--file", str(export), "--session", "x"]):
        assert serve.cmd_ui(_args(*argv, "--export-dir", str(tmp_path / "site")), cfg) == 2, argv
        assert "cannot be combined" in capsys.readouterr().err
    assert not (tmp_path / "site").exists()


def test_the_export_hides_where_the_project_lives(cfg: Config, tmp_path, monkeypatch):
    """A static copy is made to be put somewhere else. Same rule as `tainttrail export`:
    the project directory is /project, the home directory is ~."""
    monkeypatch.setenv("HOME", str(tmp_path / "home" / "alice"))
    with Store(cfg.db_path) as store:
        attack_session(store, cfg)
        store.write("MATCH (s:Session) SET s.note = $note", {"note": f"{tmp_path}/home/alice/notes.txt"})
    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--export-dir", str(target)), cfg) == 0
    text = (target / "graph.json").read_text()
    export = json.loads(text)
    assert str(cfg.root) not in text and "alice" not in text
    session = next(n["props"] for n in export["nodes"] if "Session" in n["labels"])
    assert session["cwd"] == "/project" and session["note"] == "~/notes.txt"
    env = next(n for n in export["nodes"] if n["id"].endswith("/.env"))
    assert env["id"] == "file:/project/.env" and env["props"]["value"] == "/project/.env"
    assert {r["start"] for r in export["rels"]} | {r["end"] for r in export["rels"]} <= {n["id"] for n in export["nodes"]}

    thread, box = _serve_in_thread(_args("--no-open"), cfg)       # and the served graph is the same document
    try:
        served = json.loads(fetch(box["server"], "/graph.json")[2])
    finally:
        box["server"].shutdown()
        thread.join(10)
    assert served["nodes"] == export["nodes"] and served["rels"] == export["rels"]


def test_numbers_a_browser_cannot_read_are_written_as_text(cfg: Config, tmp_path):
    """Python writes NaN and Infinity into JSON; JSON.parse refuses the whole file for one of them."""
    with Store(cfg.db_path) as store:
        attack_session(store, cfg)
        store.write("MATCH (s:Session) SET s.nan = sqrt(-1.0), s.up = toFloat(1) / 0, s.down = -toFloat(1) / 0, s.fine = 1.5")
    target = tmp_path / "site"
    assert serve.cmd_ui(_args("--export-dir", str(target)), cfg) == 0
    export = _strict_json((target / "graph.json").read_text())
    session = next(n["props"] for n in export["nodes"] if "Session" in n["labels"])
    assert (session["nan"], session["up"], session["down"], session["fine"]) == ("nan", "inf", "-inf", 1.5)


def test_a_session_prefix_that_fits_several_sessions_says_so(cfg: Config, tmp_path, capsys):
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, session="abc-1")
        attack_session(store, cfg, session="abc-2", ts=1_900_000_000_000)
    assert serve.cmd_ui(_args("--session", "abc", "--export-dir", str(tmp_path / "x")), cfg) == 1
    err = capsys.readouterr().err
    assert "'abc' is the start of 2 session ids" in err and "abc-1" in err and "abc-2" in err and "give more" in err
    assert serve.cmd_ui(_args("--session", "abc-2", "--export-dir", str(tmp_path / "x")), cfg) == 0


def test_text_from_the_graph_cannot_repaint_the_terminal(cfg: Config, tmp_path, capsys):
    """A session id comes from the harness and a file name from anywhere: no control characters on the terminal."""
    hostile = "s\x1b[2J\x1b]0;owned\x07\r\nid"
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, session=hostile)
    thread, box = _serve_in_thread(_args("--session", "last", "--no-open"), cfg)
    try:
        assert json.loads(fetch(box["server"], "/graph.json")[2])["meta"]["session"] == hostile, "the data is unchanged"
    finally:
        box["server"].shutdown()
        thread.join(10)
    out = capsys.readouterr().out
    assert "Showing session s?[2J?]0;owned???id." in out and "\x1b" not in out and "\x07" not in out

    assert serve.cmd_ui(_args("--session", "zzz", "--export-dir", str(tmp_path / "x")), cfg) == 1
    err = capsys.readouterr().err
    assert "no session matches 'zzz'" in err and "\x1b" not in err and "\x07" not in err
    odd = tmp_path / "ex\x1b[31mport.json"
    odd.write_text("{}")
    assert serve.cmd_ui(_args("--file", str(odd), "--export-dir", str(tmp_path / "x")), cfg) == 1
    assert "\x1b" not in capsys.readouterr().err


def test_the_suggested_command_survives_a_directory_name_with_spaces(cfg: Config, tmp_path, capsys):
    target = tmp_path / "my site (draft)"
    assert serve.cmd_ui(_args("--sample", "--export-dir", str(target)), cfg) == 0
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if "http.server" in l)
    assert shlex.split(line)[-2:] == ["--directory", str(target)]
    assert "recorded graph" not in out, "the sample is synthetic: nothing to be careful with"


@pytest.mark.parametrize("controller,opened", [
    (webbrowser.GenericBrowser("lynx"), False), (webbrowser.GenericBrowser("/usr/bin/w3m"), False),
    (webbrowser.GenericBrowser(["links", "-g", "%s"]), False), (webbrowser.GenericBrowser("www-browser"), False),
    (webbrowser.BackgroundBrowser("firefox"), True), (webbrowser.GenericBrowser("my-browser --new-window %s"), True),
])
def test_a_text_mode_browser_is_not_started(cfg: Config, monkeypatch, capfd, controller, opened):
    """Without a display Python falls back to lynx or w3m, which would take over the terminal
    and cannot run the viewer. The URL is printed instead."""
    done = threading.Event()
    urls: list[str] = []
    monkeypatch.setattr(serve.webbrowser, "get", lambda *a: controller)
    monkeypatch.setattr(serve.webbrowser, "open", lambda url: (urls.append(url), done.set(), True)[2])
    thread, box = _serve_in_thread(_args("--sample"), cfg)
    try:
        done.wait(3 if opened else 0.5)
    finally:
        box["server"].shutdown()
        thread.join(10)
    captured = capfd.readouterr()
    if opened:
        assert urls == [box["url"]] and "Not starting" not in captured.err
    else:
        assert urls == [] and "Not starting" in captured.err and "graphical browser" in captured.err
        assert box["url"] in captured.out, "the URL is still printed"


def _serve_as_a_process(tmp_path, signals: dict[str, object]):
    """Start `python -m tainttrail.serve --sample` with the given signal dispositions; returns (process, port).

    The dispositions are set in the child before Python starts: a test run that was itself
    started with SIGINT or SIGHUP ignored (a background job, nohup) would hand that on.
    """
    def dispositions() -> None:
        for name, how in signals.items():
            signal.signal(getattr(signal, name), how)

    env = {**os.environ, "TMPDIR": str(tmp_path / "tmp")}
    (tmp_path / "tmp").mkdir()
    proc = subprocess.Popen([sys.executable, "-m", "tainttrail.serve", "--sample", "--no-open"], cwd=tmp_path, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=dispositions)
    line = proc.stdout.readline()
    url = re.search(r"http://127\.0\.0\.1:(\d+)/", line)
    assert url, f"no URL on the first line: {line!r}"
    proc.stdout.readline()                             # "Showing ...": the server is about to serve
    assert [p.name for p in (tmp_path / "tmp").iterdir() if p.name.startswith("tainttrail-ui-")]
    return proc, int(url.group(1))


def _graph_is_served(port: int) -> bool:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", "/graph.json")
        return conn.getresponse().status == 200
    finally:
        conn.close()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="no SIGHUP on this platform")
@pytest.mark.parametrize("signame", ["SIGHUP", "SIGINT"])
def test_a_closed_terminal_or_ctrl_c_also_removes_the_export(tmp_path, signame):
    proc, port = _serve_as_a_process(tmp_path, {"SIGHUP": signal.SIG_DFL, "SIGINT": signal.SIG_DFL})
    try:
        assert _graph_is_served(port)
        proc.send_signal(getattr(signal, signame))
        assert proc.wait(15) == 0
        assert "Traceback" not in proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.stderr.close()
    assert list((tmp_path / "tmp").iterdir()) == [], "the temporary export directory was removed"


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="no SIGHUP on this platform")
def test_a_server_started_under_nohup_outlives_its_terminal(tmp_path):
    """Whoever starts the viewer with SIGHUP ignored wants it to stay up; SIGTERM still stops it cleanly."""
    proc, port = _serve_as_a_process(tmp_path, {"SIGHUP": signal.SIG_IGN})
    try:
        proc.send_signal(signal.SIGHUP)
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(1.5)
        assert _graph_is_served(port), "still serving after the hangup"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.stderr.close()
    assert list((tmp_path / "tmp").iterdir()) == []


def test_static_copy_cannot_be_written_into_the_installed_viewer(tmp_path):
    with pytest.raises(serve.UiError, match="inside the installed viewer"):
        serve.write_static_copy("{}", VIEWER / "out")
    assert not (VIEWER / "out").exists()
    web_root = tmp_path / "web"
    (web_root / "sub").mkdir(parents=True)
    (web_root / "index.html").write_text("<!doctype html>")
    with pytest.raises(serve.UiError, match="inside the installed viewer"):
        serve.write_static_copy("{}", web_root / "sub" / "copy", viewer_dir=web_root)


def test_a_killed_server_exits_cleanly_and_removes_its_export(tmp_path):
    """`kill` (SIGTERM) must behave like Ctrl+C: exit 0 and leave no temporary graph behind."""
    import os
    import signal

    env = {**os.environ, "TMPDIR": str(tmp_path / "tmp")}
    (tmp_path / "tmp").mkdir()
    proc = subprocess.Popen([sys.executable, "-m", "tainttrail.serve", "--sample", "--no-open"], cwd=tmp_path, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        url = re.search(r"http://127\.0\.0\.1:(\d+)/", line)
        assert url, f"no URL on the first line: {line!r}"
        conn = http.client.HTTPConnection("127.0.0.1", int(url.group(1)), timeout=10)
        conn.request("GET", "/graph.json")
        assert json.loads(conn.getresponse().read())["meta"]["format"] == FORMAT
        conn.close()
        assert [p.name for p in (tmp_path / "tmp").iterdir() if p.name.startswith("tainttrail-ui-")], "export is in TMPDIR"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
        proc.stderr.close()
    assert list((tmp_path / "tmp").iterdir()) == [], "the temporary export directory was removed"


def test_module_entry_point_runs_without_the_cli(tmp_path):
    target = tmp_path / "site"
    done = subprocess.run([sys.executable, "-m", "tainttrail.serve", "--sample", "--export-dir", str(target)],
                          cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert (target / "graph.json").is_file() and "wrote" in done.stdout


# -- the bundled sample ------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sample() -> dict:
    return json.loads(serve.SAMPLE_GRAPH.read_text(encoding="utf-8"))


def _make_sample_module():
    path = VIEWER / "sample" / "make_sample.py"
    spec = importlib.util.spec_from_file_location("tainttrail_make_sample", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_sample_is_what_the_generator_produces(sample, monkeypatch):
    """Regenerate with: .venv/bin/python src/tainttrail/viewer/sample/make_sample.py"""
    before = {name: __import__("os").environ.get(name) for name in ("HOME", "TAINTTRAIL_KEY")}
    built = _make_sample_module().build()
    after = {name: __import__("os").environ.get(name) for name in ("HOME", "TAINTTRAIL_KEY")}
    assert after == before, "building the sample must not leave its environment behind"
    for doc in (built, sample):
        doc["meta"] = {**doc["meta"], "version": "x"}     # the package version may move on
    assert built == sample, "sample/graph.json is stale: run make_sample.py again"


def test_the_sample_is_a_consistent_export_with_more_than_one_session(sample):
    meta = sample["meta"]
    assert meta["format"] == FORMAT and meta["project"] == "acme-api"
    assert len(meta["sessions"]) >= 2, "the overview needs more than one row"
    ids = [n["id"] for n in sample["nodes"]]
    assert len(ids) == len(set(ids)) == meta["counts"]["nodes"]
    assert len(sample["rels"]) == meta["counts"]["rels"]
    assert all(r["start"] in set(ids) and r["end"] in set(ids) for r in sample["rels"])
    verdicts = {(s["denied"] > 0, s["asked"] > 0) for s in meta["sessions"]}
    assert verdicts == {(True, False), (False, True), (False, False)}, "one denied, one asked, one clean session"
    labels = {n["labels"][0] for n in sample["nodes"]}
    assert {"Agent", "Server", "Tool", "Capability", "Credential", "Session", "ToolCall", "Content", "Entity",
            "Chunk", "Finding"} <= labels, "every part of the model is there to look at"


def test_the_sample_holds_no_secret_and_no_real_path(sample):
    text = serve.SAMPLE_GRAPH.read_text(encoding="utf-8")
    # The graph names the KIND of a secret it fingerprinted ("secret:aws_access_key_id"); the
    # detector reads that as an assignment. Anything that is not such a plain name is a leak.
    leaks = [hit for hit in find_secrets(text) if not re.fullmatch(r"[a-z_]+", hit.value)]
    assert leaks == [], "the sample must be free of anything that looks like a credential"
    assert "AKIA" not in text and "/tmp/" not in text and "/home/" not in text and "/Users/" not in text
    hosts = {n["props"]["value"] for n in sample["nodes"] if "Entity" in n["labels"] and n["props"]["kind"] == "host"}
    reserved = (".example", ".test", "pypi.org", "docs.pytest.org")
    assert all(h.endswith(reserved) for h in hosts), hosts
    assert all(c["props"].keys() <= {"id", "name", "kind"} for c in sample["nodes"] if "Credential" in c["labels"])


def test_the_sample_finding_runs_as_stored_on_a_real_store(sample, tmp_path):
    """What the viewer's Run button does in the browser, done here with the native engine."""
    finding = next(n["props"] for n in sample["nodes"] if "Finding" in n["labels"] and n["props"]["rule"] == "TT001")
    steps = json.loads(finding["path_json"])
    assert [s["role"] for s in steps] == ["untrusted", "destination", "call", "fingerprint", "sensitive"]
    assert [s["forward"] for s in steps[:-1]] == [True, False, True, False]
    target = tmp_path / "sample.rl"
    write_rl(sample, target)
    with Store(target, read_only=True) as store:
        row = store.one(finding["query"], json.loads(finding["params_json"]))
        assert [n["id"] for n in row["p"]["nodes"]] == [s["node_id"] for s in steps]
        assert [r["type"] for r in row["p"]["rels"]] == [s["rel"] for s in steps[:-1]]
        assert store.scalar("MATCH (n) WHERE NOT n:Meta RETURN count(n)") == len(sample["nodes"])


# -- the viewer's own files ----------------------------------------------------------------------------------

_OWN_SOURCES = sorted(p for p in VIEWER.rglob("*") if p.suffix in (".js", ".html", ".css") and "relate" not in p.parts)


def test_vendored_engine_is_unmodified_and_carries_its_licence():
    notice = (VIEWER / "relate" / "VENDORED.md").read_text(encoding="utf-8")
    table = dict(re.findall(r"\| `([^`]+)` \| [\d,]+ \| `([0-9a-f]{64})` \|", notice))
    assert set(table) == {"relate.js", "relate_bg.wasm", "trap.js", "LICENSE",
                          "snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js"}
    for name, digest in table.items():
        assert _sha256(VIEWER / "relate" / name) == digest, f"{name} differs from the vendored original"
    licence = (VIEWER / "relate" / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in licence and "Version 2.0" in licence and "The Relate Authors" in licence
    assert "Apache License 2.0" in notice and "@relate/relate-wasm@1.0.1" in notice


def test_the_viewer_makes_no_request_to_another_host():
    """Offline means offline: no CDN, no font, no analytics. The only URL is the SVG namespace."""
    allowed = {"http://www.w3.org/2000/svg"}
    for path in _OWN_SOURCES:
        urls = set(re.findall(r"""(?:https?:)?//[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s'"`)<]*""", path.read_text(encoding="utf-8")))
        assert urls <= allowed, f"{path.name}: {urls - allowed}"
        assert "@import" not in path.read_text(encoding="utf-8"), path.name


def test_the_viewer_never_parses_graph_text_as_markup():
    """The graph holds text an attacker wrote. The app builds DOM nodes and text nodes only."""
    banned = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function|"
                        r"srcdoc|setAttribute\(\s*['\"]on|javascript:")
    for path in (p for p in _OWN_SOURCES if p.suffix == ".js"):
        code = "\n".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("//"))
        assert not banned.search(code), f"{path.name}: {banned.search(code).group(0)}"


def test_the_page_has_no_inline_code_and_states_the_same_policy_as_the_server():
    html = (VIEWER / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "every script is an external file"
    assert not re.search(r"<style\b|\sstyle=|\son[a-z]+\s*=", html), "no inline style, no inline handler"
    meta = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    # frame-ancestors cannot be set from a <meta> element; everything else must match the header.
    assert meta == serve.CSP.replace("; frame-ancestors 'none'", "")
    refs = re.findall(r'(?:src|href)="([^"]+)"', html)
    assert {r for r in refs if not r.startswith(("#", "data:"))} == {"./theme.js", "./style.css", "./app.js"}
    assert [r[:19] for r in refs if r.startswith("data:")] == ["data:image/svg+xml,"], "the icon is inline, not a request"


# -- the console's read-only guard ----------------------------------------------------------------------------
#
# The viewer's guard is JavaScript (viewer/cypher.js). It touches no DOM, so Node can run it, and
# the native engine is the same engine the browser runs: together they answer "does anything the
# guard lets through change a graph?" without a browser. tests/viewer_check.mjs asks the same of
# the WebAssembly build.

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _guard(statements: list[str]) -> list[dict]:
    """What cypher.js says about each statement: {"refusal": text or None, "hidden": bool}."""
    script = (
        f"import {{ refusal, hiddenWrite }} from {json.dumps((VIEWER / 'cypher.js').as_uri())};\n"
        "let text = '';\n"
        "process.stdin.setEncoding('utf8');\n"
        "for await (const chunk of process.stdin) text += chunk;\n"
        "console.log(JSON.stringify(JSON.parse(text).map((s) => ({ refusal: refusal(s), hidden: hiddenWrite(s) }))));\n"
    )
    done = subprocess.run([NODE, "--input-type=module", "-e", script], input=json.dumps(statements),
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


WRITES = [
    "CREATE (n:Oops) RETURN n", "create (n:Oops)", "MERGE (n:Oops {id: 1})", "MATCH (n:Session) SET n.zzz = 1",
    "MATCH (n:Session) SET n:Extra", "MATCH (n:Session) REMOVE n.mode", "MATCH (n:Session) REMOVE n:Session",
    "MATCH (n:Chunk) DETACH DELETE n", "MATCH (n:Chunk) DELETE n", "MATCH (n:Chunk) DELETE(n)", "INSERT (n:Oops)",
    "FOREACH (x IN [1, 2] | CREATE (:Oops {v: x}))", "CREATE INDEX zzz IF NOT EXISTS FOR (n:Session) ON (n.cwd)",
    "DROP INDEX toolcall_session IF EXISTS", "CREATE CONSTRAINT zz IF NOT EXISTS FOR (n:Oops) REQUIRE n.id IS UNIQUE",
    "DROP CONSTRAINT session_id IF EXISTS", "MATCH (n:Chunk) DETACH DELETE n FINISH", "MATCH (n:Session) SET n.zzz = 1 FINISH",
    "CREATE (n:Oops) FINISH", "MATCH (n) FINISH", "match (n) finish;", "MATCH (n:Session) CALL (n) { SET n.zzz = 1 } RETURN n.zzz",
    "MATCH (n:Chunk) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 1 ROWS", "CALL { CREATE (:Oops) } RETURN 1 AS x",
    "OPTIONAL CALL () { CREATE (:Oops) }", "RETURN 1 AS x UNION CREATE (n:Oops) RETURN 2 AS x",
    "RETURN 1 AS x NEXT CREATE (n:Oops) RETURN 2 AS y", "WHEN true THEN { CREATE (n:Oops) RETURN 1 AS x } ELSE { RETURN 2 AS x }",
    "PROFILE CREATE (n:Oops)", "EXPLAIN CREATE (n:Oops)", "USE neo4j CREATE (n:Oops)",
    "LOAD CSV FROM 'file:///etc/passwd' AS row RETURN row", "load csv from 'https://attacker.example/x' as row return row",
    "MATCH (n:Session) WITH n AS SET SET SET.zzz = 1 RETURN 1 AS x", "MATCH (n:Session {id: 'x'})SET n.zzz = 1",
    "MATCH (n:Session)\u00a0SET n.zzz = 1", "MATCH (n:Session)\x0bSET n.zzz = 1", "MATCH (n:Session)\tSET\tn.zzz = 1",
    "MATCH (n:Session)\u2028SET n.zzz = 1", "MATCH (n:Chunk) DETACH/* */DELETE n", "MATCH (n:Chunk) DETACH\nDELETE\nn",
    "MATCH (n:Session) // SET in a comment\nSET n.zzz = 1", "MATCH (n:Session) // c\r\nSET n.zzz = 1",
    "/* a /* b */ CREATE (n:Oops) /* c */ RETURN 1 AS x", "RETURN 1 AS x /* unterminated CREATE (n:Oops)",
    # A string that ends in a backslash and a line break shifts what a careless tokenizer takes for text.
    "WITH 'x\\\n' AS a CREATE (n:Oops) RETURN 'done' AS d", "WITH 'x\\\r' AS a CREATE (n:Oops) RETURN 'done' AS d",
    "WITH 'x\\\u2028' AS a CREATE (n:Oops) RETURN 'done' AS d", "WITH 'x\\\u2029' AS a CREATE (n:Oops) RETURN 'done' AS d",
    'WITH "x\\\n" AS a MATCH (n:Chunk) DETACH DELETE n RETURN "done" AS d',
    "WITH 'x\\\n' AS a MATCH (n:Session) SET n.zzz = 1 FINISH //'", "WITH 'it\\'s' AS a CREATE (n:Oops) RETURN 'x' AS d",
    "WITH 'a\\\\' AS a CREATE (n:Oops) RETURN 'x' AS d", "WITH `a``b` AS x CREATE (n:Oops) RETURN `x` AS d",
    # A quoted name is still a name: after "AS `x`" comes a clause, not the alias.
    "WITH 'a' AS `x\n` CREATE (n:Oops) RETURN 1 AS d", "WITH 1 AS `x` CREATE (n:Oops) RETURN 1 AS d",
    "WITH 1 AS `x`CREATE (n:Oops)", "MATCH (n:Session) WHERE n.id = n.`id`SET n.zzz = 1", "MATCH (n:Session) WHERE n.id <> 'a'SET n.zzz = 1",
    "MATCH (`n`:Chunk) DETACH DELETE `n`", "UNWIND [1] AS `x` MERGE (:Oops {id: `x`})",
    # The engine takes AS as a name too. After "AS AS" comes a clause, and a statement can hide FINISH the same way.
    "UNWIND [1] AS AS CREATE (n:Oops)", "UNWIND [1] AS AS CREATE (n:Oops) WITH 1 AS AS FINISH",
    "MATCH (AS:Session) WITH AS SET AS.zzz = 1", "MATCH (as:Session) WITH as SET as.zzz = 1",
    "MATCH (n:Session) WITH n AS AS SET AS.zzz = 1", "CALL db.labels() YIELD label AS AS CREATE (:Oops)",
    "MATCH (AS:Chunk) WITH AS, 1 AS x WITH x, AS DETACH DELETE AS", "MATCH (FINISH:Chunk) DETACH DELETE FINISH FINISH",
    "CALL db.createLabel('Zed')", "CALL db.`createLabel`('Zed')", "CALL db . createLabel('Zed')", "CALL `db`.`createLabel`('Zed')",
    "CALL db.createProperty('zed')", "CALL db.createRelationshipType('ZED')", "CALL tx.setMetaData({a: 1})",
    "RETURN randomUUID() AS id", "RETURN randomUUID () AS id", "RETURN `randomUUID`() AS id", "RETURN RANDOMUUID() AS id",
]
READS = [
    "MATCH (n) RETURN count(n) AS n", "MATCH (s:Session) RETURN s.id AS id ORDER BY id LIMIT 3",
    "RETURN {set: 1, delete: 2, create: 3, merge: 4, remove: 5, load: 6, drop: 7}.set AS n",
    "MATCH (s:Session) RETURN count(s) AS load", "WITH [1, 2, 3] AS set RETURN size(set) AS n",
    "MATCH (s:Session) RETURN count(s) AS drop ORDER BY drop;", "WITH {a: 1} AS merge RETURN merge.a AS n",
    "WITH 'x' AS load, 2 AS drop RETURN 1 AS n", "MATCH (s:Session) WITH count(s) AS set RETURN [x IN [set] | x][0] AS n",
    "MATCH (n:Session) WHERE n.set IS NULL AND n.delete IS NULL RETURN count(n) AS n", "RETURN $set AS n, $create AS m",
    "MATCH (n:CREATE) RETURN count(n) AS n", "MATCH (n:Session)-[:SET|DELETE]->(m) RETURN count(m) AS n",
    "MATCH (dataset:Session) RETURN count(dataset) AS n", "MATCH (n) WHERE n.offset = 1 OR n.created_at > 0 RETURN n.reset, n.settings",
    "WITH [1, 2] AS `set` RETURN size(`set`) AS n", "MATCH (c:ToolCall) WHERE c.summary CONTAINS 'git merge' RETURN c",
    "MATCH (c:ToolCall) WHERE c.summary CONTAINS \"DROP TABLE\" RETURN c // and never DELETE\n",
    "CALL db.labels() YIELD label RETURN label", "CALL db.propertyKeys() YIELD propertyKey RETURN count(*) AS n",
    "SHOW PROCEDURES YIELD name RETURN count(name) AS n", "EXPLAIN MATCH (n) RETURN n", "PROFILE MATCH (n) RETURN count(n)",
    "MATCH p = SHORTEST 1 (a:Session)-[]-+(b:Finding) RETURN length(p) AS hops LIMIT 1",
    "RETURN 'CREATE (n) SET n.x = 1 DELETE n' AS text", "RETURN \"it's\" + 'a \"quote\"' AS s",
]
# Reads the guard may refuse, because telling them from a write takes a parser. The refusal says what to do.
READS_REFUSED_WITH_ADVICE = ["MATCH (n) WHERE n.id IN set RETURN n", "MATCH (s:Session) WITH count(s) AS drop RETURN drop AS n"]


@needs_node
def test_the_console_guard_refuses_writes_and_lets_reads_through():
    verdicts = _guard(WRITES + READS + READS_REFUSED_WITH_ADVICE + ["", "   \n", "// only a comment", "/* x */"])
    writes, rest = verdicts[:len(WRITES)], verdicts[len(WRITES):]
    let_through = [stmt for stmt, v in zip(WRITES, writes) if v["refusal"] is None]
    assert let_through == [], "a statement that writes (or stops the engine) must be refused before it runs"
    refused = [(stmt, v["refusal"]) for stmt, v in zip(READS, rest) if v["refusal"] is not None]
    assert refused == [], "a read was refused: a false alarm"
    for stmt, v in zip(READS_REFUSED_WITH_ADVICE, rest[len(READS):]):
        assert v["refusal"] and "backticks" in v["refusal"], stmt
    assert [v["refusal"] for v in rest[-4:]] == ["Nothing to run."] * 4
    said = dict(zip(WRITES, (v["refusal"] for v in writes)))
    assert "CREATE would change the graph" in said["CREATE (n:Oops) RETURN n"]
    assert "DETACH would change the graph" in said["MATCH (n:Chunk) DETACH DELETE n FINISH"]
    assert "FINISH returns nothing" in said["MATCH (n) FINISH"] and "LOAD CSV" in said[WRITES[31]]
    assert "db.createLabel" in said["CALL db.`createLabel`('Zed')"] and "db.createLabel" in said["CALL db . createLabel('Zed')"]
    assert "randomUUID" in said["RETURN `randomUUID`() AS id"]
    # A write word inside a string, a comment or backticks is "hidden": the viewer loads the export again after it.
    hidden = {stmt: v["hidden"] for stmt, v in zip(READS, rest)}
    assert hidden["MATCH (c:ToolCall) WHERE c.summary CONTAINS 'git merge' RETURN c"] is True
    assert hidden["WITH [1, 2] AS `set` RETURN size(`set`) AS n"] is True
    assert hidden["RETURN 'CREATE (n) SET n.x = 1 DELETE n' AS text"] is True
    assert hidden["MATCH (dataset:Session) RETURN count(dataset) AS n"] is False
    assert hidden["MATCH (n) RETURN count(n) AS n"] is False and hidden["RETURN $set AS n, $create AS m"] is False


def _write_attempts() -> list[str]:
    """Write clauses in every disguise this file could think of: quoting, comments, spacing, case."""
    clauses = [
        "CREATE (zz:Oops)", "MERGE (zz:Oops {id: 1})", "MATCH (zz:Session) SET zz.zzz = 1", "MATCH (zz:Session) REMOVE zz.cwd",
        "MATCH (zz:Chunk) DETACH DELETE zz", "MATCH (zz:Session) SET zz:Extra", "FOREACH (x IN [1] | CREATE (:Oops))", "INSERT (zz:Oops)",
        "MATCH (zz:Session) CALL (zz) { SET zz.zzz = 1 }",
    ]
    prefixes = [
        "", "WITH 1 AS one ", "WITH 'x\\\n' AS s ", "WITH \"x\\\n\" AS s ", "WITH 'x\\\r\n' AS s ", "WITH 'a\\\\' AS s ", "WITH 'a\\'b' AS s ",
        "WITH '' AS s ", "WITH '\\\\\\\n' AS s ", "WITH `a``b` AS s ", "WITH 1 AS `a\\` ", "/* ' */ WITH 1 AS s ", "// '\nWITH 1 AS s ",
        "WITH '/*' AS s ", "WITH '//' AS s ", "WITH \"'\" AS s ", "WITH '\"' AS s ", "WITH '`' AS s ", "WITH 1 AS s /* \\\n */ ",
        "WITH 'x\\\n' AS a, 'y\\\n' AS b ", "WITH '\\u0027' AS s ", "WITH 1 AS s\u00a0", "WITH 1 AS s\u2028", "WITH 1 AS SET ",
        "UNWIND [1] AS AS ", "WITH 1 AS x, 2 AS AS ", "WITH (1) AS AS WITH AS ", "WITH 'a' AS AS ", "WITH 1 AS `AS` ",
    ]
    suffixes = ["", " RETURN 1 AS x", " FINISH", " RETURN 'x' AS x //'", " RETURN \"y\" AS y /* ' */", " FINISH //'", "\n// '\n", " RETURN '\\\n' AS z",
                " WITH 1 AS AS FINISH", " WITH 1 AS finish FINISH"]
    out = []
    for i, clause in enumerate(clauses):
        for j, prefix in enumerate(prefixes):
            for k in (0, (i + j) % len(suffixes), (i + 2 * j + 3) % len(suffixes)):
                for text in (clause, re.sub(r"\b[A-Z]{2,}\b", lambda m: m.group(0).lower(), clause)):   # keywords in lower case
                    out.append(prefix + text + suffixes[k])
    return list(dict.fromkeys(out))


@needs_node
def test_nothing_the_guard_lets_through_changes_a_graph(sample, tmp_path):
    """Every disguise, judged by the guard and then run by the real engine inside a transaction that is rolled back."""
    attempts = _write_attempts() + WRITES
    verdicts = _guard(attempts)
    target = tmp_path / "sample.rl"
    write_rl(sample, target)
    fingerprint = ("MATCH (n) WHERE NOT n:Meta RETURN count(n) AS nodes, sum(size(keys(n))) AS props, sum(size(labels(n))) AS labels",
                   "MATCH ()-[r]->() RETURN count(r) AS rels", "SHOW INDEXES YIELD name RETURN count(name) AS indexes",
                   "SHOW CONSTRAINTS YIELD name RETURN count(name) AS constraints")
    slipped, wrote, ran_clean = [], 0, 0
    with Store(target) as store:
        clean = [store.run(q) for q in fingerprint]
        for statement, verdict in zip(attempts, verdicts):
            changed = False
            with store.rehearsal():
                try:
                    store.run(statement)
                except Exception:   # noqa: BLE001 - the engine refused the statement; nothing ran
                    continue
                changed = [store.run(q) for q in fingerprint] != clean
            assert [store.run(q) for q in fingerprint] == clean, "the rollback did not restore the store"
            wrote += changed
            ran_clean += not changed
            # The viewer keeps the graph if it refuses the statement, or if it reloads the export afterwards.
            if changed and verdict["refusal"] is None and not verdict["hidden"]:
                slipped.append(statement)
    assert slipped == [], "these statements change the graph and the viewer would neither refuse nor undo them"
    assert wrote > 800, f"only {wrote} of {len(attempts)} attempts were real writes: the test lost its teeth"


@needs_node
def test_reads_that_the_guard_lets_through_do_run_on_the_engine(sample, tmp_path):
    """The other half: what the guard calls a read is one, on the engine the browser also runs."""
    target = tmp_path / "sample.rl"
    write_rl(sample, target)
    with Store(target, read_only=True) as store:
        for statement in READS:
            if "$" in statement or statement.startswith(("EXPLAIN", "PROFILE", "SHOW", "CALL")):
                continue
            store.run(statement)       # read_only: a write would raise here
        assert store.one("WITH [1, 2, 3] AS set RETURN size(set) AS n")["n"] == 3
        assert store.one("RETURN {set: 1, delete: 2}.set AS n")["n"] == 1


def _viewer_queries() -> dict[str, str]:
    """Every statement in viewer/queries.js, by name (the console examples by title)."""
    script = (
        f"import * as q from {json.dumps((VIEWER / 'queries.js').as_uri())};\n"
        "const out = {};\n"
        "for (const [name, value] of Object.entries(q)) {\n"
        "  if (typeof value === 'string') out[name] = value;\n"
        "  else if (Array.isArray(value)) value.forEach((e, i) => { out[`${name}[${i}] ${e.title}`] = e.statement; });\n"
        "}\n"
        "console.log(JSON.stringify(out));\n"
    )
    done = subprocess.run([NODE, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@needs_node
def test_the_guard_runs_every_stored_rule_query_and_every_query_of_the_viewer():
    """The Run button executes the query a rule stored on its finding, and "Open in console" hands
    over the viewer's own statements. The guard must let all of them run, and none may hold a
    write word in a string or comment, which would make the viewer reload the graph after it."""
    from tainttrail import paths, rules

    statements = _viewer_queries()
    assert len(statements) >= 20 and any(name.startswith("EXAMPLES[") for name in statements)
    statements.update({f"rules.CYPHER[{key}]": text.strip() for key, text in rules.CYPHER.items()})
    statements.update({f"paths.{name}": getattr(paths, name).strip() for name in ("PATH_QUERY", "LEGS_QUERY", "WITNESS_QUERY")})
    verdicts = _guard(list(statements.values()))
    refused = {name: v["refusal"] for name, v in zip(statements, verdicts) if v["refusal"]}
    assert refused == {}, "the viewer would refuse to run one of the project's own read queries"
    reloading = [name for name, v in zip(statements, verdicts) if v["hidden"]]
    assert reloading == [], "these queries mention a write word in a string or comment"


@needs_node
def test_every_query_of_the_viewer_runs_on_the_engine(sample, tmp_path):
    """The browser runs these on the WebAssembly build; the native build parses the same Cypher."""
    queries = _viewer_queries()
    assert {"TOTALS", "SESSIONS", "FINDINGS", "DESTINATIONS", "SESSION_CALLS", "SESSION_RECEIVED", "FINDING", "MAP_TOOLS",
            "MAP_PATH_TOTALS"} <= set(queries)
    target = tmp_path / "sample.rl"
    write_rl(sample, target)
    session = sample["meta"]["sessions"][0]["id"]
    finding = next(n["id"] for n in sample["nodes"] if "Finding" in n["labels"])
    with Store(target, read_only=True) as store:
        for name, statement in queries.items():
            params = {key: value for key, value in (("sid", session), ("id", finding), ("dest", "host:attacker.example"))
                      if f"${key}" in statement}
            try:
                store.run(statement, params)
            except Exception as exc:   # noqa: BLE001 - name the statement that failed
                pytest.fail(f"{name} does not run: {exc}")
        totals = store.one(queries["TOTALS"])
        sessions = sample["meta"]["sessions"]
        assert (totals["sessions"], totals["calls"], totals["denied"], totals["asked"]) == (
            len(sessions), sum(s["calls"] for s in sessions), sum(s["denied"] for s in sessions), sum(s["asked"] for s in sessions))
        assert totals["holding"] == 2 and totals["unenforced"] == 0, "the sample was recorded in guard mode"
        received = store.run(queries["SESSION_RECEIVED"], {"sid": session})
        assert received and {"origin", "source", "bytes", "mentions"} <= set(received[0])


@needs_node
def test_the_overview_queries_tell_a_hold_from_a_hold_that_was_not_enforced(cfg: Config, tmp_path):
    """In monitor mode nothing is held. The numbers the overview shows must say that the calls
    ran, not that nothing happened: "no call was held" next to a TT001 finding is a false comfort."""
    queries = _viewer_queries()
    cfg.mode = "monitor"
    with Store(cfg.db_path) as store:
        attack_session(store, cfg)
        export = export_graph(store, project="p", root=cfg.root)
    findings = [n["props"] for n in export["nodes"] if "Finding" in n["labels"]]
    assert {(f["rule"], f["action"], f["intended"]) for f in findings} >= {("TT001", "allow", "deny")}
    target = tmp_path / "monitor.rl"
    write_rl(export, target)
    with Store(target, read_only=True) as store:
        totals = store.one(queries["TOTALS"])
        assert (totals["denied"], totals["asked"], totals["holding"]) == (0, 0, 0)
        assert totals["unenforced"] == sum(1 for f in findings if f["action"] == "allow" and f["intended"] in ("ask", "deny")) >= 1
        row = store.one(queries["SESSIONS"])
        assert (row["denied"], row["asked"]) == (0, 0) and row["would_deny"] >= 1
        destinations = {d["id"]: d for d in store.run(queries["DESTINATIONS"])}
        evil = destinations["host:attacker.example"]
        assert (evil["denied"], evil["would_deny"], evil["by_untrusted"], evil["by_user"], evil["by_trusted"]) == (0, 1, True, False, False)
        docs = destinations["host:docs.example.test"]
        assert (docs["would_deny"], docs["would_ask"], docs["by_user"]) == (0, 0, True)


def test_the_viewer_uses_no_regex_lookbehind():
    """Safari before 16.4 fails to parse a script that holds one, and the whole viewer would stay blank."""
    for path in (p for p in _OWN_SOURCES if p.suffix == ".js"):
        assert "(?<" not in path.read_text(encoding="utf-8"), path.name


def test_what_other_tools_click_in_the_viewer_is_there():
    """The demo video builder drives the viewer by visible text. A label that is reworded here breaks it there."""
    scenes = VIEWER.parents[2] / "tools" / "demo-video" / "scenes.json"
    if not scenes.is_file():
        pytest.skip("no demo video script in this checkout")
    sources = "\n".join(p.read_text(encoding="utf-8") for p in _OWN_SOURCES)
    wanted = [step[key][len("text="):] for scene in json.loads(scenes.read_text(encoding="utf-8"))["scenes"]
              if scene.get("kind") == "viewer" for step in scene.get("steps", []) for key in ("click", "scrollTo")
              if str(step.get(key, "")).startswith("text=")]
    assert wanted, "the viewer scene clicks nothing by text any more: drop this test"
    for text in wanted:
        assert f"'{text}'" in sources or f">{text}<" in sources, f"{text!r} is not a label of the viewer"


def test_viewer_sources_are_plain_ascii():
    """A static host may not declare a charset; ASCII reads the same under any of them."""
    for path in _OWN_SOURCES:
        text = path.read_text(encoding="utf-8")
        assert text.isascii(), f"{path.name}: non-ASCII at {next(i for i, c in enumerate(text) if ord(c) > 127)}"


def test_every_viewer_file_is_one_the_server_and_the_wheel_will_ship():
    served = set(serve.viewer_files())
    on_disk = {p.relative_to(VIEWER).as_posix() for p in VIEWER.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".py" and p.name != "graph.json"}
    assert served == on_disk | {"sample/graph.json"}, served ^ (on_disk | {"sample/graph.json"})
    pyproject = (VIEWER.parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'packages = ["src/tainttrail"]' in pyproject, "hatch ships every file under the package directory"
    ignored = (VIEWER.parents[2] / ".gitignore").read_text(encoding="utf-8").split()
    assert not any(part.rstrip("/") in ignored or f"{part}/" in ignored
                   for rel in served for part in rel.split("/")[:-1]), "no viewer directory may be git-ignored"
