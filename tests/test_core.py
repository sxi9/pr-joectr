from __future__ import annotations

import glob
import os
import signal
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tainttrail import schema
from tainttrail.config import Config, find_root, load_config, normalize_path
from tainttrail.model import Decision, EntityRef, Finding
from tainttrail.store import Store, StoreDamaged, StoreLocked, StoreMissing, to_plain


# -- config -------------------------------------------------------------------------


def test_sensitive_paths_and_exceptions(cfg: Config):
    assert cfg.is_sensitive_path(cfg.root / ".env")
    assert cfg.is_sensitive_path(cfg.root / "deploy" / ".env.production")
    assert cfg.is_sensitive_path("~/.ssh/id_ed25519")
    assert cfg.is_sensitive_path("~/.aws/credentials")
    assert cfg.is_sensitive_path(cfg.root / "certs" / "server.pem")
    assert not cfg.is_sensitive_path(cfg.root / ".env.example")
    assert not cfg.is_sensitive_path("~/.ssh/id_ed25519.pub")
    assert not cfg.is_sensitive_path(cfg.root / "src" / "main.py")
    assert not cfg.is_sensitive_path(cfg.root / "environment.md")


def test_relative_paths_resolve_against_the_project(cfg: Config):
    assert cfg.is_sensitive_path(".env")
    assert cfg.is_protected_path("CLAUDE.md")
    assert cfg.is_protected_path(".claude/settings.json")
    assert cfg.is_protected_path(".github/workflows/ci.yml")
    assert cfg.is_protected_path(".tainttrail/config.toml")
    assert not cfg.is_protected_path("README.md")
    assert cfg.is_untrusted_path("node_modules/left-pad/README.md")
    assert not cfg.is_untrusted_path("src/app.js")


def test_normalize_path_collapses_dots_and_expands_home(cfg: Config):
    assert normalize_path("a/../b/./c.txt", cfg.root) == f"{cfg.root.as_posix()}/b/c.txt"
    assert normalize_path("~/x") == f"{Path.home().as_posix()}/x"
    assert normalize_path("file:///etc/hosts") == "/etc/hosts"


def test_host_classification(cfg: Config):
    assert cfg.is_trusted_host("GitHub.com")
    assert cfg.is_trusted_host("pypi.org.")
    assert not cfg.is_trusted_host("github.com.attacker.example")
    assert not cfg.is_trusted_host("evilgithub.com")
    assert cfg.is_local_host("localhost")
    assert cfg.is_local_host("127.0.0.1")
    assert cfg.is_local_host("10.1.2.3")
    assert cfg.is_local_host("[::1]")
    assert not cfg.is_local_host("8.8.8.8")
    assert not cfg.is_local_host("attacker.example")


def test_rule_action_follows_mode_and_overrides(cfg: Config):
    assert cfg.rule_action("TT002", "ask") == "ask"
    cfg.mode = "strict"
    assert cfg.rule_action("TT002", "ask") == "deny"
    assert cfg.rule_action("TT009", "allow") == "allow"
    cfg.mode = "monitor"
    assert cfg.rule_action("TT001", "deny") == "allow"
    cfg.rules = {"TT001": "deny", "TT009": "off"}
    assert cfg.rule_action("TT001", "deny") == "deny"
    assert cfg.rule_action("TT009", "allow") == "off"


def test_config_file_is_read_and_extends_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("TAINTTRAIL_HOME", raising=False)
    monkeypatch.delenv("TAINTTRAIL_MODE", raising=False)
    root = tmp_path / "proj"
    (root / ".tainttrail").mkdir(parents=True)
    (root / "sub" / "dir").mkdir(parents=True)
    (root / ".tainttrail" / "config.toml").write_text(textwrap.dedent("""
        mode = "strict"
        fail_closed = true
        [hosts]
        trusted = ["intranet.example.com", "*.corp.example"]
        [paths]
        sensitive = ["**/customers.csv"]
        [rules]
        tt003 = "DENY"
        TT009 = "off"
        [limits]
        max_chunks = 50
    """))
    cfg = load_config(root / "sub" / "dir")
    assert cfg.root == root.resolve()
    assert cfg.mode == "strict" and cfg.fail_closed is True
    assert cfg.is_trusted_host("intranet.example.com")
    assert cfg.is_trusted_host("build.corp.example")
    assert cfg.is_trusted_host("github.com"), "defaults are extended, not replaced"
    assert cfg.is_sensitive_path(root / "data" / "customers.csv")
    assert cfg.rules == {"TT003": "deny", "TT009": "off"}
    assert cfg.max_chunks == 50


def test_find_root_prefers_tainttrail_dir_then_git(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "pkg" / "deep"
    inner.mkdir(parents=True)
    assert find_root(inner) == inner.resolve()
    (outer / ".git").mkdir()
    assert find_root(inner) == outer.resolve()
    (outer / "pkg" / ".tainttrail").mkdir()
    assert find_root(inner) == (outer / "pkg").resolve()


def test_key_is_created_once_with_private_permissions(tmp_path, monkeypatch):
    monkeypatch.delenv("TAINTTRAIL_KEY", raising=False)
    cfg = Config(root=tmp_path, home=tmp_path / ".tainttrail")
    first = cfg.key()
    assert len(first) == 32
    assert cfg.key() == first
    mode = (tmp_path / ".tainttrail" / "key").stat().st_mode & 0o777
    assert mode == 0o600


# -- model --------------------------------------------------------------------------


def test_entity_ids_and_names():
    assert EntityRef("host", "attacker.example").id == "host:attacker.example"
    assert EntityRef("file", "/home/u/app/.env").name == ".env"


def test_decision_takes_the_strictest_action():
    def f(action):
        return Finding(rule="TT000", name="x", severity="low", action=action, title="", explanation="")

    assert Decision.from_findings([]).action == "allow"
    assert Decision.from_findings([f("allow"), f("ask")]).action == "ask"
    assert Decision.from_findings([f("ask"), f("deny"), f("allow")]).action == "deny"


# -- store --------------------------------------------------------------------------


def test_schema_is_created_once(store: Store):
    assert store.scalar("MATCH (m:Meta {key: 'schema'}) RETURN m.version") == schema.SCHEMA_VERSION
    names = {r["name"] for r in store.run("MATCH (c:Capability) RETURN c.name AS name")}
    assert names == set(schema.CAPABILITIES)
    assert schema.ensure_schema(store.conn) is False


def test_unique_ids_are_enforced(store: Store):
    store.write("CREATE (:ToolCall {id: 'c1'})")
    with pytest.raises(Exception):
        store.write("CREATE (:ToolCall {id: 'c1'})")


def test_run_returns_plain_json_values(mem: Store):
    mem.write(
        "CREATE (:Content {id: 'u1', untrusted: true})-[:MENTIONS]->(:Entity {id: 'host:evil.test', kind: 'host'})"
        "<-[:SENDS_TO {port: 443}]-(:ToolCall {id: 'c1', seq: 3})"
    )
    row = mem.one("MATCH p = (:Content)-[:MENTIONS]->(e)<-[:SENDS_TO]-(c) RETURN p, e, c.seq AS seq")
    assert row["seq"] == 3
    assert row["e"] == {"id": "host:evil.test", "labels": ["Entity"], "props": {"id": "host:evil.test", "kind": "host"}}
    assert [n["id"] for n in row["p"]["nodes"]] == ["u1", "host:evil.test", "c1"]
    assert row["p"]["rels"] == [
        {"type": "MENTIONS", "start": "u1", "end": "host:evil.test", "props": {}},
        {"type": "SENDS_TO", "start": "c1", "end": "host:evil.test", "props": {"port": 443}},
    ]
    import json

    json.dumps(row)  # must not raise


def test_to_plain_passes_scalars_and_stringifies_unknowns():
    assert to_plain({"a": [1, "x", None, True, 1.5]}) == {"a": [1, "x", None, True, 1.5]}
    assert to_plain(Path("/x")) == "/x"


def test_transaction_commits_and_rolls_back(store: Store):
    with store.transaction():
        store.write("CREATE (:Session {id: 's1'})")
        store.write("CREATE (:ToolCall {id: 'c1', session_id: 's1'})")
    assert store.scalar("MATCH (n:ToolCall) RETURN count(n)") == 1

    with pytest.raises(RuntimeError):
        with store.transaction():
            store.write("CREATE (:ToolCall {id: 'c2', session_id: 's1'})")
            raise RuntimeError("boom")
    assert store.scalar("MATCH (n:ToolCall) RETURN count(n)") == 1
    assert store.conn.autocommit is True


def test_rehearsal_never_persists(store: Store):
    store.write("CREATE (:Tool {id: 't1', name: 'WebFetch', permission: 'allow'})")
    with store.rehearsal():
        store.write("MATCH (t:Tool {id: 't1'}) SET t.permission = 'deny'")
        assert store.scalar("MATCH (t:Tool {id: 't1'}) RETURN t.permission") == "deny"
    assert store.scalar("MATCH (t:Tool {id: 't1'}) RETURN t.permission") == "allow"


def test_data_survives_reopen(cfg: Config):
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's1'})")
    with Store(cfg.db_path) as s:
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 1
    with Store(cfg.db_path, read_only=True) as s:
        assert s.scalar("MATCH (n:Session) RETURN n.id") == "s1"


def test_read_only_open_of_missing_store_is_a_clear_error(cfg: Config):
    with pytest.raises(StoreMissing):
        Store(cfg.db_path, read_only=True).open()
    assert not cfg.db_path.exists(), "a read-only open must not create the store"


def test_second_opener_times_out_with_store_locked(cfg: Config):
    with Store(cfg.db_path):
        with pytest.raises(StoreLocked):
            Store(cfg.db_path, timeout_ms=150).open()
    # and the lock is released afterwards
    with Store(cfg.db_path, timeout_ms=150) as s:
        assert s.scalar("RETURN 1") == 1


_WORKER = textwrap.dedent("""
    import sys
    from tainttrail.store import Store
    path, worker, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    for i in range(n):
        with Store(path, timeout_ms=20000) as s:
            with s.transaction():
                seq = s.scalar("MERGE (c:Meta {key: 'counter'}) ON CREATE SET c.n = 0 SET c.n = c.n + 1 RETURN c.n")
                s.write("CREATE (:ToolCall {id: $id, seq: $seq})", {"id": f"{worker}-{i}", "seq": seq})
""")


def test_parallel_processes_queue_up_and_lose_nothing(cfg: Config, tmp_path):
    """Hooks for parallel tool calls are separate processes; none may fail or overwrite."""
    with Store(cfg.db_path):
        pass
    script = tmp_path / "worker.py"
    script.write_text(_WORKER)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    workers, per_worker = 6, 8
    procs = [
        subprocess.Popen([sys.executable, str(script), str(cfg.db_path), f"w{w}", str(per_worker)],
                         env=env, stderr=subprocess.PIPE, text=True)
        for w in range(workers)
    ]
    errors = [p.communicate()[1] for p in procs]
    assert [p.returncode for p in procs] == [0] * workers, errors
    with Store(cfg.db_path) as s:
        seqs = sorted(r["seq"] for r in s.run("MATCH (c:ToolCall) RETURN c.seq AS seq"))
    assert seqs == list(range(1, workers * per_worker + 1)), "sequence numbers must be unique and gap-free"


# -- a hook can be killed at any moment, and the graph has to survive it -----------------------

_SLOW_WRITER = textwrap.dedent("""
    import sys, time
    from tainttrail.store import Store
    path, pause = sys.argv[1], sys.argv[2]
    store = Store(path).open()
    with store.transaction():
        store.write("UNWIND range(1, 400) AS i CREATE (:Content {id: 'k' + toString(i), excerpt: 'x', session_id: 's', seq: i})")
    print("written", flush=True)
    if pause == "before-close":
        time.sleep(30)
    store.close()
    print("closed", flush=True)
""")


def _spawn_writer(tmp_path, db, pause):
    script = tmp_path / "slow_writer.py"
    script.write_text(_SLOW_WRITER)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    proc = subprocess.Popen([sys.executable, str(script), str(db), pause], env=env, stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "written"
    return proc


def _side_files(db, kind):
    return glob.glob(f"{str(db)[:-3]}.{kind}*.rl")


def test_a_writer_never_touches_the_live_file_until_it_has_closed_cleanly(cfg: Config, tmp_path):
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's1'})")
    before = cfg.db_path.read_bytes()
    proc = _spawn_writer(tmp_path, cfg.db_path, "before-close")
    assert cfg.db_path.read_bytes() == before, "the writer works on a private copy"
    assert _side_files(cfg.db_path, "work-"), "which sits next to the store"
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    assert cfg.db_path.read_bytes() == before, "a killed writer publishes nothing"
    with Store(cfg.db_path) as s:      # the next writer is not blocked by the dead one, and tidies up
        assert s.scalar("MATCH (n:Content) RETURN count(n)") == 0
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 1
    assert _side_files(cfg.db_path, "work-") == []


def test_a_writer_killed_while_closing_leaves_a_store_that_opens(cfg: Config, tmp_path):
    """In-place writes failed this about once in thirteen kills; a rename cannot."""
    with Store(cfg.db_path) as s:
        s.write("UNWIND range(1, 3000) AS i CREATE (:Entity {id: 'e' + toString(i), kind: 'file', name: 'n'})")
    seen = set()
    for delay_ms in (0, 2, 4, 6, 9, 12, 16, 22):
        proc = _spawn_writer(tmp_path, cfg.db_path, "none")
        if delay_ms:
            try:
                proc.wait(timeout=delay_ms / 1000)
            except subprocess.TimeoutExpired:
                pass
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        with Store(cfg.db_path, read_only=True) as s:
            count = s.scalar("MATCH (n:Content) RETURN count(n)")
            assert s.scalar("MATCH (n:Entity) RETURN count(n)") == 3000
        assert count in (0, 400), "the batch is there completely or not at all"
        seen.add(count)
        if count:
            with Store(cfg.db_path) as s:
                s.write("MATCH (n:Content) DETACH DELETE n")
    assert seen <= {0, 400}


def test_publishing_keeps_the_previous_version_and_private_permissions(cfg: Config):
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's1'})")
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's2'})")
        previous = s.previous_path
    assert stat.S_IMODE(os.stat(cfg.db_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(previous).st_mode) == 0o600
    with Store(previous, read_only=True) as s:
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 1
    assert _side_files(cfg.db_path, "work-") == [] and _side_files(cfg.db_path, "prev-") == []


def test_a_damaged_store_is_set_aside_and_the_previous_version_takes_over(cfg: Config):
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's1'})")
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's2'})")
    cfg.db_path.write_bytes(b"this is not a Relate store " * 400)
    with pytest.raises(StoreDamaged) as err:
        Store(cfg.db_path, read_only=True).open()
    assert "tainttrail doctor" in str(err.value)
    with Store(cfg.db_path) as s:
        assert s.recovered and s.recovered["restored"] == "previous"
        assert [r["id"] for r in s.run("MATCH (n:Session) RETURN n.id AS id")] == ["s1"]
        note = s.one("MATCH (m:Meta {key: 'recovered'}) RETURN m.damaged AS damaged, m.count AS count")
        damaged = s.recovered["damaged"]
    assert note == {"damaged": damaged, "count": 1}
    assert Path(damaged).read_bytes().startswith(b"this is not a Relate store"), "the evidence is kept"
    with Store(cfg.db_path, read_only=True) as s:      # and the store is whole again
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 1
    with Store(cfg.db_path) as s:
        assert s.recovered is None


def test_a_damaged_store_with_no_previous_version_starts_a_new_graph(cfg: Config):
    with Store(cfg.db_path) as s:
        s.write("CREATE (:Session {id: 's1'})")
        previous = s.previous_path
    assert not os.path.exists(previous), "one publish has nothing before it"
    cfg.db_path.write_bytes(b"\x00" * 4096)
    with Store(cfg.db_path) as s:
        assert s.recovered and s.recovered["restored"] == "empty"
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 0
        assert s.scalar("MATCH (c:Capability) RETURN count(c)") > 0, "with its schema in place"


def test_deleting_the_graph_also_forgets_its_previous_version(cfg: Config):
    for sid in ("s1", "s2"):
        with Store(cfg.db_path) as s:
            s.write("CREATE (:Session {id: $id})", {"id": sid})
            previous = s.previous_path
    os.unlink(cfg.db_path)
    with Store(cfg.db_path) as s:
        assert s.scalar("MATCH (n:Session) RETURN count(n)") == 0
    assert not os.path.exists(previous)

