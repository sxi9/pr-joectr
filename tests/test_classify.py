from __future__ import annotations

import pytest

from tainttrail import classify
from tainttrail.classify import (
    BUILTIN_TOOLS, classify_tool, heuristic_labels, load_catalog, match_server, parse_tool_name,
)
from tainttrail.model import CAPABILITY_NAMES

CATALOG = {
    "servers": [
        {
            "id": "github",
            "match": {"names": ["github"], "packages": ["@modelcontextprotocol/server-github", "github-mcp-server"],
                      "url_hosts": ["api.githubcopilot.com"]},
            "tools": [
                {"name": "get_issue", "untrusted_input": True, "private_data": False, "external_sink": False,
                 "local_write": False, "code_exec": False, "sink_scope": None, "notes": "issue text is third-party"},
                {"name": "create_issue", "untrusted_input": False, "private_data": False, "external_sink": True,
                 "local_write": False, "code_exec": False, "sink_scope": "public"},
                {"name": "get_file_contents", "untrusted_input": True, "private_data": True, "external_sink": False,
                 "local_write": False, "code_exec": False},
            ],
        },
        {"id": "slack", "match": {"names": ["slack"], "packages": ["@modelcontextprotocol/server-slack"]}, "tools": []},
    ],
    "heuristics": {"external_sink": ["dispatch"]},
}


def caps(labels) -> set[str]:
    return set(labels.capabilities())


def test_parse_tool_name():
    assert parse_tool_name("mcp__github__get_issue") == ("github", "get_issue")
    assert parse_tool_name("mcp__a__b__c") == ("a", "b__c")
    assert parse_tool_name("Read") == (None, "Read")
    assert parse_tool_name("mcp__") == (None, "mcp__")


def test_builtin_tools_describe_claude_code_honestly():
    assert caps(classify_tool("Read")) == {"private_data"}
    assert caps(classify_tool("Write")) == {"local_write"}
    assert caps(classify_tool("WebFetch")) == {"untrusted_input", "external_sink"}
    assert caps(classify_tool("WebSearch")) == {"untrusted_input"}
    assert caps(classify_tool("Bash")) == set(CAPABILITY_NAMES)
    assert caps(classify_tool("TodoWrite")) == set()
    for name, labels in BUILTIN_TOOLS.items():
        assert labels.source == "builtin", name
    unknown = classify_tool("SomethingNew")
    assert (unknown.source, unknown.confidence, caps(unknown)) == ("default", 0.0, set())


def test_builtin_labels_are_copies():
    a = classify_tool("Read")
    a.external_sink = True
    assert classify_tool("Read").external_sink is False


def test_catalog_tools_win_over_guessing():
    issue = classify_tool("mcp__github__get_issue", catalog=CATALOG)
    assert (issue.source, issue.confidence) == ("catalog", 0.9)
    assert caps(issue) == {"untrusted_input"} and issue.notes == "issue text is third-party"
    create = classify_tool("mcp__github__create_issue", catalog=CATALOG)
    assert caps(create) == {"external_sink"} and create.sink_scope == "public"
    assert caps(classify_tool("mcp__GitHub__Get-File-Contents", catalog=CATALOG)) == {"untrusted_input", "private_data"}


def test_unknown_tool_of_a_known_server_is_guessed_and_says_so():
    labels = classify_tool("mcp__github__add_issue_comment", catalog=CATALOG)
    assert labels.source == "heuristic" and labels.confidence == 0.5
    assert "external_sink" in caps(labels)
    assert labels.notes.startswith("github server is in the catalog but this tool is not")


@pytest.mark.parametrize("name,command,args,url,expected", [
    ("github", "", None, "", "github"),
    ("my-github", "", None, "", "github"),
    ("GitHub", "", None, "", "github"),
    ("gh", "npx", ["-y", "@modelcontextprotocol/server-github"], "", "github"),
    ("tools", "docker", ["run", "ghcr.io/github/github-mcp-server"], "", "github"),
    ("remote", "", None, "https://api.githubcopilot.com/mcp/", "github"),
    ("githubbish", "", None, "", None),
    ("notgithub", "", None, "", None),
    ("team-chat", "npx", ["@modelcontextprotocol/server-slack"], "", "slack"),
    ("database", "", None, "", None),
])
def test_match_server(name, command, args, url, expected):
    entry = match_server(name, command=command, args=args, url=url, catalog=CATALOG)
    assert (entry or {}).get("id") == expected


@pytest.mark.parametrize("tool,description,expected", [
    ("send_email", "", {"external_sink"}),
    ("post_message", "Post a message to a channel", {"external_sink"}),
    ("create_issue", "", {"external_sink"}),
    ("createPullRequest", "", {"external_sink"}),
    ("http_request", "Make an arbitrary HTTP request", {"external_sink"}),
    ("dispatch_job", "", {"external_sink"}),
    ("get_issue", "", {"untrusted_input"}),
    ("search_web", "", {"untrusted_input"}),
    ("list_emails", "", {"untrusted_input", "private_data"}),
    ("read_file", "", {"private_data"}),
    ("query_database", "Run a read-only SQL query", {"private_data"}),
    ("get_weather", "", set()),
    ("add_numbers", "", set()),
    ("write_file", "", {"local_write"}),
    ("run_command", "", {"code_exec"}),
    ("execute_script", "", {"code_exec"}),
    ("get_time", "Returns the current time in a timezone", set()),
    ("get_post", "", {"untrusted_input"}),
    ("list_comments", "", {"untrusted_input"}),
    ("email_report", "", {"external_sink"}),
    ("slack_post_message", "", {"external_sink"}),
    ("gmail_list_messages", "", {"untrusted_input"}),
    ("fetch", "Fetches a URL from the internet and extracts its contents as markdown", {"untrusted_input"}),
    ("search", "Search the web", {"untrusted_input"}),
    ("query", "Run a read-only SQL query", {"private_data"}),
    ("get_weather", "Get the forecast for a location for the user", set()),
    ("get_command_history", "", set()),
    ("python_repl", "", {"code_exec"}),
])
def test_heuristics(tool, description, expected):
    labels = heuristic_labels(tool, description, CATALOG)
    assert caps(labels) == expected
    assert labels.source == "heuristic"
    assert labels.confidence == (0.5 if expected else 0.0)


def test_unknown_server_falls_back_to_heuristics_with_low_confidence():
    labels = classify_tool("mcp__acme_crm__export_customers", catalog=CATALOG)
    assert labels.source == "heuristic" and caps(labels) == {"private_data"}
    nothing = classify_tool("mcp__acme__frobnicate", catalog=CATALOG)
    assert caps(nothing) == set() and nothing.confidence == 0.0


def test_schema_property_names_help_when_there_is_no_description():
    labels = classify_tool("mcp__x__fetch", input_schema={"properties": {"url": {}, "max_length": {}}}, catalog=CATALOG)
    assert "untrusted_input" in caps(labels)


def test_packaged_catalog_loads_or_is_empty(monkeypatch):
    load_catalog.cache_clear()
    data = load_catalog()
    assert isinstance(data.get("servers"), list)
    for server in data["servers"]:
        assert server.get("id"), "every catalog server has an id"
        for tool in server.get("tools") or []:
            assert tool.get("name")
    # with whatever is packaged, an MCP tool is always classified without raising
    assert classify_tool("mcp__github__get_issue").source in ("catalog", "heuristic")
    assert classify.classify_tool("mcp__unknown__thing").source == "heuristic"
