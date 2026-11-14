# TaintTrail plugin for Claude Code

The same guard that `tainttrail init` installs, packaged as a Claude Code plugin. It adds:

| Part | File | What it does |
|---|---|---|
| Hooks | `hooks/hooks.json` | Runs `tainttrail hook claude-code` on SessionStart, UserPromptSubmit, PreToolUse, PostToolUse and PostToolUseFailure. Every event is recorded in the project's graph (`.tainttrail/graph.rl`); a tool call that would complete an attack path is denied, a suspicious one is put to you. |
| MCP server | `.mcp.json` | Starts `tainttrail mcp` for the project: ten read-only tools over the graph, from `status` and `explain_finding` to `read_cypher`. The text of untrusted content is withheld from the agent. |
| Skill | `skills/tainttrail/SKILL.md` | `/tainttrail:tainttrail`, also loaded by Claude on its own: what to do when a call was blocked (tell you, show the path, never look for another route), and how to answer "why was this blocked?" and "is my setup risky?". |
| Command | `commands/status.md` | `/tainttrail:status` prints the guard's status and the latest findings, and explains the newest one. |

The plugin holds no code of its own. It calls the `tainttrail` command, so that command has
to be installed first.

## 1. Install the `tainttrail` command

It must be on the `PATH` of the shell that starts Claude Code. Either of these puts it
there, in an environment of its own:

```bash
uv tool install git+https://github.com/sxi9/pr-joectr
# or
pipx install git+https://github.com/sxi9/pr-joectr
```

From a clone of the repository, `uv tool install .` or `pipx install .` does the same.
Python 3.10 or newer is needed; its one dependency is `relate-db`. Check it:

```bash
tainttrail --version
tainttrail doctor
```

## 2. Load the plugin

For one session, from a clone:

```bash
claude --plugin-dir /path/to/pr-joectr/plugin
```

`claude plugin validate /path/to/pr-joectr/plugin` checks the manifest, the hooks, the MCP
entry and the skill without starting a session.

## 3. Use it

Work as usual. When a call is blocked, Claude is told why and you see a line such as
`TaintTrail blocked a call (TT001): ...`. Then:

- `/tainttrail:status` for the status, the latest findings and the path behind the newest one;
- ask "why was this blocked?" and Claude answers from the graph with `explain_finding`;
- `tainttrail explain last`, `tainttrail log` and `tainttrail ui` in a terminal show the same.

## Use the plugin or `tainttrail init`, not both

`tainttrail init` writes the same five hooks into `.claude/settings.json`. If the plugin is
loaded as well, every hook runs twice: each event is processed twice, which doubles the time
every tool call waits, and a blocked call is reported twice. Pick one:

- the plugin, when you want the guard in every project you open and the MCP tools with it;
- `tainttrail init`, when the guard should be part of one repository's settings and use the
  exact interpreter it was installed with. `tainttrail uninstall` removes that registration.

`tainttrail status` lists the settings files that register the hooks. It cannot see a
plugin, so "hooks: not registered" is expected when only the plugin is in use.

## What to know

- **If the command is missing, nothing is guarded.** Claude Code does not report a hook
  that cannot start. The plugin therefore checks at session start and shows a warning when
  `tainttrail` is not on `PATH`. Take that warning seriously.
- **Errors fail open by default.** If the guard itself fails (a bug, a store that stays
  locked), the call goes through and the error is written to `.tainttrail/guard.log`. Set
  `fail_closed = true` in `.tainttrail/config.toml` to block instead. To also block when
  the hook cannot start at all, add `"onFailure": "block"` to the PreToolUse entry in
  `hooks/hooks.json`.
- **Mode and lists** come from `.tainttrail/config.toml` in the project, created by
  `tainttrail init` or by hand: `mode = "monitor" | "guard" | "strict"`, trusted hosts,
  sensitive and untrusted paths, per-rule overrides.
- **`TAINTTRAIL_DISABLE=1`** in the environment turns the hooks into no-ops for that
  process tree. The guard treats an attempt by the agent to set it as tampering.
- **The MCP server only reads.** It refuses writes, runs Cypher from the agent in a
  separate process with a deadline on a copy of the graph, and never returns the text of
  untrusted content or the descriptions MCP servers give their tools: on that copy the
  text is overwritten before the statement runs. To read it yourself, run `tainttrail mcp
  --include-untrusted-text` or `tainttrail query` in a terminal.
- **Tool names.** Inside the plugin the MCP tools are called
  `mcp__plugin_tainttrail_tainttrail__status` and so on. A permission rule for all of them
  is `mcp__plugin_tainttrail_tainttrail__*`.
- **Limits.** The guard sees tool calls, not the model and not the inside of other MCP
  servers. A leak that is paraphrased, encoded in a way it does not decode, or sent a few
  bits at a time can pass. Run the agent in a sandbox with network egress control as well.
