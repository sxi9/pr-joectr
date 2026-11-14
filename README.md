# TaintTrail

An attack-path guard for AI coding agents: every prompt, tool call and tool result becomes a
node in an embedded [Relate](https://relatedb.ai) graph, and a tool call is blocked when it
would complete a path from untrusted content to private data leaving the machine.

The path that blocks the call is also the explanation, and the Cypher query that found it is
stored with the finding.

![A real Claude Code session: the hook denies the upload and the model reports it](docs/screenshots/02-real-claude-code-session.png)

Built for the Relate by Neo4j Hackathon 2026.
[Demo video, 1 min 53 s](docs/demo/tainttrail-demo.mp4) ·
[labelled screenshots](docs/screenshots/README.md) ·
[a recorded store to query](examples/claude-code-session)

## Use case

An agent that reads text a stranger can write, can reach private data, and can send data
out, can be told by that text to leak the data. This is indirect prompt injection, and the
combination has a name, the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/).
It is not hypothetical:

- A public GitHub issue made an agent copy private repository data into a public pull
  request ([Invariant Labs, 2025](https://invariantlabs.ai/blog/mcp-github-vulnerability)).
- A web page made a coding agent send secrets out through its shell
  ([Embrace The Red, 2025](https://embracethered.com/blog/posts/2025/devin-can-leak-your-secrets/)).
- A comment in a source file made an assistant leak a key inside a DNS lookup
  ([Embrace The Red, 2025](https://embracethered.com/blog/posts/2025/amazon-q-developer-data-exfil-via-dns/)).

No model refuses such instructions every time, and a permission prompt cannot tell where a
destination came from. What can be checked is the path. TaintTrail watches the tool boundary
of an unmodified agent and asks one question before each call: is there a path from untrusted
content to this call that carries sensitive data to somewhere outside?

The relationships that matter:

- which content named a host, a file or a repository first: the user, a trusted file, or
  something a third party wrote;
- which sensitive content a call's arguments carry, found by keyed fingerprints, including
  inside base64, hex and URL encoding;
- which files were written under untrusted influence, so that a later session that loads
  them inherits the taint;
- which tools an agent is configured with, and which combinations of them complete a leak.

Who it is for: a developer who runs a coding agent in a repository that has secrets; a
security team that has to approve agent setups; whoever has to explain afterwards what
happened in a session.

### What it does

| | |
|---|---|
| **Record** | Claude Code hooks write each event into one Relate file per project, `.tainttrail/graph.rl`. |
| **Guard** | Eleven rules, built from Cypher path queries, decide `deny`, `ask` or nothing before a tool call runs. The guard never answers "allow", so it cannot loosen the agent's own permission prompts. |
| **Explain** | The path a rule found is stored on the finding together with the query. `tainttrail explain` prints both. The agent is told why it was blocked and not to look for another route. |
| **Map** | `tainttrail scan` reads agent configuration (MCP servers, tools, permissions of Claude Code, Cursor and five other clients) into the same graph. `paths` lists toxic combinations; `fix` proposes the smallest permission change that breaks them and rehearses it in a transaction. |
| **Replay** | `tainttrail ui` opens the graph in the browser on Relate's WebAssembly build, offline. Every view is a Cypher query run in the page. |
| **Ask** | `tainttrail mcp` serves the graph to an agent, read-only. `tainttrail audit --agent` lets a second agent investigate it with Cypher. |

## How it uses Relate

- **Mode: single file** for the guard (`.tainttrail/graph.rl`) and for evidence exports;
  **in memory** in the browser viewer (Relate WASM).
- **Why this mode:** the guard is a hook, a new process for every tool call, with no server
  to start and nothing to configure. One file per project is also the artifact: after an
  incident you hand over one `.rl` file and the recipient queries it. A `.rl` file admits
  one opener at a time, which fits a hook that opens the store, does about 25 ms of work
  and closes it; parallel tool calls queue on a file lock. A single file can also be
  replaced atomically, which the guard uses to survive being killed (below). The browser
  build cannot open a `.rl` file, so the viewer seeds an in-memory store from an export and
  runs the same queries there.
- **What the graph models:** two layers in one graph.

```mermaid
flowchart LR
  subgraph map [Capability map, written by scan]
    Agent -->|CONNECTS| Server -->|PROVIDES| Tool -->|HAS_CAPABILITY| Capability
    Server -->|HOLDS| Credential
  end
  subgraph run [Session provenance, written by the hooks]
    Session -->|RAN| ToolCall -->|NEXT| ToolCall
    Session -->|RECEIVED| Content
    ToolCall -->|RETURNED| Content
    Content -->|MENTIONS| Entity
    Content -->|HAS_CHUNK| Chunk
    Content -->|FROM| Entity
    ToolCall -->|"READS, WRITES, FETCHES, SENDS_TO, UPLOADS, EXECUTES"| Entity
    ToolCall -->|CARRIES| Chunk
    Entity -->|TAINTED_BY| Content
    Entity -->|DERIVED_FROM| Entity
    Finding -->|FLAGS| ToolCall
    Finding -->|EVIDENCE| Entity
  end
  ToolCall -->|INVOKES| Tool
```

`Content` is anything that entered the agent's context, flagged `untrusted` (a third party
could have written it) and `sensitive` (it holds private data). `Entity` is a host, URL,
file, repository, e-mail address or environment variable. `Chunk` is a keyed fingerprint
(HMAC) of a secret, a long token, a line or a link: the graph never stores a secret value.

### The queries are the product

The rule that stopped the session in the screenshot, as stored on its finding:

```cypher
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})
          <-[:SENDS_TO]-(c:ToolCall {id: $call})-[:UPLOADS]->(f:Entity {sensitive: true})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
```

The same shape with a fingerprint in the middle catches a secret that was pasted, encoded or
glued into a command:

```cypher
MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity {id: $dest})
          <-[:SENDS_TO]-(c:ToolCall {id: $call})-[:CARRIES]->(k:Chunk)
          <-[:HAS_CHUNK]-(s:Content {sensitive: true})
WHERE u.session_id = c.session_id AND u.seq < c.seq
RETURN p
```

"Who named this destination?" is an `EXISTS` subquery per destination, and the shortest
chain of evidence from any untrusted content to a call is one quantified path pattern:

```cypher
MATCH p = SHORTEST 1 (u:Content {untrusted: true, session_id: $session})
          -[:MENTIONS|HAS_CHUNK|CARRIES|FROM|RETURNED|READS|WRITES|SENDS_TO|UPLOADS|TAINTED_BY|DERIVED_FROM]-{1,6}
          (c:ToolCall {id: $call})
RETURN p
```

A log and a regular expression can say that a command contains `curl`. They cannot say that
the host in it was first named by a web page fetched six calls earlier, in another agent's
session, through a notes file. That is a path question.

![The stored query, run again in the browser on Relate WASM, returns the same path](docs/screenshots/05-viewer-attack-path.png)

### Relate features this depends on

| Feature | Where |
|---|---|
| Embedded Python client, single-file store | the hook: open, one transaction, close, for every event |
| Transactions and rollback | one transaction per hook event; `fix` rehearses a permission change inside a transaction, re-runs the path query and rolls back |
| Uniqueness constraints and indexes | every node is addressed by a unique `id`, so each rule is an anchored lookup, not a scan |
| Quantified path patterns, `SHORTEST`, `EXISTS` subqueries, list comprehensions | the rules and the explanation path |
| Read-only opens | `tainttrail query`, the MCP server, the viewer's export |
| WebAssembly build | the offline viewer runs the stored rule queries in the browser |
| The `relate` CLI | inspecting the committed store without installing TaintTrail |

### Living inside a hook

Three things had to hold for an embedded store that a new process opens on every tool call.

- **A killed hook must not cost the graph.** The agent harness kills a hook that runs past
  its time limit. Each event is therefore written to a private copy of the file, which
  replaces the live file in one atomic rename; the version before it is kept, and a file
  that does not open is set aside and reported, never silently replaced. In 200 kills
  inside the store's close, and 101 at random points, the store opened every time and no
  committed event was lost.
- **The graph must stay small, because opening a store costs time in proportion to its
  size.** Fingerprints are kept only for content that is sensitive or untrusted, older
  results in a session keep their summary and lose their line-level detail (the last 12
  sensitive and 8 untrusted results keep it), and when the live graph passes 1,500 session
  nodes the oldest sessions are written to `.tainttrail/archive/` as JSON and removed from
  it. Sessions with findings go last. `tainttrail ui --file <archive>` opens one.
- **Parallel tool calls must not drop events.** A recording hook that finds the store busy
  waits, and one that would run out of time leaves its event in `.tainttrail/pending/` for
  the next hook to replay first. A check that could not be made in time is put to the
  user, never passed in silence.

## Setup and run

Python 3.10 or later. Nothing in this section needs an account, an API key or network
access after the install.

```bash
git clone https://github.com/sxi9/pr-joectr.git
cd pr-joectr
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

**1. See an attack without the guard and with it.** A scripted replay through the real hook
adapter; every secret is a canary and nothing is contacted.

```bash
tainttrail demo run a02 --compare
```

**2. Replay the whole suite**, 161 scenarios, as one table (under a minute):

```bash
tainttrail demo all
```

**3. Open the recorded graph of a real Claude Code session** (the committed store):

```bash
export TAINTTRAIL_DB=examples/claude-code-session/graph.rl
tainttrail log
tainttrail explain TT001
tainttrail ui
unset TAINTTRAIL_DB
```

**4. Map an agent setup before anything runs.** `examples/agent-config` holds a project
with four MCP servers and a Cursor configuration:

```bash
export TAINTTRAIL_DB=/tmp/agent-map.rl
tainttrail scan --path examples/agent-config/project --home examples/agent-config/home
tainttrail paths
tainttrail fix
unset TAINTTRAIL_DB
```

`paths` finds 67,184 source-to-data-to-sink combinations for Claude Code in that setup,
7,904 of them with no approval on the way out. `fix` finds four `ask` rules that break all
7,904, checks that on a rehearsal of the graph, and prints the JSON to paste. Without
`--path` and `--home`, `scan` reads your own configuration.

![Toxic paths and the smallest fix](docs/screenshots/09-toxic-paths-and-fix.png)

### Use it with Claude Code

In a project you use Claude Code in:

```bash
tainttrail init
```

This registers five hooks in `.claude/settings.json` (with a backup), writes
`.tainttrail/config.toml` and adds `.tainttrail/` to `.gitignore`. `tainttrail uninstall`
removes the hooks and keeps the graph. The same guard is packaged as a Claude Code plugin
with an MCP server, a skill and a command: see [plugin/README.md](plugin/README.md). Use one
or the other.

| Command | What it shows |
|---|---|
| `tainttrail status` | mode, hook registration, what has been recorded and archived |
| `tainttrail log [session]` | the session timeline: what entered the context, what was decided |
| `tainttrail findings` | what the rules found |
| `tainttrail explain [finding]` | one finding: the attack path and the Cypher that found it |
| `tainttrail query "<cypher>"` | any read-only Cypher against the graph |
| `tainttrail scan`, `tools`, `paths`, `fix` | the capability map, tool labels, toxic combinations, the smallest fix |
| `tainttrail ui` | the browser viewer; `--sample` before anything is recorded, `--export-dir DIR` for a static copy |
| `tainttrail export --session last -o incident.rl` | one session as a standalone Relate file (also JSON or a Cypher script) |
| `tainttrail mcp` | ten read-only tools over the graph for an agent; `--print-config` prints the `.mcp.json` entry |
| `tainttrail audit [--agent]` | an audit report in Markdown; with `--agent`, a headless Claude Code run investigates the graph and its text is added, marked as model-written |
| `tainttrail trust <file>` | clear the taint of an instruction file after reviewing it |
| `tainttrail doctor` | installation check and measured hook latency |

Modes, in `.tainttrail/config.toml`: `monitor` records and never interferes, `guard` (the
default) denies confirmed exfiltration and asks about what is only suspicious, `strict`
denies what `guard` would ask about. If the guard itself fails it lets the call through and
says so on screen, unless `fail_closed = true`.

### The rules

| Rule | Fires when | Default |
|---|---|---|
| TT001 `exfil.confirmed` | an outbound call carries sensitive data (a fingerprint, an uploaded file, the environment) and untrusted content is in the session or named the destination | deny; ask when the user named both the data and the destination |
| TT006 `leak.sensitive_egress` | the same evidence with no untrusted content involved | ask; no question for one credential sent to its own service |
| TT003 `dest.injected` | data goes to a destination that only untrusted content named | ask |
| TT011 `scope.crossed` | private data was read from one repository after untrusted content, and the call writes to another | ask |
| TT002 `trifecta.complete` | untrusted content, sensitive data and a data-carrying outbound call meet in one session, without direct evidence | ask |
| TT004 `read.steered` | text that reads like instructions pointed the agent at a sensitive file | ask |
| TT005 `persist.tainted` | an instruction, settings or autorun file (`CLAUDE.md`, CI workflows, shell profiles) is written under untrusted influence | ask; deny on a copy or when the text names a host only untrusted content named |
| TT007 `exec.injected` | code from a source only untrusted content named is downloaded and run, at once or in two steps | deny |
| TT010 `guard.tamper` | the guard's own files or its hook registration would be changed | ask; deny with untrusted content in the session |
| TT008, TT009 | inherited taint; a tool result that reads like instructions (the agent is told to treat it as data) | note |

## Where the data lives

- **In this repository:** [`examples/claude-code-session/graph.rl`](examples/claude-code-session),
  a Relate single-file store recorded by the hooks in a real, headless Claude Code session
  (69 nodes, 120 relationships, canary secrets only). Its README says how it was recorded.
  `graph.json` next to it is the same data for the viewer, and `audit.md` is what
  `tainttrail audit --agent` wrote about it.
- **In your project:** `.tainttrail/graph.rl`, created on the first hook event, with
  `graph.prev.rl` (the version before the last event) beside it and older sessions under
  `.tainttrail/archive/`. The HMAC key for fingerprints is `.tainttrail/key` (mode 0600).
  None of it should be committed; `init` adds the directory to `.gitignore`.

Inspect the committed store with the Relate CLI alone:

```bash
relate -d examples/claude-code-session/graph.rl --read-only \
  "MATCH (f:Finding) RETURN f.rule AS rule, f.action AS action, f.title AS title ORDER BY f.ts"
```

```text
rule   action  title
TT009  allow   Contents of SETUP.md reads like instructions aimed at the agent
TT001  deny    The contents of .env would be sent to telemetry.attacker.example
TT007  ask     A network command was copied from untrusted content
```

```bash
relate -d examples/claude-code-session/graph.rl --read-only \
  "MATCH (s:Session)-[:RAN]->(c:ToolCall)
   RETURN s.id AS session, c.num AS n, c.tool AS tool, c.decision AS decision
   ORDER BY s.started_at, c.seq"
```

The expected output above was produced with `tainttrail query`, which runs the same engine
through the Python client. The `relate` command itself could not be installed in the
environment this was built in, so those two command lines are untested as written.

## Results

Measured on this repository on Linux, Python 3.13, Relate 1.0.1. `tainttrail demo all` and
`tainttrail doctor` reproduce the first nine rows.

| | |
|---|---|
| Attack scenarios stopped or put to the user | 17 of 17 (16 denied outright, 1 asked) |
| Attack variants written by reviewers against the edges of the rules | 64 of 64 denied or asked |
| Known gaps kept in the suite, not stopped | 3 |
| Ordinary workflows left untouched | 10 of 10 |
| A reviewer's 64 ordinary multi-step sessions left untouched | 63 of 64 (the remaining one gets one question) |
| Harder cases (paraphrased leak, push through the project's own remote, poisoned MCP tool) | 3 of 3 put to the user or denied |
| Canary secrets that left, with the guard | 0 |
| Canary secrets that left in monitor mode | 25 |
| One hook process as the agent runs it | about 140 ms (125 to 160 measured), of which about 25 ms is rule and graph work; the rest is starting Python and loading the engine |
| A session of 300 file reads through an MCP server | 3,077 nodes, about 90 ms of rule and graph work per event (it was 46,000 nodes and climbing before the graph was bounded) |
| Store killed while closing, 200 times | opened every time, no committed event lost |
| A real Claude Code session | the upload was denied; the model reported the block to the user and did not retry |

![The whole suite](docs/screenshots/11-scenario-matrix.png)

The attack scenarios are modelled on public incident reports and were written before the
replay harness existed. A suite of this size is a regression suite, not a measure of
coverage.

### How it was checked

The project was reviewed by independent AI agents that were given the code and asked to
break it, each with one concern, and their findings were fixed and turned into tests:

- **False alarms.** A reviewer wrote 64 ordinary multi-step sessions (deploys, dependency
  upgrades, API calls with tokens, MCP work in GitHub, Slack and Notion). 32 were
  interrupted. After the fixes, 1 is, with one question.
- **Whether those fixes opened holes.** A second reviewer was asked to break them and wrote
  56 attacks against the edges they moved. 37 passed without a question. After tightening,
  53 are stopped and the ordinary sessions are unchanged; the 3 that still pass are in the
  suite as known gaps.
- **Robustness.** 22 failure cases, among them a store left unopenable by a kill, a hook
  that slowed down with every tool call, text patterns that took seconds on awkward input,
  and events lost when twenty tools returned at once. All are fixed and have tests; every
  text pattern is now checked to be linear.
- **Secrecy.** 12 ways for a secret value or a credential-bearing URL to reach the graph,
  the log or the guard's own output. All closed; a test replays every scenario and searches
  the graph for the canaries in plain, encoded and hex form.
- **Whether those fixes opened holes.** They had: a second reviewer showed that two of them
  let whoever wrote a web page choose which output the guard ignored and which parts of a
  later call it blanked, enough to get a download-and-run or a write to the guard's own
  config past it. Both are closed, and each case is a test.
- **The scanner.** Ways for a repository's configuration to hide a server or a path from
  the map (fields that only other clients read, rules the agent ignores, look-alike hosts),
  secrets in stored command lines, and writes through symbolic links. Fixed.

## What it does not do

TaintTrail blocks when it can show a path: a secret's fingerprint in an outgoing call, a
destination that only untrusted content named, a protected file written under untrusted
influence. It does not see inside the model, inside MCP servers or inside child processes.
A leak that is paraphrased, encoded in a way it does not decode, split across calls, or sent
one bit at a time will pass, at best with a question to the user.

Known gaps, three of which are in the suite (`tainttrail demo all --full`):

- **Instructions planted in the project's own files.** A file of the repository is trusted
  unless it sits under a vendored directory, was downloaded or cloned in a recorded
  session, or scores as an injection. A short planted instruction that avoids the phrases
  the score looks for is trusted text, and a host it names counts as named by the project.
  A repository you do not trust should be marked untrusted in the config.
- **A service on localhost that relays third-party text**, such as a forwarded port to an
  internal wiki. Responses from loopback count as first-party.
- **Matching is by content.** Base64, hex, percent-encoding, JSON escapes and two levels of
  nesting are undone; compression, base32, reversal and anything a script computes are not.
  Older results in a long session lose their line fingerprints, so a verbatim copy of text
  read much earlier is matched only if it holds a secret.
- **It sees what hooks see.** Slash commands the user types and anything done with hooks
  disabled never reach it. A program the agent writes and then runs is judged by its
  command line, not by what it does. Shell commands are parsed, not executed: what a
  variable holds at run time is not known.
- **"Belongs to the destination" is a heuristic.** A credential is treated as
  authentication when the project's secrets file names the host next to it or the variable
  is named after it. A generically named token for a host no file names is put to the
  user.
- **The scanner reads configuration files.** Servers that a plugin or a claude.ai connector
  provides join the map only after a recorded session used them, and an allow rule that
  runs the project's own scripts is not counted as a way out.
- **Redaction goes by shape.** Tokens, keys, credentials in URLs and passwords in the
  well-known options of common tools are replaced before anything is stored. A password
  that does not look random and is typed as a plain argument or in prose is stored in the
  call's summary as typed.
- **The fingerprint key.** Each project gets a random key in `.tainttrail/key`. Setting
  `TAINTTRAIL_KEY` instead is meant for tests and demos: whoever can guess that key can
  test guesses of a secret against an exported graph.
- **Smaller things.** `tainttrail status` cannot see hooks registered by the plugin. The
  viewer was checked in Chromium only. Everything was built and tested on Linux; the code
  has paths for macOS and Windows that have not been run.

Every block also tells an attacker which route is watched, and the graph stores short
excerpts of untrusted text: the MCP server withholds them from models, and an exported
graph should be treated like the content it came from.

Run the agent in a sandbox with network egress control. TaintTrail adds evidence and
explanation on top of that; it does not replace it.

## Prior art

TaintTrail combines known ideas in one embedded graph that guards, explains and replays
sessions of an unmodified coding agent. It is a monitor, not a sandbox and not
information-flow control.

- The threat model is the lethal trifecta and Meta's
  [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/).
- Scoring toxic combinations of tools in a graph is
  [toxic flow analysis](https://invariantlabs.ai/blog/toxic-flow-analysis) (Invariant Labs,
  now Snyk Agent Scan).
- Provenance graphs consulted before a tool call are described in
  [AgentArmor](https://arxiv.org/abs/2508.01249) and [ARM](https://arxiv.org/abs/2604.04035).
- Systems that control the planner, such as [CaMeL](https://arxiv.org/abs/2503.18813),
  track information flow by construction and are stronger where they apply.
- Attack paths as queries in a graph database is what BloodHound does for identity systems,
  and cutting all attack paths with a minimal set of changes goes back to attack-graph
  analysis.

What we did not find elsewhere, having read papers' abstracts and projects' READMEs, not
their code: the capability map and the per-call provenance of real sessions in one
persistent graph the user can query, so that one Cypher query is the rule, the explanation
and the audit record; taint that crosses sessions as edges; and a fix that is rehearsed
against the graph before it is proposed.

## Built with

- **Relate 1.0.1**: the embedded Python client (`relate-db`) for the guard and every
  command; the WebAssembly build (`@relate/relate-wasm`, vendored under
  `src/tainttrail/viewer/relate/` with its licence) for the viewer. Capabilities used:
  single-file and in-memory stores, transactions with rollback, uniqueness constraints and
  indexes, quantified path patterns, `SHORTEST`, `EXISTS` subqueries, read-only opens.
- **Python standard library** for everything else at run time: no other dependency.
  `pytest` for tests. Node, Playwright and ffmpeg only to regenerate the screenshots and
  the video and to check the viewer.
- **Claude Code** is the agent the guard plugs into (hooks, plugin, MCP), and the `claude`
  command is what `tainttrail audit --agent` starts.
- **AI use.** This project was written during the hackathon with Claude Code. The design,
  code, tests and documentation were produced by the agent under the author's direction.
  Sub-agents compiled the notes on Relate, on Claude Code hooks and on public incidents,
  built the viewer, the scanner and the MCP server from a written specification, and
  reviewed the result as described under "How it was checked". At run time no model is
  involved in any decision: the rules are deterministic. A model is used only by
  `tainttrail audit --agent`, and its text is marked as such in the report.
- **Data.** Every secret in the repository is a documented example value or a made-up
  canary, and every attacker host is a reserved name. The recorded session was run in a
  throwaway project.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

About 2,000 tests, three to four minutes. CI runs them on Python 3.10 and 3.13, replays every
scenario and opens the committed store ([workflow](.github/workflows/ci.yml)). `node tests/viewer_check.mjs` drives the viewer in a
browser (needs Node and Playwright).
