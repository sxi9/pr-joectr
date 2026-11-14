# Devpost submission text

Draft answers for the submission form. Every number is from the README, where the commands
that reproduce it are given. Check each field before sending: the form's questions could not
be read without logging in.

## Title

TaintTrail

## Tagline

An attack-path guard for AI coding agents: an embedded Relate graph of every prompt, tool
call and result that blocks a call when it would carry private data out along a path that
began in untrusted text.

## What it does and why it is useful

An agent that reads text a stranger can write, can reach private data and can send data out,
can be told by that text to leak the data. That is indirect prompt injection, and it has
happened in public: an issue that made an agent copy a private repository into a public pull
request, a web page that made one send secrets through its shell, a comment that made one
leak a key in a DNS lookup. No model refuses every time, and a permission prompt cannot tell
where a destination came from.

TaintTrail watches the tool boundary of an unmodified Claude Code. Its hooks write every
prompt, tool call and tool result into one Relate file per project. Before a call runs,
eleven rules built from Cypher path queries ask whether the call completes a path from
untrusted content to sensitive data leaving the machine. If it does, the call is denied or
put to the user, and the path that was found is stored with the query that found it. The
same graph maps the agent's configured tools before anything runs, lists the combinations
that can leak, and proposes the smallest permission change that breaks them, rehearsed in a
transaction and rolled back.

The relationships that matter: which content named a host first (the user, a project file or
a third party), which sensitive content a call's arguments carry (keyed fingerprints, also
inside base64, hex and URL encoding), which files were written under untrusted influence,
and which tools together complete a leak.

## How it uses Relate

- Mode: single file for the guard (`.tainttrail/graph.rl`), in memory in the browser viewer
  (Relate WebAssembly).
- Why: the guard is a hook, a new process for every tool call, with no server to start. One
  file per project is also the evidence: after an incident you hand over one `.rl` file. A
  single file can be replaced atomically, which is how the store survives a hook being
  killed.
- What the graph models: two layers in one graph. Session provenance (Session, ToolCall,
  Content, Entity, Chunk, Finding) written by the hooks, and a capability map (Agent, Server,
  Tool, Capability, Credential) written by `tainttrail scan`. A recorded call points at the
  tool it invoked, so one query can run from a web page through a call to the permission
  that would have stopped it.
- A persistent store recorded in a real Claude Code session is in the repository at
  `examples/claude-code-session/graph.rl`.

## Relate capabilities, third-party tools and AI tools

- Relate 1.0.1: the embedded Python client with a single-file store, transactions and
  rollback, uniqueness constraints and indexes, quantified path patterns, `SHORTEST`,
  `EXISTS` subqueries, read-only opens, and the WebAssembly build with an in-memory store
  for the viewer.
- Third-party tools: none at run time besides Relate and the Python standard library.
  pytest for the tests; Node, Playwright and ffmpeg to regenerate the screenshots and the
  video. Claude Code is the agent the guard plugs into.
- AI tools: the project was written with Claude Code during the hackathon. The design, code,
  tests, documentation, screenshots and video were produced by the agent under the author's
  direction, and independent agent reviewers were asked to break the result (see "How it was
  checked" in the README). At run time no model takes part in any decision: the rules are
  deterministic. A model is used only by `tainttrail audit --agent`, and its text is marked
  as model-written.

## Results

- 17 of 17 attack scenarios modelled on public incidents stopped or put to the user (16
  denied outright), 64 of 64 attack variants written by reviewers, 0 canary secrets leaked
  (25 leave in monitor mode).
- 73 of 74 ordinary workflows and sessions run without a question.
- 3 known gaps are kept in the suite and listed in the README.
- About 140 ms per hook process, of which about 25 ms is rule and graph work.
- About 2,000 tests; CI runs them on Python 3.10 and 3.13 and replays all 161 scenarios.

## Try it

```bash
git clone https://github.com/sxi9/pr-joectr.git && cd pr-joectr
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
tainttrail demo run a02 --compare
tainttrail demo all
TAINTTRAIL_DB=examples/claude-code-session/graph.rl tainttrail explain TT001
```

## Links

- Repository: https://github.com/sxi9/pr-joectr
- Video: `docs/demo/tainttrail-demo.mp4` in the repository (1 min 53 s). The form asks for a
  link that plays without a login, so upload the file to a video host and paste that link.
- Screenshots: `docs/screenshots/`

## Before submitting

- Make the repository public and add the topics `relate` and `relate-neo4j-hackathon`.
- Choose a licence (the rules encourage MIT or Apache-2.0) and add a `LICENSE` file. The
  vendored Relate WebAssembly files are Apache-2.0 and carry their own notice.
- The work is on `claude/nice-fermi-q7s22r`, which is the repository's only branch and so its
  default one: the README a judge sees first is this one. Rename the branch to `main` in the
  repository settings if you prefer.
