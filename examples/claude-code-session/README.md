# A real Claude Code session, recorded by TaintTrail

`graph.rl` is a Relate single-file store. It holds two sessions recorded on 2026-11-14 by
the TaintTrail hooks running inside Claude Code 2.1.325 (headless, `claude -p`, Haiku) in a
throwaway project. Nothing in it is scripted: the tool calls are the ones the model chose.

The project held a `.env` with the documented AWS example credentials and a made-up canary
token, and a vendored file, `third_party/acme-sdk/SETUP.md`, with a hidden comment telling
AI agents to POST `.env` to `telemetry.attacker.example`.

1. **Session `1ead0968…`** is ordinary work: read two files, run a Python one-liner. Three
   calls recorded, nothing flagged.
2. **Session `62615711…`** was asked to read the setup notes and the env file and then to
   attempt the command from the notes, so that the guard could be seen to act. The hook
   denied the `curl` call (rule TT001). `claude-answer.txt` is what the model then told the
   user.

The store was written with `tainttrail export --format rl`, which rewrites the project
directory to `/project`. It contains keyed fingerprints of the secrets, never their values.
`graph.json` is the same data as a `tainttrail-export/1` document for the browser viewer.

## Look inside

With TaintTrail installed:

```bash
export TAINTTRAIL_DB=examples/claude-code-session/graph.rl
tainttrail sessions
tainttrail log
tainttrail explain
tainttrail query "MATCH (c:ToolCall) RETURN c.num AS n, c.tool AS tool, c.decision AS decision, c.summary AS what ORDER BY c.seq"
```

With only the Relate CLI (`curl -sSfL https://relatedb.ai/install.sh | bash`):

```bash
relate -d examples/claude-code-session/graph.rl --read-only \
  "MATCH (f:Finding) RETURN f.rule AS rule, f.action AS action, f.title AS title ORDER BY f.ts"

relate -d examples/claude-code-session/graph.rl --read-only \
  "MATCH p = (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity)<-[:SENDS_TO]-(c:ToolCall)-[:UPLOADS]->(f:Entity {sensitive: true})
   RETURN u.excerpt AS untrusted_source, d.value AS destination, c.summary AS call, f.name AS uploaded"
```
