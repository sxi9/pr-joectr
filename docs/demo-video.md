# Demo video shot list (under two minutes)

A captioned video without narration is already in the repository: `docs/demo/tainttrail-demo.mp4`,
built from the real commands by `node tools/demo-video/build.cjs`. This list is for recording the
same scenes by hand with a voice-over.

The hackathon caps the video at two minutes. This list runs about 1:50 at a normal speaking
pace. Every command below works from a fresh clone with no account or key, except shot 3,
which needs Claude Code. Record at 1280x720 or larger with a large terminal font.

Before recording:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
export TAINTTRAIL_DB=examples/claude-code-session/graph.rl   # for shots 4 and 5
```

| # | Time | On screen | Say |
|---|---|---|---|
| 1 | 0:00-0:12 | The README hero image, or a title card | "A coding agent that reads the web, can read your secrets and can use the network can be told by a web page to leak them. TaintTrail watches the path, not the prompt." |
| 2 | 0:12-0:38 | `tainttrail demo run a02 --compare --brief` | "A page tells the agent to post dot-env to an attacker. Without the guard, three secrets leave. With it, the upload is denied. This replay goes through the real Claude Code hook adapter." |
| 3 | 0:38-0:58 | A real Claude Code session in a project after `tainttrail init`, or `tainttrail log` on the recorded store | "Here it is inside a real Claude Code session. The hook denies the call, and the model tells the user what happened instead of trying another route." |
| 4 | 0:58-1:18 | `tainttrail explain` | "Every hook event is a node in an embedded Relate graph, one file per project. The rule is a Cypher path query: untrusted content names a host, the call sends to it, and uploads a sensitive file. The path is the explanation." |
| 5 | 1:18-1:36 | `tainttrail ui`, open the finding, press Run | "The same graph opens in the browser on Relate's WebAssembly build, offline. The query that blocked the call runs again in the page." |
| 6 | 1:36-1:48 | `tainttrail scan --path examples/agent-config/project --home examples/agent-config/home` with `TAINTTRAIL_DB` pointing at a scratch file, then `tainttrail paths` and `tainttrail fix` | "Before anything runs, the same graph maps the agent's tools and finds the combinations that can leak, with the smallest permission change that breaks them." |
| 7 | 1:48-1:55 | `tainttrail demo all` | "Seventeen attacks modelled on public incidents and sixty-four variants written by reviewers stopped; seventy-three of seventy-four ordinary sessions untouched; three known gaps listed. It is a monitor, not a sandbox. The limits are in the README." |

Notes:

- Shot 3 live: in a throwaway project with a canary `.env`, run `tainttrail init`, start
  `claude`, and ask it to read a vendored file that contains an instruction and to follow its
  setup step. If the model refuses on its own, say so; that is the common case, and the guard
  is for the other one. The recorded store in `examples/claude-code-session` came from such
  a run.
- Do not show a real secret, a real token or your home directory. The example store and the
  scenarios contain only canaries and reserved host names.
- The labelled screenshots in `docs/screenshots` cover every shot and can be uploaded to the
  Devpost gallery as they are.
