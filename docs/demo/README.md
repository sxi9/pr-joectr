# Demo video

`tainttrail-demo.mp4` is a 1 minute 53 second walk through the project, with the captions
burned in (and separately in `tainttrail-demo.srt`). It has no narration.

Nothing in it is mocked or recorded by hand. `tools/demo-video/build.cjs` runs the real
commands, replays their output with a typing effect, drives the real viewer in headless
Chromium, renders every frame and encodes the result with ffmpeg:

```bash
node tools/demo-video/build.cjs           # needs Node, Playwright and ffmpeg
node tools/demo-video/build.cjs --check   # print the scene timings only
```

The scenes and captions are in `tools/demo-video/scenes.json`. The build fails if the plan
runs longer than the limit set there (the hackathon allows two minutes).

| Time | Scene | What is on screen |
|---|---|---|
| 0:00 | Title | |
| 0:05 | The problem | three ordinary abilities that together make a leak |
| 0:15 | The same attack, twice | `tainttrail demo run a02 --compare --brief` |
| 0:33 | A real Claude Code session | `tainttrail log` on the recorded store, and the model's reply |
| 0:49 | The path is the explanation | `tainttrail explain TT001` |
| 1:06 | The same graph, in the browser | `tainttrail ui`: overview, attack path, the stored query run in the page |
| 1:24 | Before anything runs | `tainttrail fix`, after `tainttrail scan` of `examples/agent-config` |
| 1:37 | Results | `tainttrail demo all` |
| 1:47 | Closing card | |

To record it yourself with a voice-over instead, `docs/demo-video.md` is a shot list with
the same scenes and a script.
