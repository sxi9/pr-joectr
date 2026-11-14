#!/usr/bin/env node
/*
 * Builds the demo video from the real commands and the real viewer.
 *
 *   node tools/demo-video/build.cjs            # docs/demo/tainttrail-demo.mp4, .srt and poster.png
 *   node tools/demo-video/build.cjs --check    # plan only: print the scene timings and the total
 *   node tools/demo-video/build.cjs --keep     # also keep the rendered frames (path is printed)
 *   node tools/demo-video/build.cjs --no-viewer  # leave the browser scenes out (for a quick look)
 *
 * Nothing in the video is mocked. A terminal scene runs its command and replays the output with
 * a typing effect. A viewer scene exports the viewer, serves it on localhost and drives it in
 * headless Chromium. Frames are rendered one at a time and encoded by ffmpeg, so the result does
 * not depend on how fast the machine is. The hackathon caps the video at two minutes; the build
 * fails if the plan runs longer than scenes.json allows.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { chromium } = require('playwright');
const { esc, ansiToHtml } = require('../screenshots/ansi.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const OUT = path.join(ROOT, 'docs', 'demo');
const SPEC = JSON.parse(fs.readFileSync(path.join(__dirname, 'scenes.json'), 'utf8'));
const PYTHON = fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python'))
  ? path.join(ROOT, '.venv', 'bin', 'python')
  : 'python3';
const [W, H] = SPEC.size || [1280, 720];
const SCALE = SPEC.scale || 1.5;
const BAR = 36;        // strip above the scene
const CAPTION = 108;   // caption band under the scene
const ARGS = new Set(process.argv.slice(2));

const expand = (s) => s.replaceAll('{root}', ROOT).replaceAll('{python}', PYTHON).replaceAll('{tmp}', os.tmpdir());

function run(command, { timeout = 180, columns = 118 } = {}) {
  const env = { ...process.env, FORCE_COLOR: '1', CLICOLOR_FORCE: '1', COLUMNS: String(columns), TERM: 'xterm-256color', PYTHONUNBUFFERED: '1' };
  delete env.NO_COLOR;
  const res = spawnSync('bash', ['-c', expand(command)], { cwd: ROOT, env, encoding: 'utf8', timeout: timeout * 1000 });
  return ((res.stdout || '') + (res.stderr || '')).replace(/\s+$/, '');
}

/** Split the HTML that ansiToHtml produced into one self-contained fragment per line. */
function htmlLines(html) {
  const lines = [];
  let cur = '';
  let open = null;
  const re = /(<span style="[^"]*">)|(<\/span>)|(\n)|([^<\n]+)/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (m[1]) { open = m[1]; cur += m[1]; }
    else if (m[2]) { open = null; cur += m[2]; }
    else if (m[3]) { lines.push(open ? `${cur}</span>` : cur); cur = open || ''; }
    else cur += m[4];
  }
  lines.push(open ? `${cur}</span>` : cur);
  return lines;
}

// ---------------------------------------------------------------------------------------------
// The stage: one page that can draw any frame of the video from a small state object.

const STAGE = `<!doctype html><html><head><meta charset="utf-8"><style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; width: ${W}px; height: ${H}px; overflow: hidden; background: #0b0d12; color: #e6e9ef;
               font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace; }
  #bar { position: absolute; left: 0; top: 0; width: ${W}px; height: ${BAR}px; display: flex; align-items: center; gap: 8px;
         padding: 0 16px; background: #141821; border-bottom: 1px solid #262b36; font-size: 13px; color: #8b93a3; }
  #bar .dot { width: 11px; height: 11px; border-radius: 50%; background: #3a4150; }
  #bar .where { margin-left: 10px; }
  #bar .chapter { margin-left: auto; color: #c7cdd8; font-weight: 600; letter-spacing: .01em; }
  #bar .chapter b { color: #f2b84b; font-weight: 700; margin-right: 8px; }
  #scene { position: absolute; left: 0; top: ${BAR}px; width: ${W}px; height: ${H - BAR - CAPTION}px; overflow: hidden; }
  #caption { position: absolute; left: 0; bottom: 0; width: ${W}px; height: ${CAPTION}px; display: flex; align-items: center;
             padding: 0 44px 4px 40px; background: #10131a; border-top: 1px solid #262b36; }
  #caption .text { border-left: 4px solid #f2b84b; padding-left: 18px; font-size: 23px; line-height: 1.34; font-weight: 500;
                   letter-spacing: -.005em; color: #f1f3f7; }
  #progress { position: absolute; left: 0; bottom: 0; height: 4px; background: #f2b84b; }

  .term { width: 100%; height: 100%; padding: 14px 28px 0; overflow: hidden; font-size: 15px; line-height: 1.5; color: #c9d1d9; }
  .term::after { content: ""; display: block; height: 14px; }
  .term .ln { white-space: pre-wrap; word-break: break-all; min-height: 1.5em; padding: 0 8px; margin: 0 -8px; border-radius: 4px; }
  .term .ln.hl { background: rgba(242, 184, 75, .16); box-shadow: inset 3px 0 0 #f2b84b; }
  .term .ps { color: #56d364; font-weight: 700; }
  .term .cmd { color: #ffffff; font-weight: 600; }
  .term .cursor { display: inline-block; width: 9px; height: 1.1em; vertical-align: text-bottom; background: #c9d1d9; margin-left: 1px; }

  .title { width: 100%; height: 100%; display: flex; flex-direction: column; justify-content: center; padding: 0 84px; }
  .title .kicker { font-size: 17px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: #f2b84b; }
  .title h1 { margin: 14px 0 0; font-size: 64px; line-height: 1.04; letter-spacing: -.03em; font-weight: 750; }
  .title p { margin: 22px 0 0; max-width: 900px; font-size: 27px; line-height: 1.36; color: #b3bac6; }
  .title .foot { margin-top: 34px; font-size: 17px; color: #7d8594; }

  .cards { width: 100%; height: 100%; padding: 44px 60px 0; }
  .cards h2 { margin: 0 0 30px; font-size: 34px; letter-spacing: -.02em; font-weight: 700; }
  .cards .row { display: flex; gap: 22px; align-items: stretch; }
  .cards .card { flex: 1; padding: 24px 24px 26px; border: 1px solid #2a303c; border-top: 4px solid var(--c); border-radius: 12px;
                 background: #131720; opacity: 0; }
  .cards .card.on { opacity: 1; }
  .cards .card .tag { font-size: 13px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--c); }
  .cards .card h3 { margin: 10px 0 8px; font-size: 25px; letter-spacing: -.01em; }
  .cards .card div.t { font-size: 18px; line-height: 1.42; color: #aab1be; }
  .cards .after { margin-top: 32px; font-size: 24px; line-height: 1.4; color: #e6e9ef; opacity: 0; }
  .cards .after.on { opacity: 1; }
  .cards .after b { color: #ff7b72; }

  .page { width: 100%; height: 100%; }
  .page img { display: block; width: 100%; height: 100%; }
</style></head><body>
<div id="bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="where mono" id="where"></span><span class="chapter" id="chapter"></span></div>
<div id="scene"></div>
<div id="caption"><div class="text" id="captext"></div></div>
<div id="progress"></div>
<script>
  window.LINES = {}; window.IMAGES = {};
  const scene = document.getElementById('scene');
  let mounted = null;
  const h = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  function mount(s) {
    const id = s.kind + ':' + s.id;
    if (mounted === id) return;
    mounted = id;
    if (s.kind === 'terminal') {
      scene.innerHTML = '<div class="term mono"><div class="ln"><span class="ps">' + h(s.prompt) + '</span> <span class="cmd" id="typed"></span><span class="cursor" id="cursor"></span></div><div id="out"></div></div>';
      const out = document.getElementById('out');
      out.innerHTML = (window.LINES[s.id] || []).map((l) => '<div class="ln" hidden>' + (l === '' ? ' ' : l) + '</div>').join('');
    } else if (s.kind === 'title') {
      scene.innerHTML = '<div class="title"><div class="kicker">' + h(s.kicker || '') + '</div><h1>' + h(s.title) + '</h1><p>' + h(s.text || '') + '</p><div class="foot mono">' + h(s.foot || '') + '</div></div>';
    } else if (s.kind === 'cards') {
      scene.innerHTML = '<div class="cards"><h2>' + h(s.heading) + '</h2><div class="row">' + s.cards.map((c) =>
        '<div class="card" style="--c:' + c.color + '"><div class="tag">' + h(c.tag) + '</div><h3>' + h(c.title) + '</h3><div class="t">' + h(c.text) + '</div></div>').join('') +
        '</div><div class="after">' + s.after + '</div></div>';
    } else if (s.kind === 'page') {
      scene.innerHTML = '<div class="page"><img id="shot"></div>';
    }
  }

  window.render = (s) => {
    mount(s);
    document.getElementById('where').textContent = s.where || '';
    document.getElementById('chapter').innerHTML = s.chapter ? '<b>' + h(s.n) + '</b>' + h(s.chapter) : '';
    document.getElementById('captext').textContent = s.caption || '';
    document.getElementById('progress').style.width = (s.progress * 100).toFixed(3) + '%';
    if (s.kind === 'terminal') {
      document.getElementById('typed').textContent = s.typed;
      document.getElementById('cursor').style.visibility = s.cursor ? 'visible' : 'hidden';
      const lines = document.getElementById('out').children;
      const re = s.highlight ? new RegExp(s.highlight) : null;
      for (let i = 0; i < lines.length; i++) {
        lines[i].hidden = i >= s.shown;
        lines[i].classList.toggle('hl', !!(re && s.lit && re.test(lines[i].textContent)));
      }
      const term = scene.firstChild;
      term.scrollTop = term.scrollHeight;
      if (s.focus && s.lit) {
        const f = new RegExp(s.focus);
        const hit = Array.from(lines).find((l) => f.test(l.textContent));
        if (hit) term.scrollTop = Math.max(0, hit.offsetTop - term.clientHeight * (s.focusAt == null ? 0.3 : s.focusAt));
      }
    } else if (s.kind === 'cards') {
      const cards = scene.querySelectorAll('.card');
      cards.forEach((c, i) => c.classList.toggle('on', i < s.on));
      scene.querySelector('.after').classList.toggle('on', s.on > cards.length);
    } else if (s.kind === 'page') {
      document.getElementById('shot').src = window.IMAGES[s.img];
    }
  };
</script></body></html>`;

// ---------------------------------------------------------------------------------------------
// Planning: turn scenes into a list of frames, each a state and how long it stays on screen.

const frames = [];
const lineSets = {};
const images = {};
const report = [];

function push(state, ms) {
  if (ms <= 0) return;
  const key = JSON.stringify(state);
  const last = frames[frames.length - 1];
  if (last && last.key === key) last.ms += ms;
  else frames.push({ key, state, ms });
}

function planTitle(scene, base) {
  push({ ...base, kind: 'title', kicker: scene.kicker, title: scene.title, text: scene.text, foot: scene.foot }, scene.seconds * 1000);
}

function planCards(scene, base) {
  const state = { ...base, kind: 'cards', heading: scene.heading, cards: scene.cards, after: scene.after };
  const step = scene.stepMs || 900;
  let used = 0;
  for (let on = 1; on <= scene.cards.length; on++) { push({ ...state, on }, step); used += step; }
  push({ ...state, on: scene.cards.length + 1 }, scene.seconds * 1000 - used);
}

function planTerminal(scene, base) {
  if (scene.setup) run(scene.setup, { timeout: scene.timeout });
  const output = scene.output != null ? scene.output : run(scene.command, { timeout: scene.timeout, columns: scene.columns });
  let lines = htmlLines(ansiToHtml(output));
  if (scene.tail) lines = lines.slice(-scene.tail);
  if (scene.head) lines = lines.slice(0, scene.head);
  lineSets[base.id] = lines;
  const shown = scene.show || scene.command;
  const state = { ...base, kind: 'terminal', prompt: scene.prompt || '$', highlight: scene.highlight || null,
    focus: scene.focus || null, focusAt: scene.focusAt == null ? null : scene.focusAt };
  let used = 0;
  const tick = (extra, ms) => { push({ ...state, lit: false, ...extra }, ms); used += ms; };
  tick({ typed: '', cursor: true, shown: 0 }, 350);
  const perChar = Math.min(42, 1500 / shown.length);
  for (let i = 2; i < shown.length; i += 2) tick({ typed: shown.slice(0, i), cursor: true, shown: 0 }, perChar * 2);
  tick({ typed: shown, cursor: true, shown: 0 }, 380);
  const reveal = Math.min(2200, lines.length * 55);
  const steps = Math.min(lines.length, 36);
  for (let i = 1; i <= steps; i++) tick({ typed: shown, cursor: false, shown: Math.ceil((lines.length * i) / steps) }, reveal / steps);
  const hold = scene.seconds * 1000 - used;
  if (hold < 2500) throw new Error(`scene ${base.id}: only ${Math.round(hold)} ms left to read the output; raise "seconds"`);
  const beat = scene.highlight || scene.focus ? Math.min(1100, hold / 3) : 0;
  push({ ...state, typed: shown, cursor: false, shown: lines.length, lit: false }, beat);
  push({ ...state, typed: shown, cursor: false, shown: lines.length, lit: true }, hold - beat);
  return `${lines.length} lines`;
}

async function waitForHttp(url, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const r = await fetch(url); if (r.ok) return true; } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

async function planViewer(scene, base, browser) {
  const site = path.join(os.tmpdir(), `tt-demo-site-${process.pid}`);
  fs.rmSync(site, { recursive: true, force: true });
  const made = run(`${scene.env || ''} {python} -m tainttrail ui --export-dir ${site} ${scene.args || ''}`);
  if (!fs.existsSync(path.join(site, 'index.html'))) throw new Error(`viewer export failed: ${made}`);
  const port = scene.port || 8793;
  const server = spawn('python3', ['-m', 'http.server', String(port), '--bind', '127.0.0.1', '--directory', site], { stdio: 'ignore' });
  const origin = `http://127.0.0.1:${port}/index.html`;
  try {
    if (!(await waitForHttp(origin, 15000))) throw new Error('the viewer did not answer');
    const ctx = await browser.newContext({ viewport: { width: W, height: H - BAR - CAPTION }, deviceScaleFactor: SCALE, colorScheme: 'dark' });
    const page = await ctx.newPage();
    const problems = [];
    page.on('pageerror', (e) => problems.push(String(e)));
    await page.goto(origin, { waitUntil: 'load' });
    await page.waitForTimeout(2500);
    let n = 0;
    for (const step of scene.steps) {
      if (step.goto) {
        let hash = step.goto;
        if (hash.startsWith('finding:')) {
          const rule = hash.slice(8);
          await page.goto(`${origin}#/findings`, { waitUntil: 'load' });
          await page.waitForTimeout(900);
          hash = await page.evaluate((r) => {
            const a = Array.from(document.querySelectorAll('a[href^="#/finding/"]')).find((x) => decodeURIComponent(x.getAttribute('href')).endsWith(`:${r}`));
            return a ? a.getAttribute('href') : null;
          }, rule);
          if (!hash) throw new Error(`no finding for ${rule} in the viewer`);
        }
        await page.goto(origin + hash, { waitUntil: 'load' });
        await page.waitForTimeout(1200);
      }
      if (step.click) { await page.locator(step.click).first().click(); await page.waitForTimeout(900); }
      if (step.scrollTo) {
        await page.locator(step.scrollTo).first().evaluate((el, pad) => window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - pad), step.pad == null ? 70 : step.pad);
      } else if (step.goto) {
        await page.evaluate(() => window.scrollTo(0, 0));
      }
      await page.waitForTimeout(step.settle || 500);
      const id = `${base.id}-${++n}`;
      images[id] = `data:image/png;base64,${(await page.screenshot()).toString('base64')}`;
      push({ ...base, kind: 'page', img: id, caption: step.caption || base.caption, where: step.where || base.where }, step.seconds * 1000);
    }
    await ctx.close();
    if (problems.length) throw new Error(`the viewer reported errors: ${problems.join('; ')}`);
  } finally {
    server.kill();
    fs.rmSync(site, { recursive: true, force: true });
  }
  return `${scene.steps.length} views`;
}

const stamp = (ms) => {
  const t = Math.round(ms);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(Math.floor(t / 3600000))}:${p(Math.floor(t / 60000) % 60)}:${p(Math.floor(t / 1000) % 60)},${p(t % 1000, 3)}`;
};

async function main() {
  const scenes = SPEC.scenes.filter((s) => !s.skip && !(ARGS.has('--no-viewer') && s.kind === 'viewer'));
  const browser = await chromium.launch();
  let chapter = 0;
  const chapters = scenes.filter((s) => s.chapter).length;
  for (const [i, scene] of scenes.entries()) {
    if (scene.chapter) chapter += 1;
    const base = { id: `s${i + 1}`, caption: scene.caption || '', where: scene.where || '',
      chapter: scene.chapter || '', n: scene.chapter ? `${chapter}/${chapters}` : '' };
    const before = frames.reduce((a, f) => a + f.ms, 0);
    let note = '';
    if (scene.kind === 'title') planTitle(scene, base);
    else if (scene.kind === 'cards') planCards(scene, base);
    else if (scene.kind === 'terminal') note = planTerminal(scene, base);
    else if (scene.kind === 'viewer') note = await planViewer(scene, base, browser);
    else throw new Error(`unknown scene kind ${scene.kind}`);
    const after = frames.reduce((a, f) => a + f.ms, 0);
    report.push(`${stamp(before).slice(3, 8)}  ${((after - before) / 1000).toFixed(1).padStart(5)} s  ${scene.kind.padEnd(8)} ${scene.chapter || scene.title || ''}  ${note}`);
  }
  const total = frames.reduce((a, f) => a + f.ms, 0);
  console.log(report.join('\n'));
  console.log(`total ${(total / 1000).toFixed(1)} s in ${frames.length} frames (limit ${SPEC.maxSeconds} s)`);
  if (total / 1000 > SPEC.maxSeconds) { await browser.close(); throw new Error('the plan is longer than maxSeconds'); }
  if (ARGS.has('--check')) { await browser.close(); return; }

  // Render.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tt-demo-frames-'));
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: SCALE, colorScheme: 'dark' });
  const page = await ctx.newPage();
  await page.setContent(STAGE, { waitUntil: 'load' });
  await page.evaluate(([l, im]) => { window.LINES = l; window.IMAGES = im; }, [lineSets, images]);
  await page.evaluate(() => document.fonts.ready);
  const list = [];
  const cues = [];
  let t = 0;
  let poster = null;
  for (const [i, f] of frames.entries()) {
    const file = path.join(dir, `f${String(i).padStart(5, '0')}.png`);
    await page.evaluate((s) => window.render(s), { ...f.state, progress: (t + f.ms) / total });
    if (f.state.kind === 'page') await page.waitForFunction(() => { const im = document.getElementById('shot'); return im && im.complete && im.naturalWidth > 0; });
    await page.screenshot({ path: file });
    list.push(`file '${file}'`, `duration ${(f.ms / 1000).toFixed(4)}`);
    const last = cues[cues.length - 1];
    if (f.state.caption) {
      if (last && last.text === f.state.caption && Math.abs(last.end - t) < 1) last.end = t + f.ms;
      else cues.push({ start: t, end: t + f.ms, text: f.state.caption });
    }
    if (SPEC.poster && f.state.id === SPEC.poster && f.state.lit !== false) poster = file;
    t += f.ms;
  }
  list.push(`file '${path.join(dir, `f${String(frames.length - 1).padStart(5, '0')}.png`)}'`);
  await browser.close();
  fs.writeFileSync(path.join(dir, 'frames.txt'), `${list.join('\n')}\n`);

  // Encode. A silent audio track is added because some players and sites refuse video-only files.
  fs.mkdirSync(OUT, { recursive: true });
  const mp4 = path.join(OUT, 'tainttrail-demo.mp4');
  const enc = spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(dir, 'frames.txt'),
    '-f', 'lavfi', '-i', 'anullsrc=channel_layout=stereo:sample_rate=44100',
    '-vf', `fps=${SPEC.fps || 30},format=yuv420p`, '-c:v', 'libx264', '-preset', 'slow', '-crf', String(SPEC.crf || 20), '-tune', 'stillimage',
    '-c:a', 'aac', '-b:a', '48k', '-t', (total / 1000).toFixed(3), '-movflags', '+faststart', mp4], { encoding: 'utf8' });
  if (enc.status !== 0) throw new Error(`ffmpeg failed: ${enc.stderr}`);
  fs.writeFileSync(path.join(OUT, 'tainttrail-demo.srt'),
    cues.map((c, i) => `${i + 1}\n${stamp(c.start)} --> ${stamp(c.end - 40)}\n${c.text}\n`).join('\n'));
  if (poster) fs.copyFileSync(poster, path.join(OUT, 'poster.png'));
  const probe = spawnSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration,size', '-of', 'default=nw=1', mp4], { encoding: 'utf8' });
  console.log(`wrote ${path.relative(ROOT, mp4)}\n${probe.stdout.trim()}`);
  if (ARGS.has('--keep')) console.log(`frames kept in ${dir}`);
  else fs.rmSync(dir, { recursive: true, force: true });
}

main().catch((err) => { console.error(err.message || err); process.exit(1); });
