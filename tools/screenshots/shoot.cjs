#!/usr/bin/env node
/*
 * Regenerates the labelled screenshots in docs/screenshots/.
 *
 *   node tools/screenshots/shoot.cjs            # every shot in shots.json
 *   node tools/screenshots/shoot.cjs 02 05      # only the shots whose id starts with 02 or 05
 *
 * Each shot is either a terminal command (its output is rendered in a terminal frame)
 * or a web page (captured, then framed). Every image carries its label in a banner at
 * the top, and docs/screenshots/README.md is rewritten as a gallery of all of them.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { chromium } = require('playwright');
const { esc, ansiToHtml } = require('./ansi.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const OUT = path.join(ROOT, 'docs', 'screenshots');
const MANIFEST = path.join(__dirname, 'shots.json');
const PYTHON = fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python'))
  ? path.join(ROOT, '.venv', 'bin', 'python')
  : 'python3';

function frame({ id, label, note, body, width }) {
  const date = new Date().toISOString().slice(0, 10);
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0b0d12; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #e6e9ef; }
  .wrap { width: ${width}px; padding: 20px; }
  .banner { display: flex; align-items: baseline; gap: 14px; padding: 14px 18px; border: 1px solid #262b36; border-bottom: 0;
            border-radius: 12px 12px 0 0; background: linear-gradient(180deg, #171b25, #12151d); }
  .num { font: 700 13px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #0b0d12; background: #f2b84b; padding: 5px 8px; border-radius: 6px; }
  .label { font-size: 19px; font-weight: 650; letter-spacing: -.01em; }
  .meta { margin-left: auto; font: 12px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #7d8594; white-space: nowrap; }
  .note { padding: 0 18px 12px 18px; border: 1px solid #262b36; border-top: 0; border-bottom: 0; background: #12151d; color: #a4acba; font-size: 14px; line-height: 1.45; }
  .body { border: 1px solid #262b36; border-radius: 0 0 12px 12px; overflow: hidden; background: #0f1218; }
  .term-bar { display: flex; gap: 7px; align-items: center; padding: 10px 14px; background: #161a23; border-bottom: 1px solid #262b36; }
  .dot { width: 11px; height: 11px; border-radius: 50%; background: #3a4150; }
  .cmd { margin-left: 10px; font: 12.5px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: #8b93a3; }
  pre { margin: 0; padding: 16px 18px 20px; font: 13.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; white-space: pre-wrap; word-break: break-word; color: #c9d1d9; }
  img { display: block; width: 100%; }
  </style></head><body><div class="wrap">
  <div class="banner"><span class="num">${esc(id)}</span><span class="label">${esc(label)}</span><span class="meta">TaintTrail &middot; ${date}</span></div>
  ${note ? `<div class="note">${esc(note)}</div>` : ''}
  <div class="body">${body}</div>
  </div></body></html>`;
}

function expand(s) {
  return s.replaceAll('{root}', ROOT).replaceAll('{python}', PYTHON).replaceAll('{tmp}', os.tmpdir());
}

function runCommand(shot) {
  const env = { ...process.env, FORCE_COLOR: '1', CLICOLOR_FORCE: '1', COLUMNS: String(shot.columns || 110), TERM: 'xterm-256color', PYTHONUNBUFFERED: '1' };
  delete env.NO_COLOR;
  if (shot.setup) spawnSync('bash', ['-c', expand(shot.setup)], { cwd: ROOT, env, encoding: 'utf8' });
  const res = spawnSync('bash', ['-c', expand(shot.command)], { cwd: expand(shot.cwd || ROOT), env, encoding: 'utf8', timeout: (shot.timeout || 120) * 1000 });
  let out = (res.stdout || '') + (res.stderr || '');
  if (shot.tail) out = out.split('\n').slice(-shot.tail).join('\n');
  if (shot.head) out = out.split('\n').slice(0, shot.head).join('\n');
  return out.replace(/\s+$/, '') + '\n';
}

async function waitForHttp(url, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const r = await fetch(url); if (r.ok) return true; } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function main() {
  const filters = process.argv.slice(2);
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const shots = manifest.shots.filter((s) => filters.length === 0 || filters.some((f) => s.id.startsWith(f)));
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const failures = [];

  for (const shot of shots) {
    const file = `${shot.id}-${shot.name}.png`;
    const width = shot.width || 1280;
    let server = null;
    try {
      let body;
      if (shot.kind === 'terminal') {
        const out = runCommand(shot);
        const shown = shot.show || shot.command;
        body = `<div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="cmd">$ ${esc(shown)}</span></div><pre>${ansiToHtml(out)}</pre>`;
      } else if (shot.kind === 'page') {
        if (shot.setup) spawnSync('bash', ['-c', expand(shot.setup)], { cwd: ROOT, encoding: 'utf8' });
        if (shot.serve) {
          server = spawn('bash', ['-c', expand(shot.serve)], { cwd: ROOT, stdio: 'ignore', detached: true });
          if (!(await waitForHttp(shot.url, 20000))) throw new Error(`server did not answer at ${shot.url}`);
        }
        const ctx = await browser.newContext({ viewport: { width: shot.viewport?.[0] || 1280, height: shot.viewport?.[1] || 760 }, deviceScaleFactor: 2, colorScheme: shot.scheme || 'dark' });
        const page = await ctx.newPage();
        await page.goto(shot.url, { waitUntil: 'load' });
        if (shot.waitFor) await page.waitForSelector(shot.waitFor, { timeout: 30000 });
        for (const step of shot.steps || []) {
          if (step.click) await page.click(step.click);
          if (step.fill) await page.fill(step.fill[0], step.fill[1]);
          if (step.press) await page.keyboard.press(step.press);
          if (step.waitFor) await page.waitForSelector(step.waitFor, { timeout: 30000 });
          if (step.wait) await page.waitForTimeout(step.wait);
        }
        await page.waitForTimeout(shot.settle || 400);
        const png = await page.screenshot({ fullPage: !!shot.fullPage });
        await ctx.close();
        body = `<img src="data:image/png;base64,${png.toString('base64')}">`;
      } else {
        throw new Error(`unknown kind ${shot.kind}`);
      }
      const ctx = await browser.newContext({ viewport: { width: width + 40, height: 400 }, deviceScaleFactor: 2 });
      const page = await ctx.newPage();
      await page.setContent(frame({ id: shot.id, label: shot.label, note: shot.note, body, width }), { waitUntil: 'load' });
      await page.locator('.wrap').screenshot({ path: path.join(OUT, file) });
      await ctx.close();
      console.log(`ok   ${file}  ${shot.label}`);
    } catch (err) {
      failures.push(`${shot.id}: ${err.message}`);
      console.log(`FAIL ${file}  ${err.message}`);
    } finally {
      if (server) { try { process.kill(-server.pid); } catch (_) { /* already gone */ } }
    }
  }
  await browser.close();

  // Gallery: every shot in the manifest whose image exists.
  const lines = ['# Screenshots', '', 'Regenerated by `node tools/screenshots/shoot.cjs`. Each image carries its label; the list below is in build order.', ''];
  for (const shot of manifest.shots) {
    const file = `${shot.id}-${shot.name}.png`;
    if (!fs.existsSync(path.join(OUT, file))) continue;
    lines.push(`## ${shot.id} · ${shot.label}`, '');
    if (shot.note) lines.push(shot.note, '');
    lines.push(`![${shot.label}](${file})`, '');
  }
  fs.writeFileSync(path.join(OUT, 'README.md'), lines.join('\n'));
  if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
}

main().catch((err) => { console.error(err); process.exit(1); });
