// app.js: starts the engine, loads one export into it, and routes between the views.
//
// The page holds no copy of the graph's content for display. After an export is loaded into
// Relate (in worker.js), every view asks the engine with Cypher and renders what comes back.

import { createClient } from './db.js';
import { h, clear, fmtInt, fmtMs, fmtTime, plural } from './dom.js';
import { refusal, hiddenWrite, changedGraph } from './cypher.js';
import { GRAPH_NODES, GRAPH_RELS } from './queries.js';
import { queryLog, emptyState } from './ui.js';
import { overviewView } from './views/overview.js';
import { sessionView } from './views/session.js';
import { findingView, findingsView } from './views/finding.js';
import { mapView } from './views/map.js';
import { consoleView } from './views/console.js';

const FORMAT = 'tainttrail-export/1';
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
const main = $('view');

const state = {
  db: null,
  engine: null, // { version, initMs }
  meta: null, // the export's own header: project, exported_at, version, session
  source: '', // where the loaded graph came from, in words
  counts: null, // { nodes, rels } as counted by the engine
  lastSession: null,
};

// ---- status bar -------------------------------------------------------------------------------

function setEngineStatus(kind, words) {
  $('status-dot').dataset.kind = kind;
  $('status-engine').textContent = words;
}

function showStats(stats) {
  const item = $('status-query');
  if (!stats.statements) return;
  item.hidden = false;
  clear(item).append(`last query ${fmtMs(stats.lastMs)}`, h('span', { class: 'status-extra' }, ` \u00b7 ${plural(stats.statements, 'query', 'queries')}`));
  item.title = stats.lastStatement.trim().slice(0, 400);
  if (stats.restarts) setEngineStatus('warn', `Relate WASM ${state.engine?.version ?? ''}: restarted ${plural(stats.restarts, 'time')}`);
}

function showGraphStatus() {
  const graph = $('status-graph');
  const source = $('status-source');
  const project = $('project');
  if (!state.counts) {
    graph.hidden = true;
    source.hidden = true;
    project.hidden = true;
    return;
  }
  graph.hidden = false;
  clear(graph).append(`${plural(state.counts.nodes, 'node')} \u00b7 ${plural(state.counts.rels, 'relationship')}`, h('span', { class: 'status-extra' }, ' in Relate WASM'));
  source.hidden = false;
  const exported = state.meta?.exported_at ? `, exported ${String(state.meta.exported_at).replace('T', ' ').replace('Z', ' UTC')}` : '';
  source.textContent = `${state.source}${exported}`;
  const name = state.meta?.project ? String(state.meta.project) : '';
  project.hidden = !name;
  project.textContent = name;
  project.title = name ? `Project: ${name}` : '';
}

// ---- loading an export ------------------------------------------------------------------------

/** Why a parsed file is not an export this viewer can show, or null. */
function exportProblem(doc) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return 'The file is not a JSON object.';
  const format = doc.meta && typeof doc.meta === 'object' ? doc.meta.format : undefined;
  if (format !== FORMAT) {
    return `This is not a TaintTrail export: expected the format "${FORMAT}"${typeof format === 'string' ? `, found "${format.slice(0, 60)}"` : ''}. Create one with: tainttrail export --out graph.json`;
  }
  if (!Array.isArray(doc.nodes) || !Array.isArray(doc.rels)) return 'The export has no "nodes" and "rels" lists.';
  if (doc.nodes.length > 250_000 || doc.rels.length > 1_000_000) return 'The export is too large for the browser viewer (more than 250,000 nodes or 1,000,000 relationships). Export one session instead: tainttrail export --session last';
  return null;
}

async function loadExport(doc, source) {
  const problem = exportProblem(doc);
  if (problem) throw new Error(problem);
  document.body.dataset.state = 'loading';
  setEngineStatus('busy', `Relate WASM ${state.engine.version}: loading the graph`);
  const seeded = await state.db.seed({ nodes: doc.nodes, rels: doc.rels });
  // Count with the engine, not from the file: the status bar says what Relate holds.
  const nodes = (await state.db.run(GRAPH_NODES)).rows[0].nodes;
  const rels = (await state.db.run(GRAPH_RELS)).rows[0].rels;
  state.meta = doc.meta;
  state.source = source;
  state.counts = { nodes, rels };
  state.lastSession = null;
  setEngineStatus('ok', `Relate WASM ${state.engine.version}`);
  $('status-engine').title = `In-memory graph database running in this tab. Engine started in ${fmtMs(state.engine.initMs)}, graph loaded in ${fmtMs(seeded.ms)} with ${fmtInt(seeded.statements)} statements.`;
  showGraphStatus();
  document.body.dataset.state = 'ready';
}

async function openFile(file) {
  try {
    if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name} is ${Math.round(file.size / 1024 / 1024)} MB; the viewer opens exports up to 64 MB.`);
    let doc;
    try {
      doc = JSON.parse(await file.text());
    } catch {
      throw new Error(`${file.name} is not valid JSON.`);
    }
    await loadExport(doc, file.name);
    navigate('#/');
  } catch (error) {
    await failedToOpen(error.message);
  }
}

/**
 * A file could not be opened. If the graph that was on screen is still in the engine (the new
 * file was refused before anything was loaded), keep it and say what went wrong; otherwise
 * there is nothing to show but the start screen.
 */
async function failedToOpen(message) {
  let intact = false;
  if (state.counts) {
    try {
      intact = (await state.db.run(GRAPH_NODES)).rows[0].nodes === state.counts.nodes;
    } catch {
      intact = false;
    }
  }
  if (!intact) {
    showStart(message);
    return;
  }
  setEngineStatus('ok', `Relate WASM ${state.engine.version}`);
  document.body.dataset.state = 'ready';
  main.querySelector('.alert-open')?.remove();
  const notice = h('p', { class: 'alert alert-open', role: 'alert' }, h('span', null, `${message} The graph that was open is still shown.`),
    h('button', { type: 'button', class: 'btn btn-small', on: { click: () => notice.remove() } }, 'Dismiss'));
  main.prepend(notice);
}

async function loadSample() {
  try {
    const response = await fetch('./sample/graph.json', { cache: 'no-store' });
    if (!response.ok) throw new Error('The sample graph is not part of this copy of the viewer.');
    await loadExport(await response.json(), 'sample graph (synthetic data)');
    navigate('#/');
  } catch (error) {
    await failedToOpen(error.message);
  }
}

/** The screen shown when there is no graph: choose a file, drop one, or load the sample. */
function showStart(problem = null) {
  state.counts = null;
  state.meta = null;
  showGraphStatus();
  if (state.engine) setEngineStatus('ok', `Relate WASM ${state.engine.version}`);
  document.body.dataset.state = 'empty';
  main.dataset.view = 'start';
  document.title = 'TaintTrail viewer';
  setTabs(null);
  clear(main).append(h('section', { class: 'start' },
    h('h1', { id: 'page-title', tabindex: '-1' }, 'Open a TaintTrail export'),
    h('p', { class: 'lede' }, 'The viewer replays a recorded agent session graph in this tab, on Relate\u2019s WebAssembly build. The file is read here and is not sent anywhere.'),
    problem ? h('p', { class: 'alert', role: 'alert' }, problem) : null,
    h('div', { class: 'dropzone', id: 'dropzone' },
      h('p', { class: 'dropzone-title' }, 'Drop an export here'),
      h('p', { class: 'muted' }, 'or'),
      h('div', { class: 'start-actions' },
        h('button', { type: 'button', class: 'btn btn-primary', id: 'choose-file', on: { click: () => $('file-input').click() } }, 'Choose a file'),
        h('button', { type: 'button', class: 'btn', id: 'load-sample', on: { click: loadSample } }, 'Load sample'))),
    h('p', { class: 'muted start-hint' }, 'Create an export with ', h('code', null, 'tainttrail export --out graph.json'),
      ', or run ', h('code', null, 'tainttrail ui'), ' to open a project\u2019s graph directly. The sample is a scripted session with synthetic data.')));
}

// ---- routing ------------------------------------------------------------------------------------

const VIEWS = {
  overview: { tab: 'overview', title: 'Overview', render: overviewView },
  session: { tab: 'session', title: 'Timeline', render: sessionView },
  findings: { tab: 'findings', title: 'Attack paths', render: findingsView },
  finding: { tab: 'findings', title: 'Attack path', render: findingView },
  map: { tab: 'map', title: 'Capability map', render: mapView },
  console: { tab: 'console', title: 'Console', render: consoleView },
};

function safeDecode(part) {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

function parseRoute() {
  let raw = location.hash.replace(/^#/, '');
  if (!raw.startsWith('/')) raw = '/'; // "#view" and other anchors inside the page are not routes
  const cut = raw.indexOf('?');
  const path = cut === -1 ? raw : raw.slice(0, cut);
  const query = new URLSearchParams(cut === -1 ? '' : raw.slice(cut + 1));
  const parts = path.split('/').filter(Boolean).map(safeDecode);
  const name = parts.length === 0 ? 'overview' : parts[0];
  return { name: Object.hasOwn(VIEWS, name) ? name : 'missing', arg: parts.length > 1 ? parts.slice(1).join('/') : null, query };
}

function setTabs(tab) {
  for (const link of document.querySelectorAll('#tabs a')) {
    if (link.dataset.tab === tab) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  // The Timeline tab returns to the session that was last looked at.
  const timeline = document.querySelector('#tabs a[data-tab="session"]');
  timeline.setAttribute('href', state.lastSession ? `#/session/${encodeURIComponent(state.lastSession)}` : '#/session');
}

function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash; // the hashchange listener renders
}

/**
 * Run a statement the viewer did not write (typed in the console, or stored in an export).
 *
 * Three things keep the graph as it was loaded. Write clauses are refused before they run.
 * A result whose counters show a change makes the viewer load the export again. And when a
 * write word sits inside a string or a comment, where only the engine knows for certain what
 * is text and what is code, the export is loaded again after the statement whatever the
 * counters say.
 */
async function runGuarded(statement, params = null, options = {}) {
  const why = refusal(statement);
  if (why) throw Object.assign(new Error(why), { refused: true });
  const unsure = hiddenWrite(statement);
  let envelope;
  try {
    envelope = await state.db.run(statement, params, options);
  } catch (error) {
    // db.js has already replaced the worker and loaded the export again; say so in plain words.
    if (error.trap) {
      throw Object.assign(new Error(`That statement stopped the engine (${error.message}). It was restarted and the graph loaded again.`), { refused: true });
    }
    if (error.timeout) throw Object.assign(new Error(error.message), { refused: true });
    if (unsure) await state.db.reload(); // a statement that failed half way may have committed part of its work
    throw error;
  }
  if (changedGraph(envelope)) {
    await state.db.reload();
    throw Object.assign(new Error('That statement changed the graph, so the export was loaded again. The viewer is read-only.'), { refused: true });
  }
  if (unsure) {
    await state.db.reload();
    envelope.reloaded = true;
  }
  return envelope;
}

let renderToken = 0;
let firstRender = true;

async function render() {
  if (!state.counts) return; // nothing is loaded; the start screen stays
  const token = ++renderToken;
  const route = parseRoute();
  const view = VIEWS[route.name];
  setTabs(view ? view.tab : null);
  main.setAttribute('aria-busy', 'true');
  const log = [];
  const ctx = {
    state, route, navigate, runGuarded,
    /** Run one of the viewer's own statements and record it for "Cypher behind this view". */
    q: async (label, statement, params = null, options = {}) => {
      const envelope = await state.db.run(statement, params, options);
      log.push({ label, statement, params, rows: envelope.rows.length, ms: envelope.elapsed_ms ?? envelope.wallMs ?? 0 });
      return envelope;
    },
  };
  let node;
  let title = view ? view.title : 'Not found';
  try {
    node = view
      ? await view.render(ctx, route)
      : emptyState('There is no such view.', `Nothing is shown at ${location.hash.slice(0, 80)}.`, h('a', { class: 'btn', href: '#/' }, 'Go to the overview'));
  } catch (error) {
    title = 'Error';
    node = emptyState('This view could not be shown.', error.message, h('a', { class: 'btn', href: '#/' }, 'Go to the overview'));
  }
  if (token !== renderToken) return; // a newer navigation finished first
  clear(main).append(node, queryLog(log) ?? '');
  main.dataset.view = route.name;
  main.dataset.arg = route.arg ?? '';
  setTabs(view ? view.tab : null); // again: the view may have chosen the session the Timeline tab returns to
  main.removeAttribute('aria-busy');
  const heading = main.querySelector('h1');
  document.title = `${heading ? heading.textContent.slice(0, 80) : title} \u00b7 TaintTrail`;
  window.scrollTo(0, 0);
  if (!firstRender) (main.querySelector('#page-title') ?? main).focus({ preventScroll: true });
  firstRender = false;
}

// ---- theme ----------------------------------------------------------------------------------------

function currentTheme() {
  const stored = document.documentElement.dataset.theme;
  if (stored === 'light' || stored === 'dark') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function syncThemeToggle() {
  const dark = currentTheme() === 'dark';
  $('theme-toggle').setAttribute('aria-pressed', String(dark));
  $('theme-label').textContent = dark ? 'Switch to light theme' : 'Switch to dark theme';
}

function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    window.localStorage.setItem('tainttrail.theme', next);
  } catch {
    // Storage is unavailable; the choice lasts until the tab closes.
  }
  syncThemeToggle();
}

// ---- wiring and start ----------------------------------------------------------------------------

function wire() {
  // The skip link moves focus to the content. Left to the browser it would set the hash to
  // "#view", which the router would read as a view that does not exist.
  document.querySelector('.skip-link').addEventListener('click', (event) => {
    event.preventDefault();
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0); // the content starts right under the bar that stays at the top
  });

  $('theme-toggle').addEventListener('click', toggleTheme);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncThemeToggle);
  syncThemeToggle();

  const input = $('file-input');
  $('open-file').addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    const file = input.files && input.files[0];
    input.value = ''; // so choosing the same file again fires a change
    if (file) openFile(file);
  });

  // Dropping a file anywhere on the page opens it. Without these handlers the browser would
  // navigate away to the dropped file.
  const veil = $('drop-veil');
  let depth = 0;
  const hasFiles = (event) => Array.from(event.dataTransfer?.types ?? []).includes('Files');
  window.addEventListener('dragenter', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth += 1;
    veil.hidden = false;
  });
  window.addEventListener('dragover', (event) => {
    if (hasFiles(event)) event.preventDefault();
  });
  window.addEventListener('dragleave', (event) => {
    if (!hasFiles(event)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) veil.hidden = true;
  });
  window.addEventListener('drop', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth = 0;
    veil.hidden = true;
    const file = event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) openFile(file);
  });

  window.addEventListener('hashchange', render);
}

function showFatal(error) {
  document.body.dataset.state = 'error';
  setEngineStatus('bad', 'Relate WASM: not running');
  clear(main).append(emptyState('The viewer could not start.', error.message));
}

async function start() {
  wire();
  state.db = createClient({ onStats: showStats });
  try {
    state.engine = await state.db.info();
    setEngineStatus('ok', `Relate WASM ${state.engine.version}`);
  } catch (error) {
    showFatal(error);
    return;
  }

  // The server (or a static copy) puts the graph next to the page. Without one, ask for a file.
  let doc = null;
  let problem = null;
  try {
    const response = await fetch('./graph.json', { cache: 'no-store' });
    if (response.ok) {
      try {
        doc = await response.json();
      } catch {
        problem = 'graph.json next to the viewer is not valid JSON.';
      }
    }
  } catch {
    // No graph.json reachable: the start screen offers a file picker and the sample.
  }
  if (doc === null) {
    showStart(problem);
    return;
  }
  try {
    await loadExport(doc, 'graph.json');
  } catch (error) {
    showStart(error.message);
    return;
  }
  await render();
}

start();
