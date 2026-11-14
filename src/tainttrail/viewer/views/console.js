// Console: ask the graph anything with Cypher. Statements run in this tab on Relate WASM.
// The console only reads: write clauses are refused, and a statement that changes the graph
// anyway makes the viewer load the export again.

import { h, clear, icon, fmtMs, plural } from '../dom.js';
import { EXAMPLES } from '../queries.js';
import { card, pageHead, resultJson, resultTable } from '../ui.js';

function parseParams(text) {
  const trimmed = text.trim();
  if (!trimmed) return null;
  let value;
  try {
    value = JSON.parse(trimmed);
  } catch (error) {
    throw new Error(`The parameters are not valid JSON (${error.message}).`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Parameters must be a JSON object, for example {"id": "host:attacker.example"}.');
  }
  return value;
}

export async function consoleView(ctx, route) {
  const saved = ctx.state.console ?? { statement: EXAMPLES[0].statement, params: '', mode: 'table' };
  const fromLink = route.query.get('q');
  if (fromLink !== null) {
    saved.statement = fromLink;
    saved.params = route.query.get('p') ?? '';
  }
  ctx.state.console = saved;

  const editor = h('textarea', { id: 'console-statement', class: 'mono editor', rows: '9', spellcheck: 'false', autocapitalize: 'off',
    autocomplete: 'off', 'aria-label': 'Cypher statement', value: saved.statement });
  const params = h('textarea', { id: 'console-params', class: 'mono editor', rows: '2', spellcheck: 'false', autocapitalize: 'off',
    autocomplete: 'off', 'aria-label': 'Parameters as a JSON object', placeholder: '{"name": "value"}', value: saved.params });
  const status = h('p', { class: 'run-status', id: 'console-status', role: 'status', 'aria-live': 'polite' },
    'Press Run, or Ctrl+Enter in the editor.');
  const output = h('div', { class: 'console-output', id: 'console-output' });
  const run = h('button', { type: 'button', class: 'btn btn-primary', id: 'console-run' }, icon('play'), 'Run');
  let last = null; // the last successful envelope, so the table / JSON switch needs no second run

  function show() {
    if (!last) return;
    const tableMode = saved.mode === 'table';
    const toggle = h('button', { type: 'button', class: 'btn btn-small', id: 'console-mode', 'aria-pressed': String(!tableMode) },
      tableMode ? 'Show as JSON' : 'Show as table');
    toggle.addEventListener('click', () => {
      saved.mode = tableMode ? 'json' : 'table';
      show();
    });
    const types = last.columns.map((name, i) => `${name} ${(last.columnTypes[i] ?? '').toLowerCase()}`).join(', ');
    clear(output).append(card({ title: 'Result', note: types ? `columns: ${types}` : null, actions: toggle, cls: 'result-card' },
      tableMode ? resultTable(last) : h('div', { class: 'card-body' }, resultJson(last))));
  }

  async function execute() {
    saved.statement = editor.value;
    saved.params = params.value;
    run.disabled = true;
    status.className = 'run-status';
    status.textContent = 'Running in Relate WASM\u2026';
    try {
      const envelope = await ctx.runGuarded(editor.value, parseParams(params.value));
      last = envelope;
      status.classList.add('run-ok');
      status.textContent = `${plural(envelope.rows.length, 'row')} in ${fmtMs(envelope.elapsed_ms)} of engine time, in this tab.` +
        (envelope.reloaded ? ' The statement mentions a write word in a string or a comment, so the graph was loaded again afterwards to be sure.' : '');
      show();
    } catch (error) {
      last = null;
      status.classList.add(error.refused ? 'run-partial' : 'run-error');
      status.textContent = error.refused ? error.message : 'The statement failed.';
      clear(output);
      if (!error.refused) output.append(h('pre', { class: 'code code-error', role: 'alert', tabindex: '0' }, h('code', null, error.message)));
    } finally {
      run.disabled = false;
    }
  }

  run.addEventListener('click', execute);
  for (const field of [editor, params]) {
    field.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        execute();
      }
    });
  }

  const examples = h('ul', { class: 'examples' }, EXAMPLES.map((example, i) => h('li', null,
    h('button', { type: 'button', class: 'example', dataset: { example: i }, on: { click: () => {
      editor.value = example.statement;
      params.value = example.params ? JSON.stringify(example.params) : '';
      execute();
    } } }, h('span', { class: 'example-title' }, example.title), h('span', { class: 'example-about' }, example.about)))));

  return h('div', { class: 'view view-console' },
    pageHead({ eyebrow: h('a', { href: '#/' }, 'Overview'), title: 'Cypher console',
      lede: 'Ask the graph directly. Statements run in this tab on Relate\u2019s WebAssembly build, against the same nodes and relationships the guard recorded. The console only reads.' }),
    h('div', { class: 'console-grid' },
      card({ title: 'Statement', cls: 'editor-card' },
        h('div', { class: 'card-body' }, editor,
          h('details', { class: 'params-box', open: saved.params ? true : null }, h('summary', null, 'Parameters'), params),
          h('div', { class: 'run-bar' }, run, status))),
      card({ title: 'Examples', note: 'click to run' }, examples)),
    output);
}
