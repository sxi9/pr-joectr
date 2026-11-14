// ui.js: the small pieces every view shares. Marks that mean something (verdicts, roles,
// severities) are built here so they look and read the same everywhere: a colour, an icon
// and the word, never the colour alone.

import { h, icon, fmtMs, fmtInt, plural } from './dom.js';
import { cypherBlock } from './cypher.js';
import { isNode, isRelationship, isPath, nodeKey } from './db.js';

export const sessionHref = (id) => `#/session/${encodeURIComponent(id)}`;
export const findingHref = (id) => `#/finding/${encodeURIComponent(id)}`;

/** A link that opens the console with a statement (and parameters) filled in. */
export function consoleHref(statement, params = null) {
  const query = `q=${encodeURIComponent(statement)}`;
  return `#/console?${query}${params && Object.keys(params).length ? `&p=${encodeURIComponent(JSON.stringify(params))}` : ''}`;
}

// ---- verdicts ------------------------------------------------------------------------------

const VERDICT_WORD = { deny: 'Denied', ask: 'Asked', allow: 'allowed' };

/**
 * What the guard did with a call or concluded in a finding.
 * `intended` differs from `action` when the project was in monitor mode or the rule was
 * overridden: the rule called for a block that was not enforced.
 */
export function verdict(action, intended = action, { kind = 'call' } = {}) {
  if (action === 'deny') return h('span', { class: 'verdict verdict-deny' }, icon('deny'), VERDICT_WORD.deny);
  if (action === 'ask') return h('span', { class: 'verdict verdict-ask' }, icon('ask'), VERDICT_WORD.ask);
  if (intended === 'deny' || intended === 'ask') {
    return h('span', {
      class: `verdict verdict-would${intended === 'ask' ? ' verdict-would-ask' : ''}`,
      title: 'Not enforced: the project was in monitor mode or the rule was overridden',
    }, icon(intended), `would be ${VERDICT_WORD[intended].toLowerCase()}`);
  }
  if (kind === 'finding') return h('span', { class: 'verdict verdict-noted' }, icon('note'), 'Noted');
  return h('span', { class: 'verdict verdict-allow' }, icon('allow'), VERDICT_WORD.allow);
}

const SEVERITY_LEVEL = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Severity as a word with a four-bar meter: an ordered scale, so one ink, not five hues. */
export function severity(level) {
  const n = SEVERITY_LEVEL[level] ?? 0;
  const bars = h('span', { class: 'severity-bars', 'aria-hidden': 'true' },
    [1, 2, 3, 4].map((i) => h('i', { class: i <= n ? 'on' : null })));
  return h('span', { class: 'severity', title: `Severity: ${level}` }, bars, String(level ?? 'info'));
}

// ---- roles and capabilities ------------------------------------------------------------------

export const ROLE_NAME = {
  untrusted: 'Untrusted', sensitive: 'Sensitive', destination: 'Destination', call: 'Call',
  user: 'Your prompt', fingerprint: 'Fingerprint', file: 'File', entity: 'Entity', content: 'Content',
};

export function roleTag(role, label = null) {
  const known = Object.hasOwn(ROLE_NAME, role) ? role : 'entity';
  return h('span', { class: `role role-${known}` }, icon(known), label ?? ROLE_NAME[known]);
}

export const CAPABILITIES = [
  { key: 'untrusted_input', label: 'untrusted input', icon: 'untrusted', role: 'untrusted', about: 'Results can contain text written by third parties' },
  { key: 'private_data', label: 'private data', icon: 'sensitive', role: 'sensitive', about: 'Results can contain non-public data' },
  { key: 'external_sink', label: 'external sink', icon: 'destination', role: 'destination', about: 'Calls can send data where third parties can read it' },
  { key: 'local_write', label: 'local write', icon: 'write', role: 'neutral', about: 'Calls change local files or state' },
  { key: 'code_exec', label: 'code exec', icon: 'exec', role: 'neutral', about: 'Calls run code or commands' },
];

export function capabilityBadge(cap) {
  return h('span', { class: `cap cap-${cap.role}`, title: cap.about }, icon(cap.icon), cap.label);
}

const PERMISSION = {
  allow: { icon: 'allow', word: 'allow', about: 'Runs without asking' },
  ask: { icon: 'ask', word: 'ask', about: 'The user is asked before it runs' },
  deny: { icon: 'deny', word: 'deny', about: 'Never runs' },
  default: { icon: null, word: 'default', about: 'No rule: the harness applies its default' },
};

export function permissionMark(permission) {
  const p = PERMISSION[permission] ?? PERMISSION.default;
  return h('span', { class: `perm perm-${Object.hasOwn(PERMISSION, permission) ? permission : 'default'}`, title: p.about },
    p.icon ? icon(p.icon) : null, p.word);
}

// ---- layout pieces ---------------------------------------------------------------------------

export function card({ title = null, note = null, actions = null, cls = '' } = {}, ...body) {
  const head = title ? h('div', { class: 'card-head' }, h('h2', null, title), note ? h('span', { class: 'card-note' }, note) : null, actions) : null;
  return h('section', { class: `card${cls ? ` ${cls}` : ''}` }, head, body);
}

export function emptyState(title, detail = null, ...actions) {
  return h('div', { class: 'empty' }, h('p', { class: 'empty-title' }, title),
    detail ? h('p', { class: 'empty-detail' }, detail) : null,
    actions.length ? h('div', { class: 'empty-actions' }, actions) : null);
}

export function pageHead({ eyebrow = null, title, lede = null, actions = null }) {
  return h('header', { class: 'page-head' },
    h('div', { class: 'page-head-main' },
      eyebrow ? h('p', { class: 'eyebrow' }, eyebrow) : null,
      h('h1', { id: 'page-title', tabindex: '-1' }, title),
      lede ? h('p', { class: 'lede' }, lede) : null),
    actions ? h('div', { class: 'page-actions' }, actions) : null);
}

/** "Cypher behind this view": every statement the view ran, its timing, and a way to rerun it. */
export function queryLog(log) {
  if (!log.length) return null;
  const total = log.reduce((sum, entry) => sum + (entry.ms ?? 0), 0);
  const items = log.map((entry) => h('li', { class: 'qlog-item' },
    h('div', { class: 'qlog-head' },
      h('span', { class: 'qlog-label' }, entry.label),
      h('span', { class: 'qlog-meta' }, `${plural(entry.rows, 'row')} \u00b7 ${fmtMs(entry.ms)}`),
      h('a', { class: 'btn btn-small', href: consoleHref(entry.statement, entry.params) }, 'Open in console')),
    cypherBlock(entry.statement, { cls: 'code-compact' })));
  return h('details', { class: 'qlog' },
    h('summary', null, icon('database'),
      h('span', null, `Cypher behind this view: ${plural(log.length, 'query', 'queries')}, ${fmtMs(total)} in Relate WASM`)),
    h('ol', { class: 'qlog-list' }, items));
}

// ---- query results ---------------------------------------------------------------------------

const MAX_ROWS = 200;
const MAX_TEXT = 280;

const clip = (s) => (s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT)}\u2026` : s);

function nodeChip(node) {
  const labels = (node.labels ?? []).join(':') || 'node';
  return h('span', { class: 'gv gv-node', title: JSON.stringify(node.properties ?? {}, null, 1).slice(0, 1500) },
    h('span', { class: 'gv-label' }, labels), h('span', { class: 'gv-key' }, clip(nodeKey(node))));
}

function relChip(rel, forward = true) {
  return h('span', { class: 'gv gv-rel', title: JSON.stringify(rel.properties ?? {}) },
    forward ? '\u2500' : '\u25c0\u2500', h('span', { class: 'gv-type' }, rel.type), forward ? '\u2500\u25b6' : '\u2500');
}

function pathChips(path) {
  const parts = [];
  for (let i = 0; i < path.length; i += 1) {
    if (i % 2 === 0) parts.push(nodeChip(path[i]));
    else parts.push(relChip(path[i], path[i].start_node === path[i - 1].id)); // the stored direction
  }
  return h('span', { class: 'gv-path' }, parts);
}

/** One result value as DOM. Graph values become chips; everything else is text. */
export function valueNode(value) {
  if (value === null || value === undefined) return h('span', { class: 'gv-null' }, 'null');
  if (typeof value === 'boolean') return h('span', { class: 'gv-bool' }, String(value));
  if (typeof value === 'number') return h('span', { class: 'gv-num' }, String(value));
  if (typeof value === 'string') return h('span', { class: 'gv-str' }, clip(value));
  if (isNode(value)) return nodeChip(value);
  if (isRelationship(value)) return relChip(value);
  if (isPath(value)) return pathChips(value);
  if (Array.isArray(value)) {
    if (value.length <= 12 && value.every((v) => v === null || ['string', 'number', 'boolean'].includes(typeof v))) {
      return h('span', { class: 'gv-list' }, clip(value.map((v) => (v === null ? 'null' : String(v))).join(', ')) || '[ ]');
    }
    if (value.length <= 12 && value.every((v) => isNode(v) || isRelationship(v))) {
      return h('span', { class: 'gv-path' }, value.map((v) => valueNode(v)));
    }
  }
  return h('span', { class: 'gv-json' }, clip(JSON.stringify(value)));
}

const NUMERIC = new Set(['INTEGER', 'FLOAT']);

/** A result as a table. Rows are read through envelope.columns: row objects are keyed alphabetically. */
export function resultTable(envelope) {
  const { columns = [], columnTypes = [], rows = [] } = envelope;
  if (!columns.length) return h('p', { class: 'muted result-none' }, 'The statement returned no columns.');
  const head = h('tr', null, columns.map((name, i) => h('th', { class: NUMERIC.has(columnTypes[i]) ? 'num' : null, scope: 'col' },
    name, h('span', { class: 'col-type' }, (columnTypes[i] ?? '').toLowerCase()))));
  const body = rows.slice(0, MAX_ROWS).map((row) => h('tr', null,
    columns.map((name, i) => h('td', { class: NUMERIC.has(columnTypes[i]) ? 'num' : null }, valueNode(row[name])))));
  return h('div', { class: 'result' },
    h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Query result' },
      h('table', { class: 'result-table' }, h('thead', null, head), h('tbody', null, body))),
    rows.length === 0 ? h('p', { class: 'muted result-none' }, 'No rows.') : null,
    rows.length > MAX_ROWS ? h('p', { class: 'muted result-none' }, `Showing the first ${MAX_ROWS} of ${fmtInt(rows.length)} rows.`) : null);
}

export function resultJson(envelope) {
  const rows = envelope.rows ?? [];
  let text = JSON.stringify(rows.slice(0, MAX_ROWS), null, 2);
  if (text.length > 200_000) text = `${text.slice(0, 200_000)}\n\u2026 (cut)`;
  return h('pre', { class: 'code code-json', tabindex: '0' }, h('code', null, text));
}
