// Session timeline: in order, what the agent was told, what it called, what each call brought
// into its context, and what the guard decided.

import { h, icon, list, fmtBytes, fmtClock, fmtInt, fmtTime, plural, shortId } from '../dom.js';
import { SESSION, SESSION_IDS, SESSION_RECEIVED, SESSION_CALLS, FINDINGS } from '../queries.js';
import { card, emptyState, pageHead, roleTag, verdict, sessionHref, findingHref } from '../ui.js';
import { findingItem } from './overview.js';

const MAX_CHIPS = 12; // a call can touch hundreds of files; the first dozen and a count are enough here
const REL_WORD = { READS: 'reads', WRITES: 'writes', FETCHES: 'fetches', SENDS_TO: 'sends to', UPLOADS: 'uploads', EXECUTES: 'runs' };

/** `mcp__github__get_issue` -> { name: 'get_issue', server: 'github' }; built-ins have no server. */
function splitTool(tool) {
  const text = String(tool ?? '');
  const parts = text.startsWith('mcp__') ? text.split('__') : [];
  return parts.length >= 3 && parts[1] && parts[2] ? { name: parts.slice(2).join('__'), server: parts[1] } : { name: text, server: null };
}

function summaryText(row) {
  const summary = String(row.summary ?? '');
  const tool = String(row.tool ?? '');
  if (tool && summary.startsWith(`${tool}: `)) return summary.slice(tool.length + 2);
  if (tool && summary.startsWith(`${tool} `)) return summary.slice(tool.length + 1);
  return summary === tool ? '' : summary;
}

function contentTitle(row) {
  if (row.src_kind === 'url' && row.src_value) return `web page ${String(row.src_value).replace(/^[a-z][a-z0-9+.-]*:\/\//, '')}`;
  if (row.src_kind === 'file' && row.src_name) return `contents of ${row.src_name}`;
  if (row.src_kind === 'host' && row.src_value) return `response from ${row.src_value}`;
  if (row.src_value) return String(row.src_value);
  return `output of ${splitTool(row.tool).name}`;
}

function touchChip(t) {
  const mark = t.sensitive ? icon('sensitive', { label: 'sensitive', cls: 'tint-sensitive' })
    : t.protected ? icon('file', { label: 'instruction or settings file' })
      : t.rel === 'SENDS_TO' && !t.local ? icon('destination', { label: 'destination', cls: 'tint-destination' }) : null;
  const flags = [t.sensitive ? 'sensitive' : null, t.protected ? 'protected file' : null, t.trusted ? 'trusted destination' : null, t.local ? 'local' : null].filter(Boolean);
  return h('span', { class: 'chip', title: `${t.rel} ${t.kind}:${t.value}${flags.length ? ` (${flags.join(', ')})` : ''}` },
    h('span', { class: 'chip-key' }, REL_WORD[t.rel] ?? String(t.rel).toLowerCase()), mark, h('span', { class: 'chip-text' }, t.name || t.value));
}

function broughtIn(row) {
  if (!row.out_id) {
    const why = row.status === 'blocked' ? 'Blocked before it ran: nothing entered the context.'
      : row.decision === 'ask' ? 'Held for approval; no result was recorded.'
        : row.status === 'failed' ? 'The call failed.' : 'No result recorded.';
    return h('div', { class: 'tl-in' }, h('p', { class: 'muted tl-none' }, why));
  }
  const flags = [row.untrusted ? roleTag('untrusted') : null, row.sensitive ? roleTag('sensitive') : null].filter(Boolean);
  const size = typeof row.bytes === 'number' && row.bytes > 0 ? fmtBytes(row.bytes) : null;
  const parts = [h('div', { class: 'tl-in-head' }, flags.length ? flags : h('span', { class: 'muted tl-plain' }, 'not flagged'),
    h('span', { class: 'tl-in-title' }, contentTitle(row)), size ? h('span', { class: 'muted nowrap' }, size) : null)];
  if (row.injection >= 0.3) {
    const markers = list(row.markers);
    parts.push(h('p', { class: 'tl-injection' }, icon('untrusted'),
      ` Reads like instructions to the agent: score ${Number(row.injection).toFixed(2)}`,
      markers.length ? h('span', { class: 'muted' }, ` (${markers.join(', ')})`) : null));
  }
  if (row.sensitive) parts.push(h('p', { class: 'muted tl-withheld' }, 'Excerpt withheld. Only keyed fingerprints of sensitive text are stored.'));
  else if (row.excerpt) parts.push(h('blockquote', { class: 'excerpt', title: row.excerpt }, row.excerpt));
  return h('div', { class: 'tl-in' }, parts);
}

function decisionCell(row) {
  const findings = list(row.findings);
  const blocking = findings.filter((f) => f.action !== 'allow' || f.intended !== 'allow');
  const top = blocking.find((f) => f.action === 'allow');
  const mark = row.decision === 'allow' && top ? verdict('allow', top.intended) : verdict(row.decision);
  return h('div', { class: 'tl-decision' }, mark,
    findings.length ? h('div', { class: 'tl-rules' }, findings.map((f) =>
      h('a', { class: 'rule rule-link', href: findingHref(f.id), title: f.title }, f.rule))) : null);
}

const DECISIONS = new Set(['allow', 'ask', 'deny']);

function callRow(row) {
  const tool = splitTool(row.tool);
  const summary = summaryText(row);
  const touches = list(row.touches);
  // The decision becomes part of a class name, so only the three known words may pass.
  return h('li', { class: `tl-row tl-call tl-${DECISIONS.has(row.decision) ? row.decision : 'allow'}`, dataset: { call: row.id } },
    h('div', { class: 'tl-num' }, h('span', { class: 'tl-hash', title: `call #${row.num}` }, `#${row.num}`), h('span', { class: 'tl-time' }, fmtClock(row.ts))),
    h('div', { class: 'tl-what' },
      h('div', { class: 'tl-tool' }, h('span', { class: 'tool-name' }, tool.name), tool.server ? h('span', { class: 'chip chip-server', title: `MCP server ${tool.server}` }, tool.server) : null,
        row.is_sink ? h('span', { class: 'chip chip-sink', title: 'This call can move data off the machine' }, icon('destination'), 'outbound') : null),
      summary ? h('code', { class: 'tl-summary' }, summary) : null,
      touches.length || row.carries ? h('div', { class: 'chips' }, touches.slice(0, MAX_CHIPS).map(touchChip),
        touches.length > MAX_CHIPS ? h('span', { class: 'chip' }, `and ${fmtInt(touches.length - MAX_CHIPS)} more`) : null,
        row.carries ? h('span', { class: 'chip', title: 'The call arguments contain keyed fingerprints of text seen earlier' },
          h('span', { class: 'chip-key' }, 'carries'), icon('fingerprint'), h('span', { class: 'chip-text' }, plural(row.carries, 'fingerprint'))) : null) : null),
    broughtIn(row), decisionCell(row));
}

/**
 * What the session was given without a tool call. Three kinds, told apart by `origin`: what
 * the user typed, a file the user attached to a prompt with @path (the harness puts its
 * contents into the context; it is judged like a file the agent read), and an instruction
 * file the harness loaded at the start that an earlier session wrote under untrusted influence.
 */
function receivedRow(row) {
  const kind = row.origin === 'memory' ? 'memory' : row.origin === 'attached' ? 'attached' : 'prompt';
  const mentions = list(row.mentions);
  const size = typeof row.bytes === 'number' && row.bytes > 0 ? fmtBytes(row.bytes) : null;
  const head = kind === 'memory' ? [roleTag('file', 'Inherited memory')]
    : kind === 'attached' ? [roleTag('file', 'Attached file'), row.source ? h('span', { class: 'tl-in-title' }, String(row.source)) : null,
      size ? h('span', { class: 'muted nowrap' }, size) : null]
      : [roleTag('user')];
  const body = row.sensitive ? h('p', { class: 'muted tl-withheld' }, 'Excerpt withheld. Only keyed fingerprints of sensitive text are stored.')
    : row.excerpt ? (kind === 'attached' ? h('blockquote', { class: 'excerpt', title: row.excerpt }, row.excerpt) : h('p', { class: 'tl-prompt-text' }, row.excerpt))
      : h('p', { class: 'muted' }, 'No text recorded.');
  return h('li', { class: `tl-row tl-received tl-given-${kind}` },
    h('div', { class: 'tl-num' }, h('span', { class: 'tl-hash tl-hash-quiet' }, icon(kind === 'prompt' ? 'user' : 'file')), h('span', { class: 'tl-time' }, fmtClock(row.ts))),
    h('div', { class: 'tl-prompt' },
      h('div', { class: 'tl-in-head' }, head, row.untrusted ? roleTag('untrusted') : null, row.sensitive ? roleTag('sensitive') : null),
      body,
      mentions.length ? h('div', { class: 'chips' }, mentions.slice(0, MAX_CHIPS).map((m) => h('span', { class: 'chip', title: `${m.kind}:${m.value}` },
        h('span', { class: 'chip-key' }, 'names'), h('span', { class: 'chip-text' }, m.name || m.value))),
      mentions.length > MAX_CHIPS ? h('span', { class: 'chip' }, `and ${fmtInt(mentions.length - MAX_CHIPS)} more`) : null) : null));
}

export async function sessionView(ctx, route) {
  const ids = (await ctx.q('Sessions, newest first', SESSION_IDS)).rows;
  if (!ids.length) return emptyState('No sessions in this export.', 'A session appears here once the guard has recorded one.', h('a', { class: 'btn', href: '#/' }, 'Go to the overview'));
  const known = new Set(ids.map((r) => r.id));
  const sid = route.arg ?? (known.has(ctx.state.lastSession) ? ctx.state.lastSession : ids[0].id);
  if (!known.has(sid)) return emptyState('No such session.', `There is no session ${sid} in this export.`, h('a', { class: 'btn', href: '#/' }, 'Go to the overview'));
  ctx.state.lastSession = sid;

  const session = (await ctx.q('The session', SESSION, { sid })).rows[0];
  const received = (await ctx.q('Prompts and inherited memory', SESSION_RECEIVED, { sid })).rows;
  const calls = (await ctx.q('Tool calls: what each touched, brought in, and the decision', SESSION_CALLS, { sid })).rows;
  const findings = (await ctx.q('Findings of this session', FINDINGS, { sid })).rows;

  const events = [...received.map((r) => ({ seq: r.seq ?? 0, node: receivedRow(r) })), ...calls.map((c) => ({ seq: c.seq ?? 0, node: callRow(c) }))]
    .sort((a, b) => a.seq - b.seq);
  const denied = calls.filter((c) => c.decision === 'deny').length;
  const asked = calls.filter((c) => c.decision === 'ask').length;
  const unenforced = findings.filter((f) => f.action === 'allow' && (f.intended === 'deny' || f.intended === 'ask')).length;
  const picker = h('select', { id: 'session-picker', 'aria-label': 'Session', on: { change: (e) => ctx.navigate(sessionHref(e.target.value)) } },
    ids.map((r) => h('option', { value: r.id, selected: r.id === sid }, `${fmtTime(r.started_at) || 'unknown time'}  ${shortId(r.id)}`)));

  return h('div', { class: 'view view-session' },
    pageHead({
      eyebrow: h('a', { href: '#/' }, 'Overview'), title: 'Session timeline',
      // An older graph does not say which mode a session ran in; then nothing is claimed about it.
      lede: [h('code', { class: 'wrap-anywhere' }, session.id), ` \u00b7 ${session.agent ?? 'agent'}${session.mode ? ` \u00b7 ${session.mode} mode` : ''}${fmtTime(session.started_at) ? ` \u00b7 started ${fmtTime(session.started_at)}` : ''}`,
        session.cwd ? [' \u00b7 ', h('code', null, session.cwd)] : null],
      actions: ids.length > 1 ? picker : null,
    }),
    h('p', { class: 'summary-line' }, `${plural(calls.length, 'tool call')}, ${fmtInt(denied)} denied, ${fmtInt(asked)} asked, ${plural(findings.length, 'finding')}.`,
      unenforced ? ` ${plural(unenforced, 'finding')} called for a hold that was not enforced (monitor mode, or a rule that was overridden).` : null),
    card({ title: 'Timeline', note: 'in the order things happened', cls: 'timeline-card' },
      h('div', { class: 'tl-head', 'aria-hidden': 'true' }, h('span', null, '#'), h('span', null, 'Tool call'), h('span', null, 'Brought into context'), h('span', null, 'Decision')),
      events.length ? h('ol', { class: 'timeline' }, events.map((e) => e.node)) : emptyState('Nothing was recorded in this session.')),
    card({ title: 'Findings in this session' },
      findings.length ? h('ul', { class: 'finding-list finding-list-wide' }, findings.map(findingItem)) : emptyState('No findings.', 'No rule matched in this session.')));
}
