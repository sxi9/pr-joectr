// Overview: what was recorded and what the guard decided, across every session in the graph.

import { h, icon, breakable, fmtInt, fmtTime, plural, shortId } from '../dom.js';
import { TOTALS, SESSIONS, FINDINGS, DESTINATIONS, DESTINATION_DETAIL } from '../queries.js';
import { card, consoleHref, emptyState, pageHead, roleTag, verdict, severity, sessionHref, findingHref } from '../ui.js';

function tile(label, value, sub, mark = null) {
  return h('div', { class: 'tile' },
    h('div', { class: 'tile-label' }, mark, label),
    h('div', { class: 'tile-value' }, fmtInt(value)),
    h('div', { class: 'tile-sub', title: sub }, sub));
}

function sessionVerdict(row) {
  if (row.denied > 0) return verdict('deny');
  if (row.asked > 0) return verdict('ask');
  return h('span', { class: 'verdict verdict-allow' }, icon('allow'), 'nothing held');
}

const MAX_SESSION_ROWS = 200;

function sessionsTable(rows, totals) {
  const body = rows.slice(0, MAX_SESSION_ROWS).map((row) => h('tr', null,
    h('td', { class: 'cell-session' },
      h('a', { class: 'id-link', href: sessionHref(row.id), title: row.id }, shortId(row.id)),
      h('span', { class: 'cell-sub cell-clip', title: row.first_prompt ?? '' }, row.first_prompt || 'no prompt recorded')),
    h('td', { class: 'nowrap col-wide' }, fmtTime(row.started_at)),
    h('td', { class: 'num' }, fmtInt(row.calls)),
    h('td', { class: 'num' }, fmtInt(row.asked)),
    h('td', { class: 'num' }, fmtInt(row.denied)),
    h('td', { class: 'num' }, fmtInt(row.findings)),
    h('td', { class: 'col-wide' }, sessionVerdict(row))));
  return h('div', { class: 'table-wrap' }, h('table', { class: 'sessions-table' },
    h('thead', null, h('tr', null,
      h('th', { scope: 'col' }, 'Session'), h('th', { scope: 'col', class: 'col-wide' }, 'Started'),
      h('th', { scope: 'col', class: 'num' }, 'Calls'), h('th', { scope: 'col', class: 'num' }, 'Asked'),
      h('th', { scope: 'col', class: 'num' }, 'Denied'), h('th', { scope: 'col', class: 'num' }, 'Findings'),
      h('th', { scope: 'col', class: 'col-wide' }, 'Outcome'))),
    h('tbody', null, body),
    h('tfoot', null, h('tr', null,
      h('td', null, `Total, ${plural(totals.sessions, 'session')}`), h('td', { class: 'col-wide' }),
      h('td', { class: 'num' }, fmtInt(totals.calls)), h('td', { class: 'num' }, fmtInt(totals.asked)),
      h('td', { class: 'num' }, fmtInt(totals.denied)), h('td', { class: 'num' }, fmtInt(totals.findings)),
      h('td', { class: 'col-wide' })))));
}

function namedBy(row) {
  if (row.by_user) return roleTag('user');
  if (row.trusted) return h('span', { class: 'role' }, icon('allow'), 'Trusted list');
  if (row.by_untrusted) return roleTag('untrusted', 'Untrusted content only');
  return h('span', { class: 'muted' }, 'nobody: it appears only in the call');
}

function destinationsTable(rows) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'dest-table' },
    h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Destination'), h('th', { scope: 'col' }, 'Named by'),
      h('th', { scope: 'col', class: 'num' }, 'Calls'),
      h('th', { scope: 'col', class: 'col-wide', title: 'Whether a call could carry data the agent chose: a request body, an upload, a query string' }, 'Carried'),
      h('th', { scope: 'col' }, 'Outcome'))),
    h('tbody', null, rows.map((row) => h('tr', null,
      h('td', { class: 'cell-dest' }, h('a', { class: 'id-link', href: consoleHref(DESTINATION_DETAIL, { dest: row.id }), title: `${row.id}: who named it and which calls sent there` }, breakable(row.value || row.id)),
        h('span', { class: 'cell-sub' }, row.kind ?? '')),
      h('td', null, namedBy(row)),
      h('td', { class: 'num' }, fmtInt(row.calls)),
      h('td', { class: 'col-wide nowrap' }, row.with_data ? 'data' : h('span', { class: 'muted' }, 'a plain request')),
      h('td', null, row.denied ? verdict('deny') : row.asked ? verdict('ask') : verdict('allow')))))));
}

export function findingItem(f) {
  const where = [
    f.session_id ? `session ${shortId(f.session_id)}` : null,
    f.call_num ? `call #${f.call_num}` : (f.target_label === 'Content' ? 'tool result' : null),
    fmtTime(f.ts),
  ].filter(Boolean).join(' \u00b7 ');
  return h('li', { class: 'finding-item' },
    h('div', { class: 'finding-item-head' },
      verdict(f.action, f.intended, { kind: 'finding' }), h('span', { class: 'rule' }, f.rule), severity(f.severity)),
    h('a', { class: 'finding-item-title', href: findingHref(f.id) }, f.title || f.name || f.id),
    h('div', { class: 'finding-item-meta' }, where));
}

export async function overviewView(ctx) {
  const totals = (await ctx.q('Totals', TOTALS)).rows[0];
  const sessions = (await ctx.q('Sessions with calls, asked, denied and findings', SESSIONS)).rows;
  const findings = (await ctx.q('Findings, the ones that held a call first', FINDINGS, { sid: null })).rows;
  const destinations = (await ctx.q('Where calls sent data, and who named each place', DESTINATIONS)).rows;

  const held = totals.asked + totals.denied;
  const lede = totals.sessions === 0
    ? 'This export holds no recorded session.'
    : held === 0
      ? `${plural(totals.sessions, 'session')} recorded. No call was held: nothing completed a path from untrusted content to data leaving the machine.`
      : `${plural(totals.sessions, 'session')} recorded. The guard held ${plural(held, 'call')}: ${fmtInt(totals.denied)} denied, ${fmtInt(totals.asked)} asked.`;
  const blocking = findings.filter((f) => f.action !== 'allow' || f.intended !== 'allow').length;

  const page = h('div', { class: 'view view-overview' },
    pageHead({ eyebrow: ctx.state.meta?.session ? `One session of ${ctx.state.meta.project || 'a project'}` : 'All sessions', title: 'Overview', lede }),
    h('div', { class: 'tiles' },
      tile('Sessions', totals.sessions, sessions.length ? `latest ${fmtTime(sessions[0].started_at)}` : 'none recorded'),
      tile('Tool calls', totals.calls, `${plural(totals.untrusted, 'untrusted input')}, ${plural(totals.sensitive, 'sensitive read')}`),
      tile('Asked', totals.asked, 'held for your approval', h('span', { class: 'mark mark-ask' }, icon('ask'))),
      tile('Denied', totals.denied, 'blocked before running', h('span', { class: 'mark mark-deny' }, icon('deny'))),
      tile('Findings', totals.findings, `${fmtInt(blocking)} held a call, ${fmtInt(totals.findings - blocking)} noted`)));

  const sessionsCard = card({ title: 'Sessions', note: sessions.length > MAX_SESSION_ROWS ? `the newest ${MAX_SESSION_ROWS} of ${fmtInt(sessions.length)}` : 'newest first' },
    sessions.length ? sessionsTable(sessions, totals)
      : emptyState('No sessions in this export.', 'The capability map may still have content.', h('a', { class: 'btn', href: '#/map' }, 'Open the capability map')));
  const findingsCard = card({ title: 'Findings', note: findings.length > 6 ? `6 of ${findings.length}` : null,
    actions: findings.length ? h('a', { class: 'btn btn-small', href: '#/findings' }, 'All attack paths') : null },
    findings.length ? h('ul', { class: 'finding-list' }, findings.slice(0, 6).map(findingItem))
      : emptyState('No findings.', 'No rule matched in any recorded session.'));
  const destinationsCard = card({ title: 'Outbound destinations', note: 'places outside this machine that calls sent data to' },
    destinations.length ? destinationsTable(destinations)
      : emptyState('No outbound calls.', 'No recorded call sent data to a place outside this machine.'));
  page.append(h('div', { class: 'grid-2' }, h('div', { class: 'stack' }, sessionsCard, destinationsCard), findingsCard));
  return page;
}
