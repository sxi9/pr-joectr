// Capability map: agents, the servers they connect to, the tools those provide, what each tool
// can do and whether it needs approval. The static picture, before anything runs.

import { h, icon, list, breakable, fmtInt, plural } from '../dom.js';
import { MAP_AGENTS, MAP_SERVERS, MAP_TOOLS, MAP_LEGS, MAP_PATH_GROUPS, MAP_PATH_TOTALS } from '../queries.js';
import { CAPABILITIES, capabilityBadge, card, emptyState, pageHead, permissionMark } from '../ui.js';

const SHOWN_TOOLS = 12; // a catalog server can list a hundred tools; the rest sit behind a button
const GATE_WORDS = { open: 'runs unasked', ask: 'asks first', deny: 'refused' };
const PATH_CAPS = ['untrusted_input', 'private_data', 'external_sink'];

/** Used tools first, then the ones that can take part in a toxic path, then by name. */
function byInterest(a, b) {
  const weight = (t) => PATH_CAPS.filter((c) => t[c]).length;
  return (b.calls - a.calls) || (weight(b) - weight(a)) || String(a.name).localeCompare(String(b.name));
}

function toolRow(tool) {
  const caps = CAPABILITIES.filter((c) => tool[c.key]);
  const known = tool.label_source && tool.label_source !== 'default';
  const confidence = typeof tool.label_confidence === 'number' ? tool.label_confidence.toFixed(2) : '';
  const short = String(tool.name ?? '').startsWith('mcp__') ? String(tool.name).split('__').slice(2).join('__') || tool.name : tool.name;
  const effect = Object.hasOwn(GATE_WORDS, tool.gate) ? GATE_WORDS[tool.gate] : null;
  return h('tr', { dataset: { tool: tool.id } },
    h('td', { class: 'cell-tool' }, h('span', { class: 'tool-name', title: `${tool.name}\n${tool.notes || ''}`.trim() }, breakable(short))),
    h('td', null, caps.length ? h('div', { class: 'chips' }, caps.map(capabilityBadge)) : h('span', { class: 'muted' }, 'none of the five')),
    h('td', { class: 'nowrap col-wide', title: known ? `Labels from ${tool.label_source}, confidence ${confidence || 'unknown'}` : 'No labels are known for this tool' },
      known ? [tool.label_source, confidence ? h('span', { class: 'muted' }, ` ${confidence}`) : null] : h('span', { class: 'muted' }, 'unknown')),
    h('td', { class: 'cell-perm', title: tool.gate_reason || null }, permissionMark(tool.permission),
      effect ? h('span', { class: 'cell-sub' }, effect) : null),
    h('td', { class: 'num' }, tool.calls ? fmtInt(tool.calls) : h('span', { class: 'muted' }, '0')));
}

function toolsTable(tools) {
  const sorted = [...tools].sort(byInterest);
  const first = sorted.slice(0, SHOWN_TOOLS);
  const rest = sorted.slice(SHOWN_TOOLS);
  const more = rest.length ? h('tbody', { class: 'more-tools', hidden: true }, rest.map(toolRow)) : null;
  const button = rest.length ? h('button', { type: 'button', class: 'btn btn-small show-all', 'aria-expanded': 'false' }, `Show all ${fmtInt(sorted.length)} tools`) : null;
  if (button) {
    button.addEventListener('click', () => {
      more.hidden = !more.hidden;
      button.setAttribute('aria-expanded', String(!more.hidden));
      button.textContent = more.hidden ? `Show all ${fmtInt(sorted.length)} tools` : `Show the first ${SHOWN_TOOLS} only`;
    });
  }
  return [h('div', { class: 'table-wrap' }, h('table', { class: 'tools-table' },
    h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Tool'), h('th', { scope: 'col' }, 'Can'),
      h('th', { scope: 'col', class: 'col-wide', title: 'Where the capability labels come from, and the confidence of that source' }, 'Labels'),
      h('th', { scope: 'col' }, 'Permission'), h('th', { scope: 'col', class: 'num' }, 'Calls'))),
    h('tbody', null, first.map(toolRow)), more)),
  button ? h('div', { class: 'card-foot' }, button, h('span', null, ` ${fmtInt(rest.length)} more. Used tools and tools that can be part of a toxic path are listed first.`)) : null];
}

function credentialChip(c) {
  const name = typeof c === 'string' ? c : c.name;
  const literal = typeof c === 'object' && c.literal;
  return h('span', { class: 'chip', title: literal
    ? 'The value is written in the configuration file in clear text. Only the name is recorded here.'
    : 'Name of a credential the server is given. Values are never recorded.' },
  icon('key'), h('span', { class: 'chip-text' }, name), literal ? h('span', { class: 'chip-key' }, 'value in file') : null);
}

function serverCard(server, tools) {
  const facts = [
    server.transport ? h('span', { class: 'chip' }, h('span', { class: 'chip-key' }, 'transport'), h('span', { class: 'chip-text' }, server.transport)) : null,
    server.scope && server.scope !== server.transport ? h('span', { class: 'chip' }, h('span', { class: 'chip-key' }, 'scope'), h('span', { class: 'chip-text' }, server.scope)) : null,
    server.enabled === false ? h('span', { class: 'chip chip-off' }, icon('deny'), 'disabled') : null,
    ...list(server.risk_flags).map((flag) => h('span', { class: 'chip', title: 'A setting that widens what this server can reach' }, h('span', { class: 'chip-key' }, 'risk'), h('span', { class: 'chip-text' }, flag))),
    ...list(server.credentials).filter((c) => c && (typeof c === 'string' || c.name)).map(credentialChip),
  ].filter(Boolean);
  const where = [server.command, server.url_host, server.source_file ? `declared in ${server.source_file}` : null].filter(Boolean).join(' \u00b7 ');
  return h('section', { class: `card server-card${server.enabled === false ? ' is-disabled' : ''}`, dataset: { server: server.name } },
    h('div', { class: 'card-head' },
      h('h3', { class: 'server-name' }, icon('server'), h('span', { class: 'mono' }, server.name), h('span', { class: 'muted server-count' }, plural(tools.length, 'tool'))),
      facts.length ? h('div', { class: 'chips' }, facts) : null),
    where ? h('p', { class: 'server-where mono wrap-anywhere' }, where) : null,
    server.status ? h('p', { class: 'server-where' }, `Status: ${server.status}`) : null,
    server.observedOnly ? h('p', { class: 'server-where' }, 'Seen in recorded sessions; no scan has described this server.') : null,
    server.enabled === false ? h('p', { class: 'server-where' }, 'Disabled in the configuration: these tools are not available to the agent.') : null,
    tools.length ? toolsTable(tools) : h('p', { class: 'card-body muted' }, 'No tools are listed for this server.'));
}

function leg(cap, row, scanned) {
  const tools = row ? row.tools : 0;
  // After a scan it is known which tools run without asking; before one it is not.
  const sub = !scanned ? (tools === 1 ? 'tool seen in sessions' : 'tools seen in sessions')
    : `${tools === 1 ? 'tool' : 'tools'}, ${fmtInt(row ? row.open : 0)} run unasked`;
  return h('div', { class: `leg leg-${cap.role}`, dataset: { capability: cap.key } },
    h('div', { class: 'leg-head' }, icon(cap.icon), cap.label),
    h('div', { class: 'leg-value' }, fmtInt(tools)),
    h('div', { class: 'leg-sub' }, sub));
}

/** The toxic-path summary of one agent: the three legs, and how many combinations are open. */
function toxicPanel(legs, totals, groups, scanned) {
  const [untrusted, privateData, sink] = CAPABILITIES;
  const byCap = new Map(legs.map((row) => [row.capability, row]));
  const tiles = h('div', { class: 'legs' }, leg(untrusted, byCap.get('untrusted_input'), scanned),
    leg(privateData, byCap.get('private_data'), scanned), leg(sink, byCap.get('external_sink'), scanned));
  const what = 'A toxic path is one tool that can bring in untrusted content, one that can reach private data and one that can send data out, all on the same agent. An injected instruction needs all three.';
  if (!scanned) {
    const complete = PATH_CAPS.every((c) => (byCap.get(c)?.tools ?? 0) > 0);
    return h('div', { class: 'toxic toxic-unknown', dataset: { scanned: 'false' } }, h('div', { class: 'toxic-main' },
      h('p', { class: 'toxic-headline' }, icon('note'), complete ? 'The tools seen in sessions cover all three legs of a toxic path' : 'The tools seen in sessions do not cover all three legs'),
      h('p', { class: 'toxic-detail' }, what),
      h('p', { class: 'muted toxic-note' }, 'Which combinations run without approval is known only after a scan has read the permission rules.')), tiles);
  }
  const paths = totals ? totals.paths : 0;
  const open = totals ? totals.open_paths : 0;
  const headline = open > 0 ? `${plural(open, 'toxic path')} ${open === 1 ? 'is' : 'are'} open: the sink runs without asking anyone`
    : paths > 0 ? `No open toxic path: every one of the ${plural(paths, 'combination')} waits for an approval at the sink`
      : 'No toxic path: at least one of the three legs is missing or refused';
  const detail = open > 0 && paths > open ? ` ${fmtInt(paths)} combinations exist in all; ${fmtInt(paths - open)} of them are held by an approval at the sink.` : '';
  return h('div', { class: `toxic${open > 0 ? ' toxic-open' : ''}`, dataset: { scanned: 'true', paths, open } },
    h('div', { class: 'toxic-main' },
      h('p', { class: 'toxic-headline' }, icon(open > 0 ? 'untrusted' : 'allow'), headline),
      h('p', { class: 'toxic-detail' }, what, detail),
      groups.length ? h('ol', { class: 'toxic-groups' }, groups.slice(0, 5).map((g) => h('li', null,
        h('span', { class: 'mono' }, g.source), h('span', { class: 'toxic-arrow', 'aria-label': 'then' }, '\u2192'),
        h('span', { class: 'mono' }, g.data), h('span', { class: 'toxic-arrow', 'aria-label': 'then' }, '\u2192'),
        h('span', { class: 'mono' }, g.sink), h('span', { class: 'muted' }, ` ${plural(g.paths, 'path')}, ${fmtInt(g.open_paths)} open`)))) : null,
      groups.length ? h('p', { class: 'muted toxic-note' }, `Source server, data server, sink server${groups.length > 5 ? `; the largest 5 of ${totals ? totals.groups : groups.length} combinations` : ''}. `,
        h('code', null, 'tainttrail paths'), ' scores them and ', h('code', null, 'tainttrail fix'), ' proposes the smallest change that breaks them.') : null),
    tiles);
}

export async function mapView(ctx) {
  const agents = (await ctx.q('Agents', MAP_AGENTS)).rows;
  const servers = (await ctx.q('Servers and the credentials they hold (names only)', MAP_SERVERS)).rows;
  const tools = (await ctx.q('Tools, capabilities, permissions and use', MAP_TOOLS)).rows;
  const legs = (await ctx.q('The three legs of a toxic path, per agent', MAP_LEGS)).rows;
  const totals = new Map((await ctx.q('Toxic paths per agent', MAP_PATH_TOTALS)).rows.map((r) => [r.agent, r]));
  const groups = (await ctx.q('Toxic paths by source, data and sink server', MAP_PATH_GROUPS)).rows;

  const head = pageHead({ eyebrow: h('a', { href: '#/' }, 'Overview'), title: 'Capability map',
    lede: 'What each agent can reach before anything runs: the servers it connects to, the tools they provide, what those tools can do and whether they need approval.' });
  if (!agents.length && !tools.length) {
    return h('div', { class: 'view view-map' }, head, card({}, emptyState('No agents or tools in this export.',
      'Run tainttrail scan to read the agent configuration into the graph, then export again.')));
  }
  const anyScan = servers.length > 0;
  const agentIds = [...new Set([...agents.map((a) => a.id), ...tools.map((t) => t.agent)])].sort();
  const sections = agentIds.map((id) => {
    const agent = agents.find((a) => a.id === id) ?? { id, name: id, config_paths: [], problems: [], permission_mode: '', servers: 0, sessions: 0 };
    const mine = tools.filter((t) => t.agent === id);
    const scanned = servers.some((s) => s.agent === id);
    const cards = servers.filter((s) => s.agent === id).map((s) => serverCard(s, mine.filter((t) => t.server_id === s.id)));
    // Tools no server PROVIDES: seen in a session, never described by a scan.
    const loose = new Map();
    for (const t of mine.filter((x) => !x.server_id)) loose.set(t.server, [...(loose.get(t.server) ?? []), t]);
    for (const [name, list] of loose) cards.push(serverCard({ name, observedOnly: true, credentials: [] }, list));
    return h('section', { class: 'agent', dataset: { agent: id } },
      h('div', { class: 'agent-head' },
        h('h2', null, icon('agent'), agent.name, agent.name !== id ? h('span', { class: 'muted mono agent-id' }, id) : null),
        h('span', { class: 'muted' }, `${plural(cards.length, 'server')}, ${plural(mine.length, 'tool')}, ${plural(agent.sessions, 'recorded session')}${agent.permission_mode ? `, permission mode ${agent.permission_mode}` : ''}`)),
      list(agent.config_paths).length ? h('p', { class: 'muted agent-config' }, 'Configuration read from ', list(agent.config_paths).map((p, i) => [i ? ', ' : '', h('code', null, breakable(p))])) : null,
      list(agent.problems).length ? h('ul', { class: 'alert alert-info agent-problems' }, list(agent.problems).map((p) => h('li', null, p))) : null,
      toxicPanel(legs.filter((l) => l.agent === id), totals.get(id), groups.filter((g) => g.agent === id), scanned),
      h('div', { class: 'server-grid' }, cards));
  });

  return h('div', { class: 'view view-map' }, head,
    anyScan ? null : h('p', { class: 'alert alert-info', id: 'no-scan-note', role: 'note' }, icon('note'),
      h('span', null, 'No scan has been recorded in this export. The tools below are the ones seen in recorded sessions, with the labels the guard gave them. Run ',
        h('code', null, 'tainttrail scan'), ' to map every configured server, tool and permission.')),
    sections);
}
