// Attack path of one finding: the stored path as a diagram, the explanation in plain language,
// and the Cypher query that found it, which runs here in the browser at the press of a button.

import { h, clear, icon, breakable, fmtBytes, fmtMs, fmtTime, plural, shortId } from '../dom.js';
import { cypherBlock } from '../cypher.js';
import { isPath, nodeKey } from '../db.js';
import { FINDING, FINDING_EVIDENCE, FINDINGS } from '../queries.js';
import { card, consoleHref, emptyState, pageHead, resultJson, resultTable, roleTag, severity, verdict, sessionHref, ROLE_NAME } from '../ui.js';
import { findingItem } from './overview.js';

const NODE_MIN = 150; // px a node needs to stay readable side by side
const EDGE_MIN = 84;
const MAX_STEPS = 40; // a stored path has a handful of steps; a file claiming thousands is not drawn in full

function parseJson(text, fallback) {
  try {
    const value = JSON.parse(text);
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

/** The stored steps, with anything malformed dropped rather than trusted. */
function pathSteps(pathJson) {
  const raw = parseJson(pathJson ?? '[]', []);
  if (!Array.isArray(raw)) return [];
  return raw.filter((s) => s && typeof s === 'object').slice(0, MAX_STEPS).map((s) => ({
    nodeId: String(s.node_id ?? ''), label: String(s.label ?? ''), title: String(s.title ?? s.node_id ?? ''),
    rel: typeof s.rel === 'string' && s.rel ? s.rel : null, forward: s.forward !== false,
    role: Object.hasOwn(ROLE_NAME, s.role) ? s.role : 'entity',
  }));
}

/** A relationship type is upper case; anything else ("in the same session") is shared context. */
const isStoredEdge = (rel) => rel !== null && rel === rel.toUpperCase() && /[A-Z]/.test(rel);

function fact(...children) {
  return h('li', null, children);
}

/** A few facts about a path node, read from the graph (the EVIDENCE query), by node label. */
function nodeFacts(step, props) {
  if (!props) return [fact(h('span', { class: 'muted' }, 'This node is not in the export.'))];
  const facts = [];
  if (step.label === 'Content') {
    if (props.injection_score >= 0.3) {
      facts.push(fact(`Reads like instructions: score ${Number(props.injection_score).toFixed(2)}`,
        Array.isArray(props.injection_markers) && props.injection_markers.length ? h('span', { class: 'muted' }, ` (${props.injection_markers.join(', ')})`) : null));
    }
    if (typeof props.bytes === 'number' && props.bytes > 0) facts.push(fact(`${fmtBytes(props.bytes)} entered the context`));
    if (props.sensitive) facts.push(fact('Excerpt withheld: only keyed fingerprints of sensitive text are stored'));
    else if (props.excerpt) facts.push(h('li', { class: 'fact-excerpt' }, h('blockquote', { class: 'excerpt', title: props.excerpt }, props.excerpt)));
  } else if (step.label === 'ToolCall') {
    facts.push(fact(h('span', { class: 'mono' }, String(props.tool ?? '')), props.is_sink ? ', an outbound call' : ''));
    if (props.status === 'blocked') facts.push(fact('Blocked before it ran'));
  } else if (step.label === 'Chunk') {
    facts.push(fact(`Keyed fingerprint of a ${props.kind ?? 'text'}${props.hint ? ` (${props.hint})` : ''}${props.length ? `, ${props.length} characters` : ''}`));
    facts.push(fact('The value itself is never stored'));
  } else if (step.label === 'Entity') {
    const kind = String(props.kind ?? 'entity');
    facts.push(fact(h('span', { class: 'mono' }, breakable(props.value ?? ''))));
    if (['host', 'url', 'repo', 'email', 'mcp'].includes(kind)) {
      facts.push(fact(props.local ? 'On this machine or network' : props.trusted ? 'On the trusted list' : `${kind === 'host' ? 'Host' : 'Destination'} outside the machine, not on the trusted list`));
    }
    if (props.sensitive) facts.push(fact('Holds sensitive data'));
    if (props.protected) facts.push(fact('Loaded or run automatically later'));
  }
  return facts;
}

function nodeTitle(step) {
  // A call title is stored as "call #3  Bash: curl ..."; the number goes into the role tag.
  const m = step.role === 'call' ? /^call #(\S{1,12})\s+([\s\S]*)$/.exec(step.title) : null;
  return m ? { tag: `Call #${m[1]}`, title: m[2], mono: true } : { tag: null, title: step.title, mono: false };
}

function buildPath(steps, evidence, finding) {
  const items = [];
  steps.forEach((step, i) => {
    const props = evidence.get(i) ?? null;
    const { tag, title, mono } = nodeTitle(step);
    const inspect = step.label && step.nodeId
      ? consoleHref(`MATCH (n:${step.label} {id: $id})-[r]-(m)\nRETURN type(r) AS relationship, startNode(r) = n AS outgoing, labels(m) AS labels, coalesce(m.id, m.name) AS node\nORDER BY relationship, node`, { id: step.nodeId })
      : null;
    items.push(h('li', { class: `path-node role-${step.role}`, dataset: { nodeId: step.nodeId, index: i } },
      h('div', { class: 'path-node-head' }, roleTag(step.role, tag),
        // Every call shows what was decided about it. What the rule called for ("would be
        // denied") belongs only to the call the finding is about, not to an earlier call
        // that happens to lie on the path.
        step.label === 'ToolCall' && props
          ? verdict(props.decision ?? 'allow', step.nodeId === finding.target_id ? finding.intended : undefined) : null),
      h('p', { class: `path-node-title${mono ? ' mono' : ''}` }, breakable(title)),
      h('ul', { class: 'path-node-facts' }, nodeFacts(step, props)),
      h('div', { class: 'path-node-foot' },
        h('span', { class: 'path-node-hit', hidden: true, title: 'This node was returned by the query' }, icon('allow'), 'in the result'),
        h('span', { class: 'path-node-other', hidden: true, title: 'More than one node fits this step of the pattern. The query returned another one.' }, icon('note'), 'another one returned'),
        inspect && /^[A-Za-z]+$/.test(step.label) ? h('a', { class: 'path-node-inspect', href: inspect, title: 'Show this node\u2019s neighbours in the console' }, 'Inspect') : null)));
    if (i === steps.length - 1) return;
    const stored = isStoredEdge(step.rel);
    const direction = !stored ? 'context' : step.forward ? 'forward' : 'backward';
    const words = !stored ? `${step.rel ?? 'related'} (shared context, not a stored relationship)`
      : step.forward ? `${step.rel}: from the node before to the node after` : `${step.rel}: from the node after to the node before`;
    items.push(h('li', { class: `path-edge path-edge-${direction}`, dataset: { index: i, rel: step.rel ?? '' }, 'aria-label': words, title: words },
      h('span', { class: 'path-edge-label' }, step.rel ?? ''),
      h('span', { class: 'path-edge-line', 'aria-hidden': 'true' })));
  });
  const list = h('ol', { class: 'path', dataset: { steps: steps.length } }, items);
  // Side by side when there is room, stacked when there is not (a phone, or a long path).
  const needed = steps.length * NODE_MIN + Math.max(0, steps.length - 1) * EDGE_MIN;
  new ResizeObserver(() => list.classList.toggle('path-stacked', list.clientWidth > 0 && list.clientWidth < needed)).observe(list);
  return list;
}

/** Mark the diagram with what the query returned. Returns counts for the status line. */
function highlight(list, steps, graph) {
  const internal = new Map(graph.nodes.map((n) => [nodeKey(n), n.id])); // TaintTrail id -> engine id
  let nodes = 0;
  for (const el of list.querySelectorAll('.path-node')) {
    const hit = internal.has(el.dataset.nodeId);
    el.classList.toggle('is-hit', hit);
    el.classList.toggle('is-miss', !hit);
    el.classList.remove('is-other');
    el.querySelector('.path-node-hit').hidden = !hit;
    el.querySelector('.path-node-other').hidden = true;
    if (hit) nodes += 1;
  }
  let edges = 0;
  let storedEdges = 0;
  for (const el of list.querySelectorAll('.path-edge')) {
    const i = Number(el.dataset.index);
    const step = steps[i];
    if (!isStoredEdge(step.rel)) continue;
    storedEdges += 1;
    const a = internal.get(step.nodeId);
    const b = internal.get(steps[i + 1].nodeId);
    // The stored direction must match too: `forward` says the edge leaves this step.
    const [from, to] = step.forward ? [a, b] : [b, a];
    const hit = a !== undefined && b !== undefined && graph.rels.some((r) => r.type === step.rel && r.start_node === from && r.end_node === to);
    el.classList.toggle('is-hit', hit);
    if (hit) edges += 1;
  }
  return { nodes, edges, storedEdges };
}

const KIND_WORD = { Chunk: 'fingerprint', Content: 'piece of content', Entity: 'entity', ToolCall: 'call' };

/**
 * The steps at which the query returned a different node than the stored path shows, when
 * the returned path has the stored path's shape (the same labels and relationship types in
 * the same places). A path query ends in LIMIT 1, and when several nodes fit one step, for
 * example three fingerprints of the same secret file, a second run may keep another one.
 * Returns [] when the result is not such a path.
 */
function otherMatches(steps, envelope) {
  const row = envelope.rows[0];
  const path = row ? (envelope.columns ?? []).map((name) => row[name]).find((value) => isPath(value)) : null;
  if (!path || (path.length + 1) / 2 !== steps.length) return [];
  const others = [];
  for (let i = 0; i < steps.length; i += 1) {
    const node = path[i * 2];
    if (!(node.labels ?? []).includes(steps[i].label)) return [];
    if (i < steps.length - 1 && isStoredEdge(steps[i].rel) && path[i * 2 + 1].type !== steps[i].rel) return [];
    if (nodeKey(node) !== steps[i].nodeId) others.push(i);
  }
  return others.length < steps.length ? others : [];
}

/**
 * The stored query of a finding: a bar with the Run button (it goes right under the diagram,
 * so the button and what it highlights are on screen together) and a card with the Cypher
 * text, its parameters and, after a run, the result.
 */
function queryParts(ctx, finding, steps, list) {
  const params = parseJson(finding.params_json ?? '{}', {});
  const safeParams = params && typeof params === 'object' && !Array.isArray(params) ? params : {};
  if (!finding.query) {
    return { bar: null, card: card({ title: 'Cypher query' }, h('div', { class: 'card-body' },
      h('p', { class: 'muted' }, steps.length <= 1
        ? 'This finding is about a single node, so no path query was stored with it.'
        : 'No query was stored with this finding.'))) };
  }
  const status = h('p', { class: 'run-status', id: 'run-status', role: 'status', 'aria-live': 'polite' },
    'The guard stored the Cypher query that found this path. Run it here, in this tab, to see the same path come back.');
  const result = h('div', { class: 'run-result', id: 'run-result' });
  const button = h('button', { type: 'button', class: 'btn btn-primary', id: 'run-query' }, icon('play'), 'Run query');
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.className = 'run-status';
    status.textContent = 'Running in Relate WASM\u2026';
    try {
      const envelope = await ctx.runGuarded(finding.query, safeParams, { graph: true });
      const graph = envelope.graph ?? { nodes: [], rels: [] };
      const { nodes, edges, storedEdges } = highlight(list, steps, graph);
      const allNodes = envelope.rows.length > 0 && nodes === steps.length;
      // A rule that returns nodes instead of a path (RETURN u, c, s) has no relationships to mark.
      const nodesOnly = allNodes && graph.rels.length === 0 && storedEdges > 0;
      const all = allNodes && edges === storedEdges;
      const others = all || nodesOnly ? [] : otherMatches(steps, envelope);
      for (const i of others) {
        const el = list.querySelector(`.path-node[data-index="${i}"]`);
        el.classList.add('is-other');
        el.querySelector('.path-node-other').hidden = false;
      }
      status.classList.add(all || nodesOnly ? 'run-ok' : 'run-partial');
      status.dataset.hitNodes = String(nodes);
      status.dataset.hitEdges = String(edges);
      status.dataset.otherNodes = String(others.length);
      const ran = `Ran in ${fmtMs(envelope.elapsed_ms)} on Relate WASM`;
      const counts = `${plural(envelope.rows.length, 'row')}, ${plural(graph.nodes.length, 'node')} and ${plural(graph.rels.length, 'relationship')}`;
      const kind = others.length === 1 && Object.hasOwn(KIND_WORD, steps[others[0]].label) ? KIND_WORD[steps[others[0]].label] : 'node';
      const where = others.length === 1 ? `another ${kind} at step ${others[0] + 1}` : `other nodes at ${plural(others.length, 'step')}`;
      status.textContent = envelope.rows.length === 0
        ? `${ran} and returned no rows: this export does not hold the whole path.`
        : all ? `${ran}: ${counts}. All ${steps.length} nodes of the diagram${storedEdges ? ` and its ${plural(storedEdges, 'relationship')}` : ''} are in the result.`
          : nodesOnly ? `${ran}: ${counts}. All ${steps.length} nodes of the diagram are in the result. This query returns nodes, not a path, so no relationship is marked.`
            : others.length ? `${ran}: ${counts}. The query found the same pattern with ${where}: more than one node fits there, and the query keeps one. ${nodes} of ${steps.length} diagram nodes are in the result.`
              : `${ran}: ${counts}. ${nodes} of ${steps.length} diagram nodes and ${edges} of ${storedEdges} relationships are in the result; the others are shown for context.`;
      const table = resultTable(envelope);
      const json = resultJson(envelope);
      json.hidden = true;
      const toggle = h('button', { type: 'button', class: 'btn btn-small', 'aria-pressed': 'false' }, 'Show as JSON');
      toggle.addEventListener('click', () => {
        const showJson = json.hidden;
        json.hidden = !showJson;
        table.hidden = showJson;
        toggle.setAttribute('aria-pressed', String(showJson));
        toggle.textContent = showJson ? 'Show as table' : 'Show as JSON';
      });
      clear(result).append(h('div', { class: 'run-result-head' }, h('h3', null, 'Result'), toggle), table, json);
    } catch (error) {
      status.classList.add('run-error');
      status.textContent = error.message;
      clear(result);
    } finally {
      button.disabled = false;
    }
  });
  const paramList = Object.keys(safeParams).length
    ? h('dl', { class: 'params' }, Object.entries(safeParams).map(([key, value]) => [h('dt', null, `$${key}`), h('dd', null, JSON.stringify(value))]))
    : null;
  return {
    bar: h('div', { class: 'run-bar path-run' }, button, status),
    card: card({ title: 'The Cypher query that found this path', note: 'stored on the finding by the guard',
      actions: h('a', { class: 'btn btn-small', href: consoleHref(finding.query, safeParams) }, 'Open in console') },
    h('div', { class: 'card-body query-body' }, cypherBlock(finding.query), paramList, result)),
  };
}

export async function findingView(ctx, route) {
  if (!route.arg) return findingsView(ctx);
  const finding = (await ctx.q('The finding', FINDING, { id: route.arg })).rows[0];
  if (!finding) return emptyState('No such finding.', `There is no finding ${route.arg} in this export.`, h('a', { class: 'btn', href: '#/findings' }, 'All attack paths'));
  const evidence = new Map((await ctx.q('Path nodes, as they are in the graph', FINDING_EVIDENCE, { id: finding.id })).rows.map((r) => [r.ord, r.props]));
  const steps = pathSteps(finding.path_json);
  if (finding.session_id) ctx.state.lastSession = finding.session_id;

  const crumbs = [h('a', { href: '#/findings' }, 'Attack paths'),
    finding.session_id ? [' / ', h('a', { href: sessionHref(finding.session_id), title: finding.session_id }, `session ${shortId(finding.session_id)}`)] : null,
    finding.call_num ? ` / call #${finding.call_num}` : null];
  const list = steps.length ? buildPath(steps, evidence, finding) : null;
  const roles = [...new Set(steps.map((s) => s.role))];
  const query = list ? queryParts(ctx, finding, steps, list) : { bar: null, card: null };

  return h('div', { class: 'view view-finding' },
    pageHead({ eyebrow: crumbs, title: finding.title || finding.name || finding.id }),
    h('div', { class: 'finding-meta' }, verdict(finding.action, finding.intended, { kind: 'finding' }),
      h('span', { class: 'rule' }, finding.rule), h('span', { class: 'muted' }, finding.name ?? ''), severity(finding.severity),
      h('span', { class: 'muted nowrap' }, fmtTime(finding.ts, { seconds: true }))),
    finding.explanation ? h('p', { class: 'explanation' }, finding.explanation) : null,
    card({ title: 'Attack path', note: steps.length ? `${plural(steps.length, 'node')}, arrows follow the stored relationships`: null, cls: 'path-card',
      actions: roles.length ? h('div', { class: 'legend', 'aria-label': 'Roles on this path' }, roles.map((r) => roleTag(r))) : null },
      h('div', { class: 'card-body path-body' }, list ?? emptyState('No path was recorded for this finding.'), query.bar)),
    query.card,
    h('p', { class: 'muted finding-id' }, 'Finding ', h('code', { class: 'wrap-anywhere' }, finding.id)));
}

export async function findingsView(ctx) {
  const findings = (await ctx.q('Findings, the ones that held a call first', FINDINGS, { sid: null })).rows;
  return h('div', { class: 'view view-findings' },
    pageHead({ eyebrow: h('a', { href: '#/' }, 'Overview'), title: 'Attack paths',
      lede: 'Every finding carries the path through the graph that explains it and the Cypher query that found that path. Findings that held a call come first.' }),
    card({ title: plural(findings.length, 'finding') },
      findings.length ? h('ul', { class: 'finding-list finding-list-wide' }, findings.map(findingItem))
        : emptyState('No findings.', 'No rule matched in any recorded session, so there is no attack path to show.')));
}
