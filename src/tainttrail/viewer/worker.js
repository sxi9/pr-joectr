// worker.js: an ES module worker that owns ONE in-memory Relate database.
//
//   page   -> worker   { id, op, ...args }
//   worker -> page     { id, ok: true, result } | { id, ok: false, error, trap, intact }
//                      (intact: a seed was refused before the store was touched)
//
//   info                                 -> { version, initMs, memoryBytes }
//   exec   { statement, params, graph }  -> the envelope of ONE statement, parsed, plus wallMs;
//                                           with graph: true also envelope.graph = { nodes, rels },
//                                           each node and relationship of the result once
//   seed   { graph }                     -> { nodes, rels, labels, statements, ms, memoryBytes }
//                                           (empties the store first: one export at a time)
//   reset                                -> { memoryBytes }
//
// No bundler: the imports are plain relative URLs, and relate.js resolves ./snippets/ and
// ./relate_bg.wasm against itself. Keep relate/ intact.
import init, { RelateDb, renderResult } from './relate/relate.js';
import { isWasmTrap } from './relate/trap.js';

const BATCH = 500; // rows per UNWIND statement: keeps the memory peak low, time is per row anyway
const MAX_KEY_LABELS = 64; // a TaintTrail export has eleven; a file with hundreds is not one

let wasm = null; // InitOutput; wasm.memory is the engine's linear memory (it only grows)
let db = null;

// onmessage is assigned synchronously below and awaits this promise, so a message that arrives
// while the engine is still compiling waits its turn instead of being lost.
const ready = (async () => {
  const t0 = performance.now();
  wasm = await init();
  db = new RelateDb(); // in memory and writable. new RelateDb(true) would be read-only AND empty.
  return { initMs: performance.now() - t0 };
})();

/** Run one statement and return its envelope as text. A statement error does not throw. */
function executeText(statement, params) {
  // Both arguments must reach the glue as strings (params may be null). An object or a number
  // there is not rejected by the glue: it faults inside the engine.
  if (typeof statement !== 'string') throw new TypeError('statement must be a string');
  return db.execute(statement, params == null ? null : JSON.stringify(params));
}

/** Run one statement and throw on a statement error. Used for seeding only. */
function must(statement, params) {
  const envelope = JSON.parse(executeText(statement, params));
  if (envelope.error !== null) throw new Error(`${envelope.error} (while loading the graph)`);
  return envelope;
}

// ---- making an export loadable ------------------------------------------------------------

// A whole number of 2^63 or more is written out in full by JSON.stringify and then refused by
// the engine ("integer exceeds i64 range"), which would fail the whole batch. It is kept as text.
const I64_LIMIT = 2 ** 63;
const isStorableNumber = (v) => Number.isFinite(v) && !(Number.isInteger(v) && Math.abs(v) >= I64_LIMIT);
const isPrimitive = (v) => typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && isStorableNumber(v));

/**
 * One value as Relate can store it. Relate stores strings, booleans, numbers and lists of ONE of
 * those kinds. A map, a nested list, a mixed list or a list holding null would fail the whole
 * batch with a bare InvalidPropertyType, so such a value is stored as JSON text instead.
 * null and undefined drop the key.
 */
function storable(value) {
  if (value === null || value === undefined) return undefined;
  if (isPrimitive(value)) return value;
  if (typeof value === 'number' || typeof value === 'bigint') return String(value); // NaN, Infinity, 2^63 and beyond, BigInt
  if (Array.isArray(value)) {
    const kind = value.length ? typeof value[0] : 'string';
    if (value.every((item) => isPrimitive(item) && typeof item === kind)) return value;
  }
  return JSON.stringify(value);
}

function storableProps(props) {
  const out = {};
  if (props === null || typeof props !== 'object' || Array.isArray(props)) return out;
  for (const [key, value] of Object.entries(props)) {
    const v = storable(value);
    if (v !== undefined) out[key] = v;
  }
  return out;
}

// The only escaping a backtick-quoted identifier needs: double every backtick inside it.
const ident = (name) => '`' + String(name).replace(/`/g, '``') + '`';
const usableName = (name) => typeof name === 'string' && name !== '' && !name.includes('\u0000');

// The same keys the native store uses (schema.py): Capability nodes are unique by name, every
// other node by id. Keeping them makes the graph in this tab the graph of the .rl file, label
// for label, so a stored finding query runs here unchanged and with the same indexes.
const keyProp = (label) => (label === 'Capability' ? 'name' : 'id');

// Secondary indexes of the native schema, created when their label is present.
const SECONDARY_INDEXES = [
  ['ToolCall', 'session_id'], ['Content', 'session_id'], ['Finding', 'session_id'], ['Tool', 'name'], ['Entity', 'kind'],
];

/**
 * Turn {nodes:[{id,labels,props}], rels:[{type,start,end,props}]} into rows the engine accepts.
 * Throws with a message a person can act on when the file is not a consistent graph; nothing
 * has been written to the store at that point.
 */
function plan(graph) {
  if (graph === null || typeof graph !== 'object' || !Array.isArray(graph.nodes) || !Array.isArray(graph.rels)) {
    throw new Error('not a graph export: expected an object with "nodes" and "rels" lists');
  }
  const keys = new Map(); // export id -> { label, value }
  const keyLabels = new Map(); // key label -> its key property
  const taken = new Set(); // "label, type and value" of every key: the uniqueness the store will enforce
  const nodeRows = [];
  for (const [i, node] of graph.nodes.entries()) {
    if (node === null || typeof node !== 'object') throw new Error(`node ${i} is not an object`);
    const id = node.id;
    if (typeof id !== 'string' || id === '') throw new Error(`node ${i} has no id`);
    if (keys.has(id)) throw new Error(`two nodes share the id ${JSON.stringify(id)}`);
    const labels = [...new Set((Array.isArray(node.labels) ? node.labels : []).filter(usableName))];
    if (labels.length === 0) throw new Error(`node ${JSON.stringify(id)} has no label`);
    const label = labels[0];
    const prop = keyProp(label);
    const props = storableProps(node.props);
    if (props[prop] === undefined) {
      if (prop !== 'id') throw new Error(`node ${JSON.stringify(id)} (${label}) has no ${prop}`);
      props.id = id; // a node without an id of its own is addressed by its export id
    }
    if (!isPrimitive(props[prop])) throw new Error(`node ${JSON.stringify(id)} has a ${prop} that is not a plain value`);
    // Two export ids can carry the same key. Said here, before the store is emptied, it is a
    // message about the file; left to the uniqueness constraint it would be an engine error
    // half way through the load.
    const key = `${label}\u0000${typeof props[prop]}\u0000${props[prop]}`;
    if (taken.has(key)) throw new Error(`two ${label} nodes share the ${prop} ${JSON.stringify(props[prop])}`);
    taken.add(key);
    keys.set(id, { label, value: props[prop] });
    keyLabels.set(label, prop);
    nodeRows.push({ labels, props });
  }
  if (keyLabels.size > MAX_KEY_LABELS) {
    throw new Error(`${keyLabels.size} different node labels: this does not look like a TaintTrail export`);
  }

  const relGroups = new Map(); // "start label \0 end label" -> { a, b, rows }
  for (const [i, rel] of graph.rels.entries()) {
    if (rel === null || typeof rel !== 'object') throw new Error(`relationship ${i} is not an object`);
    if (!usableName(rel.type)) throw new Error(`relationship ${i} has no type`);
    const a = keys.get(rel.start);
    const b = keys.get(rel.end);
    if (!a || !b) {
      throw new Error(`relationship ${i} (${rel.type}) points at a node that is not in the file: ${JSON.stringify(a ? rel.end : rel.start)}`);
    }
    const groupKey = `${a.label}\u0000${b.label}`;
    let group = relGroups.get(groupKey);
    if (!group) relGroups.set(groupKey, (group = { a: a.label, b: b.label, rows: [] }));
    group.rows.push({ start: a.value, end: b.value, type: rel.type, props: storableProps(rel.props) });
  }
  return { keyLabels, nodeRows, relGroups, relCount: graph.rels.length };
}

/** Empty the store and load one export. Each UNWIND statement is atomic and commits on its own. */
function seed(graph) {
  const t0 = performance.now();
  let planned;
  try {
    planned = plan(graph);
  } catch (err) {
    err.intact = true; // refused before anything was written: the graph that was loaded is still there
    throw err;
  }
  const { keyLabels, nodeRows, relGroups, relCount } = planned;
  db.reset(); // drops data, indexes and constraints
  let statements = 0;
  try {
    // A uniqueness constraint per label: it is the index every id lookup needs (creating a
    // relationship without one costs a scan per endpoint) and it refuses a duplicate id.
    let n = 0;
    for (const [label, prop] of keyLabels) {
      must(`CREATE CONSTRAINT tt_key_${n++} IF NOT EXISTS FOR (n:${ident(label)}) REQUIRE n.${ident(prop)} IS UNIQUE`);
      statements += 1;
    }
    for (const [label, prop] of SECONDARY_INDEXES) {
      if (!keyLabels.has(label)) continue;
      must(`CREATE INDEX tt_idx_${n++} IF NOT EXISTS FOR (n:${ident(label)}) ON (n.${ident(prop)})`);
      statements += 1;
    }

    // Labels and relationship types travel as data (`:$(expr)`), never as statement text.
    let nodes = 0;
    for (let i = 0; i < nodeRows.length; i += BATCH) {
      nodes += must('UNWIND $rows AS r CREATE (n:$(r.labels)) SET n = r.props', { rows: nodeRows.slice(i, i + BATCH) }).stats.nodes_created;
      statements += 1;
    }

    let rels = 0;
    for (const { a, b, rows } of relGroups.values()) {
      // The two endpoint labels are the only identifiers in statement text, and they are quoted.
      const statement =
        `UNWIND $rows AS r MATCH (a:${ident(a)} {${ident(keyProp(a))}: r.start}) MATCH (b:${ident(b)} {${ident(keyProp(b))}: r.end}) ` +
        'CREATE (a)-[x:$(r.type)]->(b) SET x = r.props';
      for (let i = 0; i < rows.length; i += BATCH) {
        rels += must(statement, { rows: rows.slice(i, i + BATCH) }).stats.relationships_created;
        statements += 1;
      }
    }

    // MATCH drops a row whose endpoint it cannot find without saying so: compare the counters.
    if (nodes !== nodeRows.length || rels !== relCount) {
      throw new Error(`the graph did not load completely: ${nodes} of ${nodeRows.length} nodes and ${rels} of ${relCount} relationships`);
    }
    return { nodes, rels, labels: keyLabels.size, statements, ms: performance.now() - t0, memoryBytes: wasm.memory.buffer.byteLength };
  } catch (err) {
    try { db.reset(); } catch { /* a trapped engine cannot be reset; the page replaces the worker */ }
    throw err;
  }
}

// ---- message loop -------------------------------------------------------------------------

self.onmessage = async (event) => {
  const { id, op, ...args } = event.data;
  try {
    const boot = await ready;
    let result;
    switch (op) {
      case 'info': {
        const row = must("CALL dbms.components() YIELD name, versions WHERE name = 'Relate' RETURN versions[0] AS version").rows[0];
        result = { version: row ? row.version : 'unknown', initMs: boot.initMs, memoryBytes: wasm.memory.buffer.byteLength };
        break;
      }
      case 'exec': {
        const t0 = performance.now();
        const text = executeText(args.statement, args.params);
        result = JSON.parse(text);
        // renderResult walks every row (paths, lists and maps included) and returns each node
        // and relationship once: what a diagram needs to know which nodes a query returned.
        if (args.graph && result.error === null) result.graph = JSON.parse(renderResult([text])).graph ?? { nodes: [], rels: [] };
        result.wallMs = performance.now() - t0;
        break;
      }
      case 'seed':
        result = seed(args.graph);
        break;
      case 'reset':
        db.reset();
        result = { memoryBytes: wasm.memory.buffer.byteLength };
        break;
      default:
        throw new Error(`unknown op: ${op}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    // trap: true means the engine panicked or ran out of stack or memory. Its database handle is
    // then locked for good, so the page must terminate this worker and start a new one.
    const message = String(err?.message ?? err);
    const trap = isWasmTrap(err) || /recursive use of an object|attempted to take ownership of Rust value/.test(message);
    self.postMessage({ id, ok: false, error: message, trap, intact: err?.intact === true });
  }
};
