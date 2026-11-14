// db.js: the page-side half of the engine. The page never imports Relate; every call is a
// message to worker.js and comes back as a plain object.
//
// The store is treated as a cache of the export it was loaded from. The engine has no statement
// timeout, and an engine that trapped cannot be used again, so on a timeout or a trap this client
// terminates the worker, starts a new one and loads the same export again before the next call.

const DEFAULT_TIMEOUT_MS = 20_000;
const SEED_TIMEOUT_MS = 120_000;

/**
 * @param {object} [options]
 * @param {(stats: object) => void} [options.onStats]  called after every statement and restart
 */
export function createClient({ onStats = () => {} } = {}) {
  const workerUrl = new URL('./worker.js', import.meta.url);
  const pending = new Map(); // id -> { resolve, reject, timer }
  let nextId = 0;
  let worker = null;
  let seeded = null; // the export of the last successful load, replayed after a restart
  let restored = Promise.resolve(); // settles when the replay on the current worker has finished
  let broken = null; // set when that replay failed
  let fatal = null; // set when worker.js or the engine cannot be loaded at all

  const stats = { statements: 0, lastMs: null, lastStatement: '', totalMs: 0, restarts: 0 };

  function settle(id, how, value) {
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id);
    clearTimeout(entry.timer);
    entry[how](value);
  }

  function failAll(error) {
    for (const id of [...pending.keys()]) settle(id, 'reject', error);
  }

  function spawn() {
    worker = new Worker(workerUrl, { type: 'module' });
    worker.onmessage = ({ data }) => {
      if (data.ok) {
        settle(data.id, 'resolve', data.result);
        return;
      }
      settle(data.id, 'reject', Object.assign(new Error(data.error), { trap: data.trap === true, intact: data.intact === true }));
      if (data.trap) restart(new Error(`The engine stopped (${data.error}) and was restarted.`));
    };
    // Fires when worker.js or one of its imports cannot be loaded (404, wrong MIME type, CSP).
    // Browsers give no message for a failed module fetch, so name the usual causes.
    worker.onerror = (event) => {
      event.preventDefault?.();
      fatal = new Error(
        `The Relate engine could not be started (${event.message || 'worker.js, relate/relate.js or relate/relate_bg.wasm did not load'}). ` +
          'The viewer must be served over http, with a JavaScript MIME type for .js files.',
      );
      failAll(fatal);
    };
  }

  function restart(reason) {
    worker.terminate(); // the only way to stop a running statement, and to give its memory back
    failAll(reason);
    stats.restarts += 1;
    spawn();
    const replay = seeded;
    seeded = null; // so that a replay which itself fails is not replayed for ever
    restored = Promise.resolve();
    if (replay) {
      restored = post('seed', { graph: replay }, SEED_TIMEOUT_MS).then(
        () => { seeded = replay; },
        (error) => { broken = new Error(`The graph could not be loaded again after a restart (${error.message}). Reload the page.`); },
      );
    }
    onStats({ ...stats });
  }

  function post(op, args, limit) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => {
        settle(id, 'reject', Object.assign(new Error(`No answer within ${Number((limit / 1000).toFixed(1))} s. The statement was stopped and the graph reloaded.`), { timeout: true }));
        restart(new Error('The engine was restarted because another statement ran too long.'));
      }, limit);
      pending.set(id, { resolve, reject, timer });
      try {
        worker.postMessage({ id, op, ...args }); // throws DataCloneError for a function, a DOM node, ...
      } catch (error) {
        settle(id, 'reject', error);
      }
    });
  }

  async function call(op, args = {}, limit = DEFAULT_TIMEOUT_MS) {
    if (fatal) throw fatal;
    await restored; // never rejects
    if (fatal) throw fatal;
    if (broken && op !== 'seed') throw broken;
    return post(op, args, limit);
  }

  function record(statement, envelope) {
    stats.statements += 1;
    stats.lastMs = typeof envelope.elapsed_ms === 'number' ? envelope.elapsed_ms : envelope.wallMs ?? null;
    stats.lastStatement = statement;
    stats.totalMs += stats.lastMs ?? 0;
    onStats({ ...stats });
  }

  spawn();

  return {
    /** { version, initMs, memoryBytes } */
    info: () => call('info'),

    /**
     * Run ONE statement. Resolves with its envelope { columns, columnTypes, rows, stats,
     * elapsed_ms, ..., error: null }; rejects with an Error carrying the engine's own message.
     * `params` is a plain object. options.graph adds envelope.graph = { nodes, rels }.
     */
    async run(statement, params = null, options = {}) {
      const envelope = await call('exec', { statement, params, graph: options.graph === true }, options.timeoutMs);
      record(statement, envelope);
      if (envelope.error !== null) throw Object.assign(new Error(envelope.error), { envelope, statementError: true });
      return envelope;
    },

    /**
     * Empty the store and load one export: { nodes: [{id, labels, props}], rels: [{type, start, end, props}] }.
     * When the load fails, the export that was loaded before is still (or again) in the store.
     */
    async seed(graph) {
      let result;
      try {
        result = await call('seed', { graph }, SEED_TIMEOUT_MS);
      } catch (error) {
        // error.intact: refused before the store was touched. A trap or a timeout: restart()
        // already replays the previous export. Otherwise the worker emptied its store before
        // the load failed, so put back what was there.
        if (seeded && seeded !== graph && !error.intact && !error.trap && !error.timeout) {
          try {
            await call('seed', { graph: seeded }, SEED_TIMEOUT_MS);
          } catch {
            // The caller hears about the first failure; the page then finds the store empty.
          }
        }
        throw error;
      }
      seeded = graph;
      broken = null;
      return result;
    },

    /** Load the last export again, discarding anything a statement changed. */
    async reload() {
      if (!seeded) throw new Error('No graph is loaded.');
      return this.seed(seeded);
    },

    get stats() {
      return { ...stats };
    },
  };
}

// ---- reading graph values out of an envelope ----------------------------------------------

export const isNode = (v) => v !== null && typeof v === 'object' && v.kind === 'node';
export const isRelationship = (v) => v !== null && typeof v === 'object' && v.kind === 'relationship';

/**
 * A PATH arrives as a flat array [node, rel, node, ..., node] with no wrapper. The column type
 * says PATH for a top-level column; this shape test covers paths nested in lists and maps.
 */
export const isPath = (v) =>
  Array.isArray(v) && v.length % 2 === 1 && v.length > 1 && v.every((item, i) => (i % 2 === 0 ? isNode(item) : isRelationship(item)));

/**
 * The id TaintTrail gave a node: its `id` property, or `cap:<name>` for a capability, which is
 * how exports and stored attack paths name it. The engine's own node.id is an internal counter.
 */
export function nodeKey(node) {
  const p = node.properties ?? {};
  if ((node.labels ?? []).includes('Capability') && p.id === undefined) return `cap:${p.name}`;
  return p.id === undefined ? `#${node.id}` : String(p.id);
}
