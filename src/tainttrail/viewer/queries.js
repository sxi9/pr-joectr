// queries.js: every Cypher statement the views run, in one place.
//
// The viewer keeps no model of its own. Each number, row and badge on screen is the result of
// one of these statements, executed by Relate in this browser tab. Each view lists the ones it
// ran, with their timings, under "Cypher behind this view".
//
// A flag is tested as `x.flag = true`, never as a bare `x.flag`: an export is a file anyone can
// write, and a flag that holds text instead of a boolean must read as "not set", not stop the
// statement with a type error.

export const GRAPH_NODES = 'MATCH (n) RETURN count(n) AS nodes';
export const GRAPH_RELS = 'MATCH ()-[r]->() RETURN count(r) AS rels';

export const TOTALS = `
MATCH (n)
RETURN sum(CASE WHEN n:Session THEN 1 ELSE 0 END) AS sessions,
       sum(CASE WHEN n:ToolCall THEN 1 ELSE 0 END) AS calls,
       sum(CASE WHEN n:ToolCall AND n.decision = 'ask' THEN 1 ELSE 0 END) AS asked,
       sum(CASE WHEN n:ToolCall AND n.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
       sum(CASE WHEN n:Finding THEN 1 ELSE 0 END) AS findings,
       sum(CASE WHEN n:Content AND n.untrusted = true THEN 1 ELSE 0 END) AS untrusted,
       sum(CASE WHEN n:Content AND n.sensitive = true THEN 1 ELSE 0 END) AS sensitive`.trim();

export const SESSIONS = `
MATCH (s:Session)
OPTIONAL MATCH (s)-[:RAN]->(c:ToolCall)
WITH s, count(c) AS calls,
     sum(CASE WHEN c.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
     sum(CASE WHEN c.decision = 'ask' THEN 1 ELSE 0 END) AS asked
OPTIONAL MATCH (f:Finding {session_id: s.id})
WITH s, calls, denied, asked, count(f) AS findings
OPTIONAL MATCH (s)-[:RECEIVED]->(p:Content {origin: 'user'})
WITH s, calls, denied, asked, findings, p ORDER BY p.seq
WITH s, calls, denied, asked, findings, collect(p.excerpt)[0] AS first_prompt
RETURN s.id AS id, s.started_at AS started_at, s.agent_kind AS agent, s.mode AS mode, s.cwd AS cwd,
       calls, asked, denied, findings, first_prompt
ORDER BY started_at DESC, id DESC`.trim();

export const SESSION_IDS = `
MATCH (s:Session)
RETURN s.id AS id, s.started_at AS started_at
ORDER BY started_at DESC, id DESC`.trim();

// Findings, the ones that held a call first. $sid null means every session.
export const FINDINGS = `
MATCH (f:Finding)
WHERE $sid IS NULL OR f.session_id = $sid
OPTIONAL MATCH (f)-[:FLAGS]->(c:ToolCall)
RETURN f.id AS id, f.rule AS rule, f.name AS name, f.severity AS severity, f.action AS action,
       coalesce(f.intended, f.action) AS intended, f.title AS title, f.session_id AS session_id,
       f.target_label AS target_label, f.ts AS ts, c.num AS call_num, c.tool AS tool
ORDER BY CASE WHEN f.action = 'deny' THEN 0 WHEN f.action = 'ask' THEN 1
              WHEN coalesce(f.intended, f.action) IN ['ask', 'deny'] THEN 2 ELSE 3 END,
         ts DESC, id DESC`.trim();

// Where calls sent data, and who had named each place: the user, trusted content, or only
// content a third party could have written.
export const DESTINATIONS = `
MATCH (c:ToolCall)-[:SENDS_TO]->(d:Entity)
WHERE NOT coalesce(d.local = true, false)
WITH d, count(c) AS calls,
     sum(CASE WHEN c.decision = 'deny' THEN 1 ELSE 0 END) AS denied,
     sum(CASE WHEN c.decision = 'ask' THEN 1 ELSE 0 END) AS asked,
     sum(CASE WHEN c.carries_payload = true THEN 1 ELSE 0 END) AS with_data
RETURN d.id AS id, d.kind AS kind, d.value AS value, coalesce(d.trusted = true, false) AS trusted, calls, denied, asked, with_data,
       EXISTS { MATCH (p:Content {origin: 'user'})-[:MENTIONS]->(d) } AS by_user,
       EXISTS { MATCH (u:Content {untrusted: true})-[:MENTIONS]->(d) } AS by_untrusted
ORDER BY denied DESC, asked DESC, calls DESC, id
LIMIT 8`.trim();

// The console statement behind each row of that table.
export const DESTINATION_DETAIL = `
MATCH (d:Entity {id: $dest})
OPTIONAL MATCH (src:Content)-[:MENTIONS]->(d)
OPTIONAL MATCH (call:ToolCall)-[:SENDS_TO]->(d)
RETURN d.id AS destination,
       collect(DISTINCT {content: src.id, origin: src.origin, untrusted: src.untrusted}) AS named_by,
       collect(DISTINCT {call: call.id, tool: call.tool, decision: call.decision}) AS sent_by`.trim();

export const SESSION = `
MATCH (s:Session {id: $sid})
OPTIONAL MATCH (s)-[:BY]->(a:Agent)
RETURN s.id AS id, s.started_at AS started_at, coalesce(a.name, s.agent_kind) AS agent,
       s.mode AS mode, s.cwd AS cwd`.trim();

// What the session was given without a tool call: prompts, files attached to a prompt with
// @path, and inherited instruction files.
export const SESSION_RECEIVED = `
MATCH (:Session {id: $sid})-[:RECEIVED]->(p:Content)
RETURN p.id AS id, p.seq AS seq, p.ts AS ts, p.origin AS origin, p.excerpt AS excerpt, p.bytes AS bytes,
       coalesce(p.untrusted, false) AS untrusted, coalesce(p.sensitive, false) AS sensitive,
       [(p)-[:FROM]->(src:Entity) | coalesce(src.name, src.value)][0] AS source,
       [(p)-[:MENTIONS]->(e:Entity) | {kind: e.kind, name: e.name, value: e.value}] AS mentions
ORDER BY seq`.trim();

// Every tool call with what it touched, what it brought into the context and what was decided.
export const SESSION_CALLS = `
MATCH (c:ToolCall {session_id: $sid})
OPTIONAL MATCH (c)-[:RETURNED]->(o:Content)
OPTIONAL MATCH (o)-[:FROM]->(src:Entity)
RETURN c.id AS id, c.seq AS seq, coalesce(c.num, c.seq) AS num, c.ts AS ts, c.tool AS tool,
       c.summary AS summary, coalesce(c.decision, 'allow') AS decision, c.status AS status,
       coalesce(c.is_sink, false) AS is_sink,
       [(c)-[r:READS|WRITES|FETCHES|SENDS_TO|UPLOADS|EXECUTES]->(e:Entity) |
          {rel: type(r), kind: e.kind, name: e.name, value: e.value,
           sensitive: coalesce(e.sensitive, false), protected: coalesce(e.protected, false),
           trusted: coalesce(e.trusted, false), local: coalesce(e.local, false)}] AS touches,
       COUNT { (c)-[:CARRIES]->(:Chunk) } AS carries,
       o.id AS out_id, coalesce(o.untrusted, false) AS untrusted, coalesce(o.sensitive, false) AS sensitive,
       coalesce(o.injection_score, 0.0) AS injection, coalesce(o.injection_markers, []) AS markers,
       coalesce(o.reasons, []) AS reasons, o.excerpt AS excerpt, o.bytes AS bytes,
       src.kind AS src_kind, src.value AS src_value, src.name AS src_name,
       COLLECT { MATCH (f:Finding)-[:FLAGS]->(c)
                 RETURN {id: f.id, rule: f.rule, action: f.action, intended: coalesce(f.intended, f.action), title: f.title}
                 ORDER BY f.rule } +
       COLLECT { MATCH (f:Finding)-[:FLAGS]->(o)
                 RETURN {id: f.id, rule: f.rule, action: f.action, intended: coalesce(f.intended, f.action), title: f.title}
                 ORDER BY f.rule } AS findings
ORDER BY seq`.trim();

export const FINDING = `
MATCH (f:Finding {id: $id})
OPTIONAL MATCH (f)-[:FLAGS]->(t)
RETURN f.id AS id, f.rule AS rule, f.name AS name, f.severity AS severity, f.action AS action,
       coalesce(f.intended, f.action) AS intended, f.title AS title, f.explanation AS explanation,
       f.path_json AS path_json, f.query AS query, f.params_json AS params_json,
       f.session_id AS session_id, f.target_id AS target_id, f.target_label AS target_label, f.ts AS ts,
       t.num AS call_num, t.tool AS tool, t.decision AS decision`.trim();

// The nodes of the stored attack path, in order, as they are in the graph now.
export const FINDING_EVIDENCE = `
MATCH (f:Finding {id: $id})-[e:EVIDENCE]->(n)
RETURN e.ord AS ord, labels(n) AS labels, properties(n) AS props
ORDER BY ord`.trim();

// ---- capability map ---------------------------------------------------------------------------

export const MAP_AGENTS = `
MATCH (a:Agent)
RETURN a.id AS id, coalesce(a.name, a.id) AS name, coalesce(a.config_paths, []) AS config_paths,
       coalesce(a.permission_mode, '') AS permission_mode, coalesce(a.problems, []) AS problems,
       COUNT { (a)-[:CONNECTS]->(:Server) } AS servers, COUNT { (:Session)-[:BY]->(a) } AS sessions
ORDER BY id`.trim();

export const MAP_SERVERS = `
MATCH (a:Agent)-[:CONNECTS]->(s:Server)
RETURN a.id AS agent, s.id AS id, s.name AS name, s.transport AS transport, s.command AS command,
       s.url_host AS url_host, s.source_file AS source_file, s.scope AS scope,
       NOT coalesce(s.enabled = false, false) AS enabled, coalesce(s.status, '') AS status,
       coalesce(s.risk_flags, []) AS risk_flags,
       [(s)-[:HOLDS]->(c:Credential) | {name: c.name, kind: c.kind, literal: coalesce(c.literal, false)}] AS credentials
ORDER BY agent, CASE s.transport WHEN 'builtin' THEN 0 ELSE 1 END, name`.trim();

// A tool belongs to the server that PROVIDES it. Tools that were only observed in a session
// have no such edge; their id (<agent>::<name>) and server property place them.
export const MAP_TOOLS = `
MATCH (t:Tool)
OPTIONAL MATCH (s:Server)-[:PROVIDES]->(t)
RETURN split(t.id, '::')[0] AS agent, s.id AS server_id, coalesce(s.name, t.server, 'builtin') AS server,
       t.id AS id, t.name AS name, coalesce(t.permission, 'default') AS permission,
       t.gate AS gate, t.gate_reason AS gate_reason,
       coalesce(t.untrusted_input, false) AS untrusted_input, coalesce(t.private_data, false) AS private_data,
       coalesce(t.external_sink, false) AS external_sink, coalesce(t.local_write, false) AS local_write,
       coalesce(t.code_exec, false) AS code_exec, t.label_source AS label_source,
       t.label_confidence AS label_confidence, t.notes AS notes,
       COUNT { (:ToolCall)-[:INVOKES]->(t) } AS calls
ORDER BY agent, server, name`.trim();

// What happens when a tool is called: it runs unasked ('open'), waits for a person ('ask') or is
// refused ('deny'). A scan stores this as Tool.gate; a graph that only carries the permission
// rule is read the obvious way. The same expression as in tainttrail/paths.py.
const gate = (v) => `coalesce(${v}.gate, CASE coalesce(${v}.permission, 'default') WHEN 'deny' THEN 'deny' WHEN 'allow' THEN 'open' ELSE 'ask' END)`;
// A server counts unless its configuration switched it off. (paths.py writes coalesce(s.enabled, true).)
const enabled = (v) => `NOT coalesce(${v}.enabled = false, false)`;

// The three legs of a toxic path, per agent: tools that can bring in untrusted content, reach
// private data, or send data out. A refused tool and a tool of a disabled server do not count.
export const MAP_LEGS = `
MATCH (t:Tool)-[:HAS_CAPABILITY]->(k:Capability)
WHERE k.name IN ['untrusted_input', 'private_data', 'external_sink']
OPTIONAL MATCH (s:Server)-[:PROVIDES]->(t)
WITH split(t.id, '::')[0] AS agent, k.name AS capability, t, ${enabled('s')} AS enabled,
     ${gate('t')} AS gate
WHERE enabled AND gate <> 'deny'
RETURN agent, capability, count(DISTINCT t) AS tools,
       count(DISTINCT CASE WHEN gate = 'open' THEN t END) AS open
ORDER BY agent, capability`.trim();

// Toxic paths in factored form, as `tainttrail paths` finds them: one row per (source server,
// data server, sink server). Every source x data x sink combination of a row is a path; it is
// open when its sink runs without asking anyone.
const PATH_ROWS = `
MATCH (a:Agent)-[:CONNECTS]->(ss:Server)-[:PROVIDES]->(src:Tool)
      -[:HAS_CAPABILITY]->(:Capability {name: 'untrusted_input'})
WHERE ${enabled('ss')} AND ${gate('src')} <> 'deny'
WITH a, ss, count(src) AS sources
MATCH (a)-[:CONNECTS]->(ds:Server)-[:PROVIDES]->(dat:Tool)
      -[:HAS_CAPABILITY]->(:Capability {name: 'private_data'})
WHERE ${enabled('ds')} AND ${gate('dat')} <> 'deny'
WITH a, ss, sources, ds, count(dat) AS data
MATCH (a)-[:CONNECTS]->(ks:Server)-[:PROVIDES]->(snk:Tool)
      -[:HAS_CAPABILITY]->(:Capability {name: 'external_sink'})
WHERE ${enabled('ks')} AND ${gate('snk')} <> 'deny'
WITH a, ss, ds, ks, sources, data, count(snk) AS sinks,
     sum(CASE WHEN ${gate('snk')} = 'open' THEN 1 ELSE 0 END) AS open_sinks
WITH a, ss, ds, ks, sources * data * sinks AS paths, sources * data * open_sinks AS open_paths`;

export const MAP_PATH_GROUPS = `${PATH_ROWS}
RETURN a.id AS agent, ss.name AS source, ds.name AS data, ks.name AS sink, paths, open_paths
ORDER BY agent, open_paths DESC, paths DESC, source, data, sink
LIMIT 60`.trim();

export const MAP_PATH_TOTALS = `${PATH_ROWS}
RETURN a.id AS agent, sum(paths) AS paths, sum(open_paths) AS open_paths, count(*) AS groups
ORDER BY agent`.trim();

// ---- console examples -----------------------------------------------------------------------

export const EXAMPLES = [
  {
    title: 'Sessions and verdicts',
    about: 'One row per recorded session: how many calls ran, were asked about or were denied.',
    statement: `MATCH (s:Session)
OPTIONAL MATCH (s)-[:RAN]->(c:ToolCall)
RETURN s.id AS session, count(c) AS calls,
       sum(CASE WHEN c.decision = 'ask' THEN 1 ELSE 0 END) AS asked,
       sum(CASE WHEN c.decision = 'deny' THEN 1 ELSE 0 END) AS denied
ORDER BY denied DESC, asked DESC, session`,
  },
  {
    title: 'Untrusted content, most suspicious first',
    about: 'Everything a third party could have written that entered an agent context.',
    statement: `MATCH (c:Content {untrusted: true})
OPTIONAL MATCH (c)-[:FROM]->(src:Entity)
RETURN c.session_id AS session, c.seq AS seq, coalesce(src.value, c.origin) AS source,
       c.injection_score AS injection_score, c.injection_markers AS markers
ORDER BY injection_score DESC, session, seq`,
  },
  {
    title: 'Destinations only untrusted content named',
    about: 'Places no prompt and no trusted content mentions, and the calls that tried to send there.',
    statement: `MATCH (u:Content {untrusted: true})-[:MENTIONS]->(d:Entity)
WHERE d.kind IN ['host', 'url', 'repo', 'email']
  AND NOT coalesce(d.trusted, false) AND NOT coalesce(d.local, false)
  AND NOT EXISTS { MATCH (t:Content)-[:MENTIONS]->(d) WHERE coalesce(t.untrusted, false) = false }
OPTIONAL MATCH (c:ToolCall)-[:SENDS_TO]->(d)
RETURN d.id AS destination, count(DISTINCT u) AS named_by_untrusted,
       collect(DISTINCT c.summary) AS calls_sending_there
ORDER BY size(calls_sending_there) DESC, destination`,
  },
  {
    title: 'Held calls and the chain back to untrusted content',
    about: 'For every call that was asked about or denied: the shortest evidence path from untrusted content of the same session.',
    statement: `MATCH (c:ToolCall) WHERE c.decision IN ['ask', 'deny']
MATCH (u:Content {untrusted: true}) WHERE u.session_id = c.session_id AND u.seq < c.seq
MATCH p = SHORTEST 1 (u)-[:MENTIONS|SENDS_TO|CARRIES|HAS_CHUNK|READS|WRITES|UPLOADS|FETCHES|FROM|TAINTED_BY]-{1,6}(c)
RETURN c.num AS call, c.decision AS decision, length(p) AS hops, p
ORDER BY hops, call
LIMIT 10`,
  },
  {
    title: 'Secrets that calls carried (fingerprints only)',
    about: 'A CARRIES edge means the call arguments contain a keyed fingerprint of sensitive text. The text itself is never stored.',
    statement: `MATCH (c:ToolCall)-[:CARRIES]->(k:Chunk)<-[:HAS_CHUNK]-(s:Content {sensitive: true})
OPTIONAL MATCH (s)-[:FROM]->(f:Entity)
RETURN c.session_id AS session, c.num AS call, c.summary AS command, k.kind AS fingerprint_of,
       k.hint AS hint, f.name AS read_from, c.decision AS decision
ORDER BY session, call`,
  },
  {
    title: 'Where data was sent, and whether the host is trusted',
    about: 'Every outbound call with its destination.',
    statement: `MATCH (c:ToolCall)-[:SENDS_TO]->(d:Entity)
RETURN c.session_id AS session, c.num AS call, c.tool AS tool, d.id AS destination,
       coalesce(d.trusted, false) AS trusted, coalesce(d.local, false) AS local, c.decision AS decision
ORDER BY session, call`,
  },
  {
    title: 'Tools by capability',
    about: 'What each tool can do, as the scanner or the guard labelled it.',
    statement: `MATCH (t:Tool)-[:HAS_CAPABILITY]->(k:Capability)
RETURN k.name AS capability, count(t) AS tools, collect(t.name)[0..8] AS examples
ORDER BY tools DESC, capability`,
  },
  {
    title: 'What is in this graph',
    about: 'Node labels and how many nodes carry each.',
    statement: `MATCH (n)
UNWIND labels(n) AS label
RETURN label, count(*) AS nodes
ORDER BY nodes DESC, label`,
  },
];
