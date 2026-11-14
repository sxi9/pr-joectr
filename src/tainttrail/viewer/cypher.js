// cypher.js: looking at Cypher text. Colouring it for display, and refusing statements that
// would change the graph. Nothing here runs a statement.

import { h } from './dom.js';

const KEYWORDS = new Set((
  'MATCH OPTIONAL WHERE RETURN WITH ORDER BY LIMIT SKIP AS AND OR NOT XOR IN IS NULL TRUE FALSE DISTINCT ' +
  'CASE WHEN THEN ELSE END UNWIND CALL YIELD UNION ALL SHORTEST ANY EXISTS COUNT COLLECT DESC ASC ' +
  'STARTS ENDS CONTAINS CREATE MERGE SET DELETE DETACH REMOVE ON SHOW EXPLAIN PROFILE USE FILTER LET NEXT ' +
  'FINISH FOREACH INSERT LOAD DROP'
).split(' '));

// The pieces of a statement, read the way the engine reads them. A backslash in a string
// escapes whatever follows it, a line break included: without that, a string ending in a
// backslash and a line break would shift what this pattern takes for text and what for code.
const TOKEN = new RegExp(
  [
    '(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)', // 1 comment
    '(\'(?:[^\'\\\\]|\\\\[\\s\\S])*\'|"(?:[^"\\\\]|\\\\[\\s\\S])*")', // 2 string
    '(`(?:[^`]|``)*`)', // 3 quoted identifier
    '(\\$[A-Za-z_][A-Za-z0-9_]*)', // 4 parameter
    '(:[A-Za-z_][A-Za-z0-9_]*)', // 5 label or relationship type
    '([A-Za-z_][A-Za-z0-9_]*)', // 6 word
  ].join('|'),
  'g',
);

/** A <pre><code> block with the statement coloured. The text is added as text nodes only. */
export function cypherBlock(statement, { cls = '' } = {}) {
  const code = h('code', null);
  const source = String(statement ?? '');
  let last = 0;
  for (const m of source.matchAll(TOKEN)) {
    if (m.index > last) code.append(source.slice(last, m.index));
    const [whole, comment, string, quoted, param, label, word] = m;
    let kind = null;
    if (comment) kind = 'comment';
    else if (string) kind = 'string';
    else if (param) kind = 'param';
    else if (label) kind = 'label';
    else if (word && KEYWORDS.has(word.toUpperCase()) && word === word.toUpperCase()) kind = 'keyword';
    code.append(kind && !quoted ? h('span', { class: `tok-${kind}` }, whole) : whole);
    last = m.index + whole.length;
  }
  if (last < source.length) code.append(source.slice(last));
  return h('pre', { class: `code${cls ? ` ${cls}` : ''}`, tabindex: '0' }, code);
}

/**
 * The statement as its bare words: a comment becomes a space, a string an empty string and a
 * quoted identifier a plain name, each set apart by spaces. Their content is gone, but each is
 * still there as a token: in "AS `x` CREATE" the name after AS is `x`, not CREATE.
 */
function bare(statement) {
  return String(statement).replace(TOKEN, (whole, comment, string, quoted) => (comment ? ' ' : string ? " '' " : quoted ? ' _ ' : whole));
}

/** The statement without comments and strings, quoted identifiers written plainly: db.`createLabel` reads db.createLabel. */
function named(statement) {
  return String(statement)
    .replace(TOKEN, (whole, comment, string, quoted) => (comment || string ? ' ' : quoted ? quoted.slice(1, -1).replace(/``/g, '`') : whole))
    .replace(/\s*\.\s*/g, '.');
}

// A word that starts a clause which changes the graph, or reads from outside it (LOAD CSV).
// Not after a dot, a dollar sign or a colon: n.set, $set and :SET are a property, a parameter
// and a label. FINISH ends a statement without returning anything; the engine reports no
// counters for such a statement, so what it changed could not be noticed afterwards.
const CLAUSE = /(^|[^.$:\w])(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|FOREACH|INSERT|LOAD|FINISH)(?!\w)/gi;
// RETURN count(*) AS load: the word is a name the statement gives. Only when AS follows the end
// of an expression that cannot be mistaken, a bracket, a quote or a digit: the engine also takes
// AS as a name (UNWIND [1] AS AS CREATE ...), and after that name comes a clause.
const AS_BEFORE = /[)\]}'"0-9]\s*AS\s+$/i;
const NAME_AFTER = /^\s*[),.=:\]}]/; // {set: 1}, size(set), set.x: no clause continues like this

/** The first clause-starting write word in a text, in upper case, or null. */
function writeWord(text) {
  CLAUSE.lastIndex = 0;
  for (let m = CLAUSE.exec(text); m !== null; m = CLAUSE.exec(text)) {
    const word = m[2].toUpperCase();
    const start = m.index + m[1].length;
    const after = text.slice(start + word.length);
    // At the very end a word can only be a name (ORDER BY load). Except FINISH: the end is where it belongs.
    const isName = AS_BEFORE.test(text.slice(0, start)) || NAME_AFTER.test(after) || (word !== 'FINISH' && /^[\s;]*$/.test(after));
    if (!isName) return word;
    CLAUSE.lastIndex = start + word.length; // the character before the next word may be the one just read
  }
  return null;
}

const WRITE_PROCEDURE = /(?:^|[^\w.])((?:db\.create|db\.checkpoint|db\.clearQueryCaches|db\.prepareForReplanning|tx\.setMetaData)[\w.]*)/i;

/**
 * Why the viewer will not run a statement, or null when it may run.
 *
 * The graph in the tab is a copy of an export and the engine has no read-only mode for an
 * in-memory store, so "read-only" is a rule the viewer keeps: it refuses write clauses up
 * front. The caller also checks the counters of every result, and loads the export again
 * after a statement this function could not vouch for (see hiddenWrite).
 */
export function refusal(statement) {
  const text = bare(statement);
  if (!text.trim()) return 'Nothing to run.';
  const word = writeWord(text);
  const asName = word ? ` If ${word} is a name in your statement, write it in backticks: \`${word.toLowerCase()}\`.` : '';
  if (word === 'FINISH') return `This viewer is read-only: FINISH returns nothing and hides what a statement changed, so it is not run here.${asName}`;
  if (word === 'LOAD') return `This viewer is read-only: LOAD CSV reads from outside the graph, and the viewer works offline.${asName}`;
  if (word) return `This viewer is read-only: ${word} would change the graph. Queries here only read.${asName}`;
  const plain = named(statement);
  const procedure = WRITE_PROCEDURE.exec(plain);
  if (procedure) return `This viewer is read-only: the procedure ${procedure[1]} changes the database. Queries here only read.`;
  if (/(?:^|[^\w.])randomUUID\s*\(/i.test(plain)) {
    return 'randomUUID() is not available in the WebAssembly build of Relate (it stops the engine).';
  }
  return null;
}

/**
 * True when a write word appears only inside a string, a comment or a quoted identifier.
 *
 * Almost always that is a search for the word ("... CONTAINS 'git merge'"). But it is also
 * the one place where this file and the engine could disagree about what is text and what
 * is code, so the caller loads the export again after such a statement instead of trusting
 * that nothing changed.
 */
export function hiddenWrite(statement) {
  return writeWord(bare(statement)) === null && writeWord(String(statement)) !== null;
}

/** True when a result's counters show that the statement changed the store. */
export function changedGraph(envelope) {
  return Object.values(envelope?.stats ?? {}).some((n) => typeof n === 'number' && n > 0);
}
