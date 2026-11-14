// dom.js: the only way this app makes DOM nodes.
//
// Everything the viewer shows comes out of a graph that recorded hostile text: page titles,
// shell commands, excerpts of fetched content. So no string from the graph is ever parsed as
// markup. h() creates elements and TEXT nodes; there is no innerHTML anywhere in the app.

const SVG_NS = 'http://www.w3.org/2000/svg';

function append(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else if (child instanceof Node) parent.appendChild(child);
    else parent.appendChild(document.createTextNode(String(child)));
  }
}

function setAttrs(el, attrs) {
  for (const [name, value] of Object.entries(attrs ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name === 'on') {
      for (const [type, handler] of Object.entries(value)) el.addEventListener(type, handler);
    } else if (name === 'class') {
      el.setAttribute('class', Array.isArray(value) ? value.filter(Boolean).join(' ') : value);
    } else if (name === 'dataset') {
      for (const [key, v] of Object.entries(value)) if (v !== null && v !== undefined) el.dataset[key] = String(v);
    } else if (name === 'value' && 'value' in el) {
      el.value = value;
    } else {
      el.setAttribute(name, value === true ? '' : String(value));
    }
  }
}

/** h('a', { class: 'x', href: '#/' }, 'text', node, [more]) -> HTMLElement. Strings become text. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// ---- icons ---------------------------------------------------------------------------------
// 16 x 16, one path each. `stroke: true` icons are drawn as outlines.

const ICONS = {
  untrusted: { d: 'M8 1.4 15.2 14.2H.8L8 1.4zM7.2 6.1v4h1.6v-4H7.2zm0 5.1v1.6h1.6v-1.6H7.2z', evenodd: true },
  sensitive: { d: 'M4.4 7V5.1a3.6 3.6 0 0 1 7.2 0V7h.4a1 1 0 0 1 1 1v5.4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1h.4zM6 7h4V5.1a2 2 0 0 0-4 0V7z', evenodd: true },
  destination: { d: 'M9.5 2.5h4v4M13.5 2.5 7.6 8.4M11.5 9.6v2.9a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h2.9', stroke: true },
  call: { d: 'M2.6 4.2 6.6 8l-4 3.8M8.4 12.4h5', stroke: true },
  user: { d: 'M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-5.6 6.4a5.6 5.6 0 0 1 11.2 0H2.4z' },
  fingerprint: { d: 'M6.2 2 5 14M11 2 9.8 14M2.6 5.8h11.2M2.2 10.2h11.2', stroke: true },
  file: { d: 'M4 1.6h5l3.4 3.4v8.9a.5.5 0 0 1-.5.5H4a.5.5 0 0 1-.5-.5V2.1a.5.5 0 0 1 .5-.5zM9 1.6V5h3.4', stroke: true },
  content: { d: 'M3 4h10M3 8h10M3 12h6', stroke: true },
  entity: { d: 'M8 4.4a3.6 3.6 0 1 0 0 7.2 3.6 3.6 0 0 0 0-7.2z' },
  deny: { d: 'M4 4l8 8M12 4l-8 8', stroke: true },
  ask: { d: 'M5.7 6.1a2.3 2.3 0 1 1 3.5 2c-.8.5-1.2 1-1.2 1.9M8 12.5v.3', stroke: true },
  allow: { d: 'M3.4 8.6l3 3 6.2-7.2', stroke: true },
  note: { d: 'M8 1.8a6.2 6.2 0 1 0 0 12.4A6.2 6.2 0 0 0 8 1.8zM8 7.3v3.9M8 4.8v.3', stroke: true },
  server: { d: 'M2.5 3.3h11v3.6h-11zM2.5 9.1h11v3.6h-11zM5 5.1h.3M5 10.9h.3', stroke: true },
  key: { d: 'M13.5 5.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0zM8.4 7.6 2.5 13.5M4.6 11.4l1.6 1.6M6.6 9.4 8 10.8', stroke: true },
  play: { d: 'M4.6 2.8v10.4l8.6-5.2-8.6-5.2z' },
  chevron: { d: 'M6 3.5 10.5 8 6 12.5', stroke: true },
  database: { d: 'M2.8 4.2c0-1.2 2.3-2.2 5.2-2.2s5.2 1 5.2 2.2-2.3 2.2-5.2 2.2-5.2-1-5.2-2.2zM2.8 4.2v7.6c0 1.2 2.3 2.2 5.2 2.2s5.2-1 5.2-2.2V4.2M2.8 8c0 1.2 2.3 2.2 5.2 2.2s5.2-1 5.2-2.2', stroke: true },
  write: { d: 'M11 2.6 13.4 5 6 12.4l-3.1.7.7-3.1L11 2.6z', stroke: true },
  exec: { d: 'M9.2 1.4 3.4 9.1H8l-1.2 5.5 5.8-7.7H8l1.2-5.5z' },
  agent: { d: 'M5 5.5h6a1.5 1.5 0 0 1 1.5 1.5v4A1.5 1.5 0 0 1 11 12.5H5A1.5 1.5 0 0 1 3.5 11V7A1.5 1.5 0 0 1 5 5.5zM8 5.5V3M6.3 8.6v.6M9.7 8.6v.6', stroke: true },
};

/** An inline SVG icon. Decorative unless `label` is given. */
export function icon(name, { label = null, cls = '' } = {}) {
  const def = ICONS[name] ?? ICONS.entity;
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('class', `icon${def.stroke ? ' icon-stroke' : ''}${cls ? ` ${cls}` : ''}`);
  svg.setAttribute('focusable', 'false');
  if (label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', def.d);
  if (def.evenodd) path.setAttribute('fill-rule', 'evenodd');
  svg.appendChild(path);
  return svg;
}

// ---- words and numbers ----------------------------------------------------------------------

const pad = (n) => String(n).padStart(2, '0');

/** Epoch milliseconds as "2026-11-14 09:12 UTC": the same clock the command line prints. */
export function fmtTime(ms, { seconds = false } = {}) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return '';
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '';
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${seconds ? `:${pad(d.getUTCSeconds())}` : ''}`;
  return `${date} ${time} UTC`;
}

export function fmtClock(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return '';
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '' : `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

export function fmtMs(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '';
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export const fmtInt = (n) => (typeof n === 'number' && Number.isFinite(n) ? n.toLocaleString('en-US') : '0');

export function fmtBytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const plural = (n, one, many = `${one}s`) => `${fmtInt(n)} ${n === 1 ? one : many}`;

/** A long opaque id shortened for a table cell; the full id belongs in a title attribute. */
export function shortId(id, keep = 8) {
  const text = String(id ?? '');
  return text.length > keep + 4 ? `${text.slice(0, keep)}\u2026` : text;
}

/** A value from the graph that should be a list: anything else (a file can say anything) is no items. */
export const list = (value) => (Array.isArray(value) ? value : []);

const BREAK_AFTER = new Set('/._:@=&?-');

/**
 * Text with a line-break opportunity after each separator, so a long path, URL or tool name
 * wraps at a slash or an underscore instead of in the middle of a word.
 */
export function breakable(value) {
  const text = String(value ?? '').slice(0, 2000);
  const out = [];
  let start = 0;
  for (let i = 0; i < text.length - 1; i += 1) {
    if (!BREAK_AFTER.has(text[i])) continue;
    out.push(text.slice(start, i + 1), document.createElement('wbr'));
    start = i + 1;
  }
  out.push(text.slice(start));
  return out;
}
