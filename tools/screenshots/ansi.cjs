/*
 * ANSI SGR escape sequences to HTML. Shared by the screenshot tool and the demo video tool.
 */
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const BASIC = ['#1f2430', '#e5484d', '#3fb950', '#d9a514', '#4f8cf7', '#b47cf5', '#2bb5c4', '#c9d1d9'];
const BRIGHT = ['#6b7280', '#ff7b72', '#56d364', '#f2cc60', '#79b8ff', '#d2a8ff', '#56d4dd', '#ffffff'];

/** Minimal ANSI SGR to HTML: colours, bold, dim, underline, reverse off. */
function ansiToHtml(text) {
  let html = '';
  let open = false;
  let state = { fg: null, bg: null, bold: false, dim: false, underline: false };
  const style = () => {
    const css = [];
    if (state.fg) css.push(`color:${state.fg}`);
    if (state.bg) css.push(`background:${state.bg}`);
    if (state.bold) css.push('font-weight:700');
    if (state.dim) css.push('opacity:.62');
    if (state.underline) css.push('text-decoration:underline');
    return css.join(';');
  };
  const reopen = () => {
    if (open) html += '</span>';
    const css = style();
    open = css.length > 0;
    if (open) html += `<span style="${css}">`;
  };
  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    html += esc(text.slice(last, m.index));
    last = re.lastIndex;
    const codes = m[1] === '' ? [0] : m[1].split(';').map(Number);
    for (let i = 0; i < codes.length; i++) {
      const c = codes[i];
      if (c === 0) state = { fg: null, bg: null, bold: false, dim: false, underline: false };
      else if (c === 1) state.bold = true;
      else if (c === 2) state.dim = true;
      else if (c === 4) state.underline = true;
      else if (c === 22) { state.bold = false; state.dim = false; }
      else if (c === 24) state.underline = false;
      else if (c >= 30 && c <= 37) state.fg = BASIC[c - 30];
      else if (c === 39) state.fg = null;
      else if (c >= 40 && c <= 47) state.bg = BASIC[c - 40];
      else if (c === 49) state.bg = null;
      else if (c >= 90 && c <= 97) state.fg = BRIGHT[c - 90];
      else if ((c === 38 || c === 48) && codes[i + 1] === 2) {
        const rgb = `rgb(${codes[i + 2]},${codes[i + 3]},${codes[i + 4]})`;
        if (c === 38) state.fg = rgb; else state.bg = rgb;
        i += 4;
      } else if ((c === 38 || c === 48) && codes[i + 1] === 5) {
        const n = codes[i + 2];
        const col = n < 8 ? BASIC[n] : n < 16 ? BRIGHT[n - 8] : null;
        if (c === 38) state.fg = col; else state.bg = col;
        i += 2;
      }
    }
    reopen();
  }
  html += esc(text.slice(last));
  if (open) html += '</span>';
  // Drop any other escape sequences (cursor movement and the like).
  return html.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '');
}

module.exports = { esc, ansiToHtml };
