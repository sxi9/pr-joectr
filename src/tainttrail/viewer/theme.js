// theme.js: a classic script, loaded before the stylesheet paints, so a stored choice of theme
// applies without a flash. With no stored choice the page follows the system setting through
// the CSS media query, and app.js keeps the toggle in step with it.
//
// Being a classic script it also runs where the app's modules cannot: opened from a file://
// address, or from a server that sends .js files with the wrong type. Nothing would then ever
// replace the "starting" screen, so this script says what is wrong.
(function () {
  'use strict';
  try {
    var stored = window.localStorage.getItem('tainttrail.theme');
    if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
  } catch (error) {
    // Storage can be unavailable (private mode, blocked site data). The system setting applies.
  }

  // The load event waits for module scripts: by then app.js has run its first line, or it never will.
  window.addEventListener('load', function () {
    if (document.documentElement.dataset.app === 'started') return;
    var title = document.getElementById('boot-title');
    var detail = document.getElementById('boot-detail');
    if (!title || !detail) return;
    var spinner = document.querySelector('.boot-spinner');
    var engine = document.getElementById('status-engine');
    document.body.dataset.state = 'error';
    if (spinner) spinner.hidden = true;
    if (engine) engine.textContent = 'Relate WASM: not running';
    title.textContent = 'The viewer could not start';
    detail.textContent = window.location.protocol === 'file:'
      ? 'A browser does not load this page from a file:// address. Serve this directory over http, for example with ' +
        '"python -m http.server --bind 127.0.0.1" in it, or run "tainttrail ui".'
      : 'Its scripts did not load. The server must send .js files with a JavaScript MIME type, and every file of the viewer must be there.';
  });
})();
