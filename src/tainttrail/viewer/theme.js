// theme.js: a classic script, loaded before the stylesheet paints, so a stored choice of theme
// applies without a flash. With no stored choice the page follows the system setting through
// the CSS media query, and app.js keeps the toggle in step with it.
(function () {
  'use strict';
  try {
    var stored = window.localStorage.getItem('tainttrail.theme');
    if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
  } catch (error) {
    // Storage can be unavailable (private mode, blocked site data). The system setting applies.
  }
})();
