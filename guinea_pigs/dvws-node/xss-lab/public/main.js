// Argentum Digital — small client-side helpers used across the site.
// Per-page interactive features ship inline in their own templates.

(function () {
  // Highlight active nav link
  var path = window.location.pathname;
  document.querySelectorAll('.primary-nav a').forEach(function (a) {
    if (a.getAttribute('href') && path.indexOf(a.getAttribute('href')) === 0 && a.getAttribute('href') !== '/argentum/') {
      a.style.borderColor = 'var(--ink)';
    }
  });

  // Persist a lightweight visitor preference (used by /preferences and /welcome)
  if (!localStorage.getItem('arg_visit_count')) {
    localStorage.setItem('arg_visit_count', '1');
  } else {
    localStorage.setItem('arg_visit_count', String(parseInt(localStorage.getItem('arg_visit_count'), 10) + 1));
  }
})();
