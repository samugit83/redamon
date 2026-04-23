// Shared HTML wrapper for every page on the Argentum Digital site.
// Pages call layout(title, body, options?) to get a complete document.

const BASE = process.env.SITE_BASE || '/argentum';

function nav() {
  return `
    <header class="site-header">
      <div class="container nav-row">
        <a class="brand" href="${BASE}/">
          <span class="brand-mark">A</span>
          <span class="brand-name">Argentum<small>Digital</small></span>
        </a>
        <nav class="primary-nav">
          <a href="${BASE}/about">About</a>
          <a href="${BASE}/services">Services</a>
          <a href="${BASE}/products">Products</a>
          <a href="${BASE}/blog">Blog</a>
          <a href="${BASE}/case-studies">Case studies</a>
          <a href="${BASE}/contact">Contact</a>
        </nav>
        <div class="nav-actions">
          <a class="btn-ghost" href="${BASE}/account/profile">Sign in</a>
          <a class="btn-primary" href="${BASE}/contact">Get a quote</a>
        </div>
      </div>
    </header>`;
}

function footer() {
  return `
    <footer class="site-footer">
      <div class="container footer-grid">
        <div>
          <div class="footer-brand">Argentum Digital</div>
          <p>Consulting and growth engineering for ambitious B2B companies.</p>
          <p class="footer-meta">28 Hatton Garden, London EC1N 8JE</p>
        </div>
        <div>
          <h4>Company</h4>
          <ul>
            <li><a href="${BASE}/about">About us</a></li>
            <li><a href="${BASE}/case-studies">Case studies</a></li>
            <li><a href="${BASE}/careers">Careers</a></li>
            <li><a href="${BASE}/blog">Insights</a></li>
          </ul>
        </div>
        <div>
          <h4>Services</h4>
          <ul>
            <li><a href="${BASE}/services/calculator">ROI calculator</a></li>
            <li><a href="${BASE}/services/preview">Campaign preview</a></li>
            <li><a href="${BASE}/services/share">Share studio</a></li>
            <li><a href="${BASE}/services/theme">Theme builder</a></li>
            <li><a href="${BASE}/services/embed">Embed widgets</a></li>
          </ul>
        </div>
        <div>
          <h4>Help</h4>
          <ul>
            <li><a href="${BASE}/support">Support tickets</a></li>
            <li><a href="${BASE}/contact">Contact us</a></li>
            <li><a href="${BASE}/account/preferences">Preferences</a></li>
            <li><a href="${BASE}/welcome">What's new</a></li>
          </ul>
        </div>
      </div>
      <div class="container footer-bottom">
        <span>&copy; ${new Date().getFullYear()} Argentum Digital Ltd.</span>
        <span>Registered in England &amp; Wales No. 09114782</span>
      </div>
    </footer>`;
}

function layout(title, body, opts = {}) {
  const cspHeader = opts.cspNote || '';
  const extraHead = opts.head || '';
  const noNav = opts.noNav || false;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — Argentum Digital</title>
  <meta name="description" content="Argentum Digital — consulting and growth engineering for ambitious B2B teams.">
  <link rel="stylesheet" href="${BASE}/static/style.css">
  ${cspHeader}
  ${extraHead}
</head>
<body>
  ${noNav ? '' : nav()}
  <main>${body}</main>
  ${noNav ? '' : footer()}
  <script src="${BASE}/static/main.js"></script>
</body>
</html>`;
}

// Minimal HTML escaper for places where we DO want to escape (used sparingly,
// since the whole point of this site is to leave plenty of unescaped paths).
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { layout, nav, footer, escapeHtml, BASE };
