const express = require('express');
const { layout, BASE } = require('../lib/layout');

const router = express.Router();

// Site-wide search index — links to multiple "search backends"
// (legacy, v2, secure, enterprise, cloud) — each has progressively stronger
// input filtering. Disguised as different generations of search infra.
router.get('/', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Site search</h1>
        <p class="lead">Argentum currently runs five search backends in parallel as we migrate from the original 2018 implementation. Pick the one that suits your environment.</p>
        <div class="grid grid-2" style="margin-top:32px;">
          <div class="card">
            <h3>Legacy search</h3>
            <p>The original full-text index. Fast, no auth, used by our internal docs.</p>
            <a class="read-more" href="${BASE}/search/legacy?q=growth">Open legacy →</a>
          </div>
          <div class="card">
            <h3>Search v2</h3>
            <p>2020 rewrite with sanitised rendering for the public marketing site.</p>
            <a class="read-more" href="${BASE}/search/v2?q=growth">Open v2 →</a>
          </div>
          <div class="card">
            <h3>Secure search</h3>
            <p>Hardened variant used inside customer-facing dashboards. Strips event handlers.</p>
            <a class="read-more" href="${BASE}/search/secure?q=growth">Open secure →</a>
          </div>
          <div class="card">
            <h3>Enterprise search</h3>
            <p>Keyword-blacklist based filter for accounts on the Enterprise plan.</p>
            <a class="read-more" href="${BASE}/search/enterprise?q=growth">Open enterprise →</a>
          </div>
          <div class="card">
            <h3>Cloud search</h3>
            <p>Multi-pattern policy filter routed through our cloud edge.</p>
            <a class="read-more" href="${BASE}/search/cloud?q=growth">Open cloud →</a>
          </div>
        </div>
      </div>
    </section>`;
  res.send(layout('Site search', body));
});

// Helper to render a results page given a (potentially filtered) query
function resultsPage(title, label, q, filtered) {
  return `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">${title}</h1>
        <p class="muted">${label}</p>
        <form method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" value="${filtered}" placeholder="Search…">
        </form>
        <h3>Results for: ${filtered}</h3>
        <p class="muted">No matching documents indexed yet.</p>
      </div>
    </section>`;
}

// Tier 1 — strips literal <script>...</script> blocks (case-sensitive, no nested handling)
router.get('/legacy', (req, res) => {
  const q = req.query.q || '';
  const filtered = q.replace(/<script>[\s\S]*?<\/script>/g, '');
  res.send(layout('Legacy search', resultsPage('Legacy search', 'Original 2018 backend.', q, filtered)));
});

// Tier 2 — escapes < and > only when they form complete tags (regex)
// Bypassable via attribute injection if input lands in attribute context, OR by SVG with attribute-based events
router.get('/v2', (req, res) => {
  const q = req.query.q || '';
  // Strip tags that look like <something> but leave loose < > alone
  const filtered = q.replace(/<\/?[a-zA-Z][^>]*>/g, '');
  res.send(layout('Search v2', resultsPage('Search v2', '2020 rewrite — drops complete HTML tags.', q, filtered)));
});

// Tier 3 — strips inline event-handler attributes via regex /on\w+\s*=/i
// Bypassable via <a href=javascript:...> or via <svg><animate onbegin=...> etc with attribute name not matching ^on\w+ exactly
router.get('/secure', (req, res) => {
  const q = req.query.q || '';
  const filtered = q.replace(/\son[a-zA-Z]+\s*=/gi, ' data-evt=');
  res.send(layout('Secure search', resultsPage('Secure search', 'Hardened variant — neuters inline event handlers.', q, filtered)));
});

// Tier 4 — keyword blacklist (case-insensitive)
// Bypassable via encoding (HTML entity, hex/unicode JS escapes)
router.get('/enterprise', (req, res) => {
  const q = req.query.q || '';
  const blacklist = /(script|alert|javascript:|onerror|onload|onfocus|onmouseover|svg|iframe|prompt|confirm)/gi;
  const filtered = q.replace(blacklist, '[blocked]');
  res.send(layout('Enterprise search', resultsPage('Enterprise search', 'Enterprise-tier keyword filter.', q, filtered)));
});

// Tier 5 — multi-pattern WAF (mod_security style)
// Strips dangerous patterns but a determined polyglot can still slip through
router.get('/cloud', (req, res) => {
  const q = req.query.q || '';
  const patterns = [
    /<\/?\s*[a-zA-Z][^>]*>/g,                         // any tag
    /\son[a-zA-Z]+\s*=/gi,                             // event handlers
    /(script|alert|javascript|vbscript|data:text\/html|eval|expression\s*\()/gi,  // keywords
    /(&#x?[0-9a-f]+;?)/gi,                             // entity decoding (overzealous)
    /(\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/gi,               // hex/unicode escapes
  ];
  let filtered = q;
  patterns.forEach(p => { filtered = filtered.replace(p, ''); });
  res.send(layout('Cloud search', resultsPage('Cloud search', 'Multi-pattern policy filter at the edge.', q, filtered)));
});

module.exports = router;
