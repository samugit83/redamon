const express = require('express');
const { layout, BASE, escapeHtml } = require('../lib/layout');
const store = require('../lib/store');

const router = express.Router();

const PRODUCTS = [
  { slug: 'pulse', name: 'Pulse', tagline: 'Warehouse-native attribution for B2B SaaS.', price: '£890/mo', body: 'Pulse stitches sessions, identities, and revenue events into a single timeline so your dashboards stop disagreeing with your CFO.' },
  { slug: 'forge', name: 'Forge', tagline: 'Activation playbook engine.', price: '£1,400/mo', body: 'Forge encodes your activation rules in version-controlled YAML and ships the runtime to your warehouse.' },
  { slug: 'meridian', name: 'Meridian', tagline: 'Forecasting and revenue modelling for the office of finance.', price: '£2,100/mo', body: 'Meridian replaces brittle spreadsheets with a warehouse-native model your auditors can read.' },
];

// Catalog index
router.get('/', (req, res) => {
  const cards = PRODUCTS.map(p => `
    <div class="card">
      <h3><a href="${BASE}/products/${p.slug}" style="color:inherit;text-decoration:none;">${p.name}</a></h3>
      <p>${p.tagline}</p>
      <div class="meta"><span>${p.price}</span><span>14-day trial</span></div>
      <a class="read-more" href="${BASE}/products/${p.slug}">Learn more →</a>
    </div>`).join('');
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Products</h1>
        <p class="lead">A small, opinionated suite of tools we built and battle-tested with our consulting clients.</p>
        <form action="${BASE}/products/search" method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" placeholder="Search the catalog…">
        </form>
        <div class="grid grid-3">${cards}</div>
      </div>
    </section>`;
  res.send(layout('Products', body));
});

// VECTOR: Reflected XSS — HTML body context (with stricter filter for variety)
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  const matches = PRODUCTS.filter(p => q && (p.name.toLowerCase().includes(q.toLowerCase()) || p.body.toLowerCase().includes(q.toLowerCase())));
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Catalog search</h1>
        <p>You searched for: <em>${q}</em></p>
        <form action="${BASE}/products/search" method="GET" style="max-width:540px; margin:24px 0;">
          <input type="search" name="q" value="${q}" placeholder="Refine your search…">
        </form>
        <p class="muted">Found ${matches.length} matching product${matches.length === 1 ? '' : 's'}.</p>
        <div class="grid grid-3" style="margin-top:24px;">
          ${matches.map(p => `
            <div class="card">
              <h3><a href="${BASE}/products/${p.slug}" style="color:inherit;text-decoration:none;">${p.name}</a></h3>
              <p>${escapeHtml(p.tagline)}</p>
            </div>`).join('')}
        </div>
      </div>
    </section>`;
  res.send(layout('Catalog search', body));
});

// Product detail page
// VECTOR: Reflected XSS — attribute context unquoted (?theme=)
// VECTOR: Reflected XSS — JS string context (?utm_source= captured for client-side tracking)
// VECTOR: Reflected XSS — JS code context (?dim= used as numeric in inline JS)
// VECTOR: Reflected XSS — CSS context (?accent= used in <style>)
// VECTOR: Stored XSS — review body rendered into HTML
// VECTOR: Stored XSS — review author rendered into JS string in tracking
router.get('/:slug', (req, res) => {
  const product = PRODUCTS.find(p => p.slug === req.params.slug);
  if (!product) return res.status(404).send(layout('Not found', `<section><div class="container"><h1>Product not found</h1></div></section>`));

  const theme = req.query.theme || 'default';        // unquoted attribute
  const accent = req.query.accent || '#2451d6';      // CSS context
  const dim = req.query.dim || '1';                  // JS code context
  const utm = req.query.utm_source || 'direct';     // JS string context

  const reviews = store.reviews.list(product.slug);
  const reviewsHtml = reviews.length === 0
    ? `<p class="muted">No reviews yet — be the first.</p>`
    : reviews.map(r => `
        <div class="review">
          <div class="who">${r.author} <span class="muted" style="font-weight:400;">— ${'★'.repeat(r.rating)}${'☆'.repeat(5 - r.rating)}</span></div>
          <div>${r.body}</div>
          <div class="when">${r.when}</div>
        </div>`).join('');

  const reviewAuthorsForTracking = reviews.map(r => r.author).join(', ');

  const body = `
    <section>
      <div class="container">
        <a href="${BASE}/products" class="muted" style="font-size:13px;">← All products</a>
        <div class="banner" style="margin-top:16px; padding:32px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h1 style="margin:0; font-size:36px;">${product.name}</h1>
            <p style="margin:8px 0 0; font-size:18px; color:var(--muted);">${product.tagline}</p>
          </div>
          <div style="text-align:right;">
            <div style="font-size:28px; font-weight:600;">${product.price}</div>
            <a class="btn-primary" href="${BASE}/contact?product=${product.slug}" style="margin-top:8px;">Request a demo</a>
          </div>
        </div>

        <!-- Theme switcher -- uses unquoted attribute on the wrapper for legacy CSS hooks -->
        <div class=card-${theme} style="margin-top:24px; padding:24px; border:1px solid var(--line); border-radius:8px;">
          <h3>Overview</h3>
          <p>${product.body}</p>
          <p class="muted" style="font-size:13px;">Theme variant: <code>${theme}</code> · Accent <code>${accent}</code></p>
        </div>

        <style>
          .product-accent { color: ${accent}; border-color: ${accent}; }
          .product-card-${theme} { padding: 16px; }
        </style>

        <h3 style="margin-top:48px;">Customer reviews</h3>
        <div class="comments">${reviewsHtml}</div>

        <h4 style="margin-top:32px;">Leave a review</h4>
        <form action="${BASE}/products/${product.slug}/review" method="POST" class="stacked">
          <div class="form-row">
            <label>Name</label>
            <input type="text" name="author" required maxlength="80">
          </div>
          <div class="form-row">
            <label>Rating</label>
            <select name="rating">
              <option value="5">★★★★★</option>
              <option value="4">★★★★☆</option>
              <option value="3">★★★☆☆</option>
              <option value="2">★★☆☆☆</option>
              <option value="1">★☆☆☆☆</option>
            </select>
          </div>
          <div class="form-row">
            <label>Review</label>
            <textarea name="body" required maxlength="2000"></textarea>
          </div>
          <button type="submit">Publish review</button>
        </form>
      </div>
    </section>

    <script>
      // Lightweight pageview ping with UTM source attached for our analytics warehouse
      (function () {
        var src = "${utm}";
        var dim = ${dim};
        var reviewers = "${reviewAuthorsForTracking}";
        if (window.fetch) {
          fetch('${BASE}/api/track?ref=' + encodeURIComponent(src), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ p: '${product.slug}', d: dim, r: reviewers }) }).catch(function(){});
        }
      })();
    </script>`;
  res.send(layout(`${product.name} — Products`, body));
});

router.post('/:slug/review', (req, res) => {
  const product = PRODUCTS.find(p => p.slug === req.params.slug);
  if (!product) return res.status(404).send('Not found');
  const author = (req.body.author || 'Anonymous').slice(0, 200);
  const body = (req.body.body || '').slice(0, 5000);
  const rating = Math.max(1, Math.min(5, parseInt(req.body.rating, 10) || 5));
  store.reviews.add(product.slug, rating, author, body);
  res.redirect(`${BASE}/products/${product.slug}#reviews`);
});

module.exports = router;
