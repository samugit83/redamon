const express = require('express');
const { layout, BASE } = require('../lib/layout');

const router = express.Router();

// Services index
router.get('/', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Services</h1>
        <p class="lead">Self-serve tooling we ship alongside our consulting engagements. All free for current clients.</p>
        <div class="grid grid-3" style="margin-top:32px;">
          <div class="card"><h3><a href="${BASE}/services/calculator" style="color:inherit;text-decoration:none;">ROI calculator</a></h3><p>Quick payback model for marketing spend with a custom expression input.</p></div>
          <div class="card"><h3><a href="${BASE}/services/preview" style="color:inherit;text-decoration:none;">Campaign preview</a></h3><p>Render an inline preview of any landing-page copy before publishing.</p></div>
          <div class="card"><h3><a href="${BASE}/services/share" style="color:inherit;text-decoration:none;">Share studio</a></h3><p>Build a shareable card and post it to your social channels in one click.</p></div>
          <div class="card"><h3><a href="${BASE}/services/theme" style="color:inherit;text-decoration:none;">Theme builder</a></h3><p>Save your brand colours and they will follow you across our tools.</p></div>
          <div class="card"><h3><a href="${BASE}/services/embed" style="color:inherit;text-decoration:none;">Embed widgets</a></h3><p>Drop a small script into your site to embed our calculators.</p></div>
          <div class="card"><h3><a href="${BASE}/services/redirect" style="color:inherit;text-decoration:none;">Outbound link helper</a></h3><p>Tracked redirect helper used in our newsletters.</p></div>
          <div class="card"><h3><a href="${BASE}/services/tabs" style="color:inherit;text-decoration:none;">Document tabs</a></h3><p>Single-page document viewer with deep-linkable tabs.</p></div>
        </div>
      </div>
    </section>`;
  res.send(layout('Services', body));
});

// VECTOR: DOM XSS — eval sink consuming URL search param
router.get('/calculator', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">ROI calculator</h1>
        <p class="lead">Type any expression and we will evaluate it. Useful for quick payback maths in client conversations.</p>
        <div style="max-width:540px; margin-top:24px;">
          <input type="text" id="expr-input" placeholder="e.g. 12000 * 0.08 / 12" style="margin-bottom:12px;" value="">
          <button id="calc-btn">Calculate</button>
          <div id="calc-output" class="note info" style="margin-top:16px; min-height:48px;"></div>
          <p class="muted" style="font-size:13px;">Tip: append <code>?expr=…</code> to share a calculation.</p>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var input = document.getElementById('expr-input');
        var output = document.getElementById('calc-output');
        var btn = document.getElementById('calc-btn');
        function run(expr) {
          if (!expr) { output.textContent = 'Type an expression.'; return; }
          try {
            // Evaluate the supplied expression
            var result = eval(expr);
            output.textContent = 'Result: ' + result;
          } catch (e) {
            output.textContent = 'Could not evaluate: ' + e.message;
          }
        }
        btn.addEventListener('click', function () { run(input.value); });
        // Also pick up ?expr= from URL so calculations are shareable
        var params = new URLSearchParams(window.location.search);
        if (params.has('expr')) {
          input.value = params.get('expr');
          run(input.value);
        }
      })();
    </script>`;
  res.send(layout('ROI calculator', body));
});

// VECTOR: DOM XSS — document.write of URL fragment
router.get('/preview', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Campaign preview</h1>
        <p class="lead">Share a preview link with your team. Append your draft markup after the <code>#</code>.</p>
        <div style="margin-top:32px;">
          <iframe id="preview-frame" style="width:100%; height:420px; border:1px solid var(--line); border-radius:8px;"></iframe>
        </div>
        <p class="muted" style="font-size:13px; margin-top:12px;">Example: <code>${BASE}/services/preview#&lt;h2&gt;Hello world&lt;/h2&gt;</code></p>
      </div>
    </section>
    <script>
      (function () {
        var frame = document.getElementById('preview-frame');
        var content = decodeURIComponent(window.location.hash.slice(1) || '<p style="color:#6b7280;font-family:sans-serif;padding:24px;">Append your preview HTML after the # to render it here.</p>');
        var doc = frame.contentDocument || frame.contentWindow.document;
        doc.open();
        doc.write(content);
        doc.close();
      })();
    </script>`;
  res.send(layout('Campaign preview', body));
});

// VECTOR: DOM XSS — postMessage handler that writes to innerHTML without origin check
router.get('/share', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Share studio</h1>
        <p class="lead">Compose a share card for LinkedIn or X. Other tabs can post messages to update the live preview.</p>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-top:32px;">
          <div>
            <label style="display:block; font-size:13px; margin-bottom:6px;">Headline</label>
            <input type="text" id="share-headline" placeholder="Type or paste a headline">
            <button id="post-self" style="margin-top:12px;">Update preview</button>
            <p class="muted" style="font-size:13px; margin-top:24px;">Open this page in a popup from another window and call <code>win.postMessage({headline:"…"}, "*")</code> to update the preview from your editor.</p>
          </div>
          <div>
            <div id="share-preview" style="padding:24px; border:1px solid var(--line); border-radius:8px; min-height:200px; background:#fafbfc;">
              <strong>Preview will appear here.</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var preview = document.getElementById('share-preview');
        var input = document.getElementById('share-headline');
        var btn = document.getElementById('post-self');
        function render(html) { preview.innerHTML = html; }
        btn.addEventListener('click', function () { render(input.value); });
        // Listen for cross-window updates from companion tools
        window.addEventListener('message', function (e) {
          if (e.data && typeof e.data === 'object' && 'headline' in e.data) {
            render(e.data.headline);
          } else if (typeof e.data === 'string') {
            render(e.data);
          }
        });
      })();
    </script>`;
  res.send(layout('Share studio', body));
});

// VECTOR: DOM XSS — localStorage source piped into setTimeout(string)
router.get('/theme', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Theme builder</h1>
        <p class="lead">Save your brand palette and an optional welcome script that runs every time you open a tool page.</p>
        <div style="max-width:540px; margin-top:32px;">
          <div class="form-row">
            <label>Brand colour (hex)</label>
            <input type="text" id="brand-color" placeholder="#2451d6">
          </div>
          <div class="form-row" style="margin-top:14px;">
            <label>Welcome script (optional, evaluated when you load a page)</label>
            <textarea id="welcome-script" placeholder="e.g. console.log('Welcome back, ' + (window.userName || 'team'))"></textarea>
          </div>
          <button id="save-theme" style="margin-top:14px;">Save preferences</button>
          <p class="muted" style="font-size:13px; margin-top:8px;">Stored locally in your browser only.</p>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var brand = document.getElementById('brand-color');
        var welcome = document.getElementById('welcome-script');
        var btn = document.getElementById('save-theme');
        // Pre-populate from existing storage
        brand.value = localStorage.getItem('arg_brand_color') || '';
        welcome.value = localStorage.getItem('arg_welcome_script') || '';
        btn.addEventListener('click', function () {
          localStorage.setItem('arg_brand_color', brand.value);
          localStorage.setItem('arg_welcome_script', welcome.value);
          alert('Saved.');
        });
        // Run any saved welcome script on page load (1s after DOM ready)
        var saved = localStorage.getItem('arg_welcome_script');
        if (saved) {
          setTimeout(saved, 1000);
        }
      })();
    </script>`;
  res.send(layout('Theme builder', body));
});

// VECTOR: Reflected XSS — URL context (?widget= rendered into <a href>) AND attribute (?caption=)
router.get('/embed', (req, res) => {
  const widget = req.query.widget || `${BASE}/services/calculator`;
  const caption = req.query.caption || 'Try our ROI calculator';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Embed widgets</h1>
        <p class="lead">Drop these snippets into your own site to embed any of our tools.</p>
        <div style="margin-top:32px;">
          <a href="${widget}" id="embed-link" class="btn-primary" data-label="${caption}">${caption}</a>
        </div>
        <h3 style="margin-top:32px;">Embed code</h3>
        <pre style="padding:16px; background:#0e1320; color:#e5e7eb; border-radius:8px; overflow-x:auto;"><code>&lt;a href="${widget}"&gt;${caption}&lt;/a&gt;</code></pre>
        <form method="GET" action="${BASE}/services/embed" class="stacked" style="margin-top:32px;">
          <div class="form-row"><label>Widget URL</label><input type="text" name="widget" value="${widget}"></div>
          <div class="form-row"><label>Caption</label><input type="text" name="caption" value="${caption}"></div>
          <button type="submit">Update</button>
        </form>
      </div>
    </section>`;
  res.send(layout('Embed widgets', body));
});

// VECTOR: Reflected XSS — URL context (server-side ?next= rendered into <a href>)
// Open redirect that doubles as a javascript: URI XSS
router.get('/redirect', (req, res) => {
  const next = req.query.next || `${BASE}/`;
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Outbound link helper</h1>
        <p class="lead">You will be redirected to your destination shortly. If nothing happens, click below.</p>
        <p style="margin-top:32px;"><a id="next-link" href="${next}" class="btn-primary">Continue to destination</a></p>
        <p class="muted" style="font-size:13px;">Destination: <code>${next}</code></p>
      </div>
    </section>
    <script>
      // Auto-follow after a short delay
      setTimeout(function () { window.location.href = document.getElementById('next-link').getAttribute('href'); }, 2000);
    </script>`;
  res.send(layout('Redirecting…', body));
});

// VECTOR: DOM XSS — jQuery .html() reading from location.hash (router-style tabs)
router.get('/tabs', (req, res) => {
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Document tabs</h1>
        <p class="lead">Single-page document viewer. Tab state lives in the URL hash so you can deep-link.</p>
        <nav style="display:flex; gap:16px; margin-top:24px; border-bottom:1px solid var(--line); padding-bottom:12px;">
          <a href="#overview">Overview</a>
          <a href="#pricing">Pricing</a>
          <a href="#changelog">Changelog</a>
          <a href="#faq">FAQ</a>
        </nav>
        <div id="tab-content" style="margin-top:24px; padding:24px; border:1px solid var(--line); border-radius:8px; min-height:200px;">
          <p class="muted">Pick a tab above.</p>
        </div>
      </div>
    </section>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
    <script>
      (function () {
        var tabs = {
          overview: '<h3>Overview</h3><p>This is the overview tab — replace with your own content.</p>',
          pricing: '<h3>Pricing</h3><p>Tiered pricing starts at £890/mo with a 14-day trial.</p>',
          changelog: '<h3>Changelog</h3><p>v3.2 — improved warehouse sync.</p>',
          faq: '<h3>FAQ</h3><p>Common questions about the product.</p>'
        };
        function render() {
          var key = window.location.hash.slice(1);
          if (tabs[key]) {
            $('#tab-content').html(tabs[key]);
          } else if (key) {
            // Fallback: render raw hash content for custom deep-links from our docs
            $('#tab-content').html(decodeURIComponent(key));
          }
        }
        window.addEventListener('hashchange', render);
        render();
      })();
    </script>`;
  res.send(layout('Document tabs', body));
});

module.exports = router;
