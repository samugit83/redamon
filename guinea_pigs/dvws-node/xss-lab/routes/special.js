const express = require('express');
const { layout, BASE } = require('../lib/layout');

const router = express.Router();

// All routes here set their own Content-Security-Policy header to reflect
// different deployment postures across the marketing site, customer dashboard,
// embeddable widgets, and a legacy single-page app.

// Marketing campaign banner — CSP allows 'unsafe-inline'
router.get('/marketing/banner', (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  const title = req.query.title || 'Quarter-end campaign';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">${title}</h1>
        <p class="lead">Inline-rendered campaign banner page. Used by our paid acquisition team for short-lived marketing pushes.</p>
        <div class="banner" style="margin-top:32px;">${title}</div>
        <p class="muted" style="margin-top:24px; font-size:13px;">Edit this page via <code>?title=</code></p>
      </div>
    </section>`;
  res.send(layout('Marketing campaign', body));
});

// Customer analytics dashboard — CSP allows 'unsafe-eval' (charting library uses it)
router.get('/dashboard/analytics', (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'");
  const formula = req.query.formula || '12000 * 0.08';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:36px;">Analytics dashboard</h1>
        <p class="lead">Custom KPI builder for your account. Drop a formula in the box and we will plot it.</p>
        <div style="max-width:540px; margin-top:32px;">
          <input type="text" id="formula" value="${formula}" placeholder="e.g. 12000 * 0.08">
          <button id="run">Plot</button>
          <div id="output" class="note info" style="margin-top:16px; min-height:48px;"></div>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var inp = document.getElementById('formula');
        var out = document.getElementById('output');
        document.getElementById('run').addEventListener('click', function () {
          try { out.textContent = 'Plotted value: ' + eval(inp.value); }
          catch (e) { out.textContent = 'Error: ' + e.message; }
        });
        // Auto-run if loaded with ?formula=
        if (inp.value) document.getElementById('run').click();
      })();
    </script>`;
  res.send(layout('Analytics dashboard', body));
});

// Embeddable widget that loads helpers from google.com (CSP allows it for JSONP autocomplete)
router.get('/widgets/jsonp', (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://www.google.com");
  const callback = req.query.callback || '';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Search widget</h1>
        <p class="lead">Embeddable autocomplete that fetches suggestions from Google's public JSONP endpoint.</p>
        <div style="max-width:540px; margin-top:32px;">
          <input type="text" id="suggest" placeholder="Type to search…">
          <ul id="suggestions" style="list-style:none; padding:0; margin-top:12px;"></ul>
        </div>
        ${callback ? `<script src="https://www.google.com/complete/search?client=chrome&q=demo&jsonp=${callback}"></script>` : ''}
      </div>
    </section>
    <script>
      (function () {
        // Stub renderer — production uses Google's JSONP feed
        window.handleSuggest = function (results) {
          var ul = document.getElementById('suggestions');
          (results[1] || []).slice(0, 5).forEach(function (s) {
            var li = document.createElement('li'); li.textContent = s; li.style.padding = '6px 0'; li.style.borderBottom = '1px solid var(--line)';
            ul.appendChild(li);
          });
        };
      })();
    </script>`;
  res.send(layout('Search widget', body));
});

// Blog post served with a strict-but-imperfect nonce CSP
// VECTOR: nonce reuse — the nonce is rendered in the page so an attacker who can inject HTML can reuse it
router.get('/blog/note/:slug', (req, res) => {
  const nonce = 'argentum-' + Math.random().toString(36).slice(2, 10);
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'`);
  const slug = req.params.slug;
  const note = req.query.note || 'A short field note from one of our consultants.';
  const body = `
    <section>
      <div class="container">
        <article class="post">
          <a href="${BASE}/blog" class="muted" style="font-size:13px;">← All insights</a>
          <h1>Field note: ${slug}</h1>
          <p class="byline">Posted under nonce <code>${nonce}</code></p>
          <div id="note-body">${note}</div>
          <script nonce="${nonce}">
            console.log('Field note ${slug} rendered.');
          </script>
        </article>
      </div>
    </section>`;
  res.send(layout(`Field note — ${slug}`, body));
});

// Angular-based pricing wizard — old AngularJS still in production for one tool
// VECTOR: AngularJS template injection — even with strict CSP, ng-* expressions execute
router.get('/services/wizard', (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'self' https://ajax.googleapis.com; script-src 'self' https://ajax.googleapis.com 'unsafe-eval'; style-src 'self' 'unsafe-inline'");
  const greeting = req.query.greeting || 'Welcome';
  const body = `
    <section>
      <div class="container" ng-app="">
        <h1 style="font-size:36px;">{{ '${greeting}' }}</h1>
        <p class="lead">Configure your engagement scope and we will price it instantly.</p>
        <div style="max-width:640px; margin-top:32px;">
          <div class="form-row"><label>Team size</label><input type="number" ng-model="team" value="10"></div>
          <div class="form-row" style="margin-top:14px;"><label>Engagement length (weeks)</label><input type="number" ng-model="weeks" value="12"></div>
          <p style="margin-top:24px; font-size:18px;">Estimate: £{{ team * weeks * 250 }}</p>
        </div>
      </div>
    </section>
    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.6/angular.min.js"></script>`;
  res.send(layout('Pricing wizard', body));
});

// Fully locked-down internal admin area — demonstrates a strict CSP that cannot be bypassed.
// (Useful for the agent to learn when to give up.)
router.get('/internal/board', (req, res) => {
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  const note = req.query.note || 'No notes today.';
  const body = `
    <section>
      <div class="container">
        <h1 style="font-size:32px;">Internal board</h1>
        <p class="lead">Read-only summary for partners. Restricted via a hardened content security policy.</p>
        <div class="banner" style="margin-top:32px;">${note}</div>
      </div>
    </section>`;
  res.send(layout('Internal board', body));
});

module.exports = router;
