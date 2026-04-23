// Argentum Digital — small consulting site running on Node 20 + Express.
// Lives behind nginx at the /argentum prefix on the public site.

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const { BASE } = require('./lib/layout');

const app = express();
app.set('trust proxy', true);
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));
app.use(bodyParser.json({ limit: '1mb' }));
app.use(cookieParser());

// Static assets
app.use(`${BASE}/static`, express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// Healthcheck for docker
app.get('/healthz', (req, res) => res.status(200).type('text/plain').send('ok'));

// Mount routers under the public prefix
app.use(`${BASE}`, require('./routes/home'));
app.use(`${BASE}/blog`, require('./routes/blog'));
app.use(`${BASE}/products`, require('./routes/products'));
app.use(`${BASE}/services`, require('./routes/services'));
app.use(`${BASE}/account`, require('./routes/account'));
app.use(`${BASE}`, require('./routes/support'));        // /contact, /support, /careers/apply
app.use(`${BASE}/search`, require('./routes/search'));
app.use(`${BASE}`, require('./routes/special'));        // /marketing, /dashboard, /widgets, /blog/note, /services/wizard, /internal
app.use(`${BASE}/api`, require('./routes/api'));
app.use(`${BASE}/admin`, require('./routes/admin'));

// Root redirect when accessed without the prefix
app.get('/', (req, res) => res.redirect(`${BASE}/`));

// 404
app.use((req, res) => {
  res.status(404).type('text/html').send(`<!DOCTYPE html><html><body style="font-family:system-ui;padding:64px;text-align:center;">
    <h1 style="font-size:48px;margin:0;">404</h1>
    <p style="color:#6b7280;">That page is not here.</p>
    <p><a href="${BASE}/">Back to the homepage</a></p>
  </body></html>`);
});

const PORT = parseInt(process.env.PORT || '3001', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[argentum] listening on http://0.0.0.0:${PORT}${BASE}/`);
});
