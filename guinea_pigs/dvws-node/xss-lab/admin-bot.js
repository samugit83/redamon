// Internal headless browser that periodically loads the moderation queue.
// This is what makes the blind-XSS surfaces actually fire — any JavaScript
// embedded in stored submissions executes in this real browser context.

const puppeteer = require('puppeteer-core');

const INBOX_URL = 'http://127.0.0.1:3001/argentum/admin/inbox';
const INTERVAL_MS = parseInt(process.env.ADMIN_BOT_INTERVAL_MS || '30000', 10);
const VIEWER_COOKIE = 'admin_session=internal-bot-' + Math.random().toString(36).slice(2, 12);

let browser = null;

async function ensureBrowser() {
  if (browser && browser.connected) return browser;
  browser = await puppeteer.launch({
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium',
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--no-first-run',
      '--no-zygote',
    ],
  });
  console.log('[admin-bot] browser launched');
  return browser;
}

async function visitOnce() {
  const b = await ensureBrowser();
  const ctx = await b.createBrowserContext();
  const page = await ctx.newPage();

  // Make the bot identifiable so the inbox route lets it in
  await page.setExtraHTTPHeaders({ 'X-Internal-Bot': '1' });
  await page.setCookie({
    name: 'admin_session',
    value: VIEWER_COOKIE.split('=')[1],
    domain: '127.0.0.1',
    path: '/',
  });

  // Capture anything noisy that fires
  page.on('dialog', async d => {
    console.log(`[admin-bot] dialog (${d.type()}): ${d.message()}`);
    await d.dismiss().catch(() => {});
  });
  page.on('console', msg => {
    // Log everything except generic resource-load errors so noisy console.log
    // inside legitimate page code still surfaces in the moderation log.
    const text = msg.text();
    if (msg.type() === 'error' && text.includes('Failed to load resource')) return;
    console.log(`[admin-bot] console.${msg.type()}: ${text}`);
  });
  page.on('request', req => {
    // Surface outbound requests other than the inbox load itself — useful
    // when someone embeds a fetch() in a stored submission.
    const url = req.url();
    if (url.indexOf(INBOX_URL) !== 0 && !url.startsWith('http://127.0.0.1:3001/argentum/static/')) {
      console.log(`[admin-bot] outbound request: ${req.method()} ${url}`);
    }
  });

  try {
    await page.goto(INBOX_URL, { waitUntil: 'networkidle2', timeout: 20000 });
    // Linger so async fetch()/setTimeout payloads have time to complete
    await new Promise(r => setTimeout(r, 5000));
  } catch (e) {
    console.log(`[admin-bot] visit error: ${e.message}`);
  } finally {
    await ctx.close().catch(() => {});
  }
}

async function loop() {
  while (true) {
    try {
      await visitOnce();
    } catch (e) {
      console.log(`[admin-bot] loop error: ${e.message}`);
    }
    await new Promise(r => setTimeout(r, INTERVAL_MS));
  }
}

loop().catch(e => {
  console.error('[admin-bot] fatal:', e);
  process.exit(1);
});
