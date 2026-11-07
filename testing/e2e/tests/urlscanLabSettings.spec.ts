import { test, expect, type APIRequestContext, type Page, type Locator } from '@playwright/test'
import { mintToken, signIn } from './auth'
import { envValue } from './uiLogin'

/**
 * urlscan lab, U-02 (testing/guinea_pigs/urlscan_lab/ui_checklist.md): the URLScan,
 * Origin Discovery and Security Checks sections, driven through the real settings
 * form. Texts are the plan's item tables (the "Final UI" mockup paraphrases a few);
 * each switch flips, saves, reloads and flips back, and the stored value is read
 * back through the project API and through MCP get_recon_settings.
 *
 * A throwaway project on example.test, deleted afterwards. The key-dependent lines
 * follow whatever the account holds now: run it once with no urlscan key and once
 * in run B's window (`lab-key`). Run:
 *   cd testing/e2e && npx playwright test urlscanLabSettings
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const SHOTS = '../guinea_pigs/urlscan_lab/generated/ui'
const MCP_URL = '/api/mcp-server'

let projectId = ''
let api: APIRequestContext
let mcpSession = ''

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: 'urlscan-lab U-02 (temp)', targetDomain: 'example.test', originDiscoveryEnabled: true },
  })
  expect(res.ok(), `create project: ${res.status()}`).toBeTruthy()
  projectId = (await res.json()).id
})

test.afterAll(async () => {
  if (projectId) {
    const res = await api.delete(`/api/projects/${projectId}`)
    expect(res.ok(), `delete the throwaway project: ${res.status()}`).toBeTruthy()
  }
  await api?.dispose()
})

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function stored(): Promise<Record<string, unknown>> {
  const res = await api.get(`/api/projects/${projectId}`)
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return res.json()
}

async function setStored(fields: Record<string, unknown>) {
  const res = await api.put(`/api/projects/${projectId}`, { data: fields })
  expect(res.status(), `PUT ${Object.keys(fields).join(',')} -> ${res.status()}`).toBeLessThan(400)
}

/** One MCP tools/call with the account's token (read from .env by name). */
async function mcp(tool: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const token = envValue('MCP_SERVER_TOKEN')
  const post = async (body: Record<string, unknown>) => {
    const res = await api.post(MCP_URL, {
      headers: {
        Authorization: `Bearer ${token}`, Accept: 'application/json, text/event-stream',
        'Content-Type': 'application/json', ...(mcpSession ? { 'Mcp-Session-Id': mcpSession } : {}),
      },
      data: body,
    })
    mcpSession = res.headers()['mcp-session-id'] || mcpSession
    const raw = await res.text()
    const line = raw.split('\n').find(l => l.startsWith('data:'))
    return JSON.parse(line ? line.slice(5) : raw || '{}')
  }
  if (!mcpSession) {
    await post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'urlscan-lab-e2e', version: '1' } } })
    await post({ jsonrpc: '2.0', method: 'notifications/initialized' }).catch(() => undefined)
  }
  for (let attempt = 0; attempt < 6; attempt++) {
    const out = await post({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: tool, arguments: args } })
    const text = (out?.result?.content || []).map((c: { text?: string }) => c.text || '').join('\n')
    const wait = /Try again in (\d+)s/.exec(text)
    if (out?.result?.isError && wait) { await new Promise(r => setTimeout(r, (Number(wait[1]) + 2) * 1000)); continue }
    return { text, isError: Boolean(out?.result?.isError) }
  }
  throw new Error(`${tool} stayed rate-limited`)
}

async function mcpSettings(): Promise<Record<string, unknown>> {
  const { text, isError } = await mcp('get_recon_settings', { projectId })
  expect(isError, `get_recon_settings: ${text.slice(0, 200)}`).toBe(false)
  const body = JSON.parse(text)
  return (body.settings ?? body) as Record<string, unknown>
}

async function openTab(page: Page, tab: string, waitFor: string) {
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: tab, exact: true }).first().click()
  await expect(page.getByText(waitFor).first()).toBeVisible({ timeout: 15_000 })
}

/** A ProjectForm section: the root that carries both `section` and `formSkin`. */
function section(page: Page, title: string): Locator {
  return page.locator('h2[class*="sectionTitle"]', { hasText: title }).first()
    .locator('xpath=ancestor::div[contains(@class, "formSkin")][1]')
}

/** The switch on the toggle row whose label reads `label`. */
function rowSwitch(scope: Locator, label: string): Locator {
  return scope.locator('[class*="toggleRow"]').filter({
    has: scope.page().locator('[class*="toggleLabel"]', { hasText: new RegExp(`^${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }),
  }).getByRole('switch')
}

function rowText(scope: Locator, label: string): Locator {
  return scope.locator('[class*="toggleRow"]').filter({
    has: scope.page().locator('[class*="toggleLabel"]', { hasText: label }),
  })
}

async function save(page: Page): Promise<Record<string, unknown>> {
  const btn = page.getByRole('button', { name: 'Update Settings', exact: true }).first()
  await expect(btn, 'Save stayed disabled, so the form never saw the change').toBeEnabled()
  const [response] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'PUT' &&
      r.url().includes(`/api/projects/${projectId}`), { timeout: 20_000 }),
    btn.click(),
  ])
  expect(response.status(), `PUT -> ${response.status()}`).toBeLessThan(400)
  return response.request().postDataJSON()
}

function watchConsole(page: Page): string[] {
  const errors: string[] = []
  page.on('console', msg => { if (msg.type() === 'error' || /Warning:/.test(msg.text())) errors.push(msg.text()) })
  page.on('pageerror', err => errors.push(String(err)))
  return errors
}

function realErrors(errors: string[]): string[] {
  // Saving leaves for the graph page, which probes for downloads a never-scanned
  // project does not have; those 404s are the only expected noise.
  return errors.filter(e => !e.startsWith('Failed to load resource'))
}

async function hasUrlscanKey(): Promise<boolean> {
  const res = await api.get(`/api/users/${USER}/settings`)
  expect(res.ok(), `user settings -> ${res.status()}`).toBeTruthy()
  return Boolean((await res.json()).urlscanApiKey)
}

const URLSCAN_SWITCHES = [
  { field: 'urlscanRedirectSearch', label: 'Outbound Redirects', byDefault: false },
  { field: 'urlscanLeakedLinks', label: 'Leaked One-Time Links', byDefault: true },
  { field: 'urlscanSecretsInUrls', label: 'Secrets in URLs', byDefault: true },
  { field: 'urlscanSensitiveFiles', label: 'Sensitive Files and Pages', byDefault: true },
  { field: 'urlscanDocumentLinks', label: 'Documents Opened by Direct Link', byDefault: true },
  { field: 'urlscanTakeoverPages', label: 'Takeover Pages', byDefault: true },
  { field: 'urlscanProblemPages', label: 'Problem Pages from Titles and Certificates', byDefault: true },
] as const

const PAGE_CONTENT = [
  { field: 'securityCheckOpenConsoles', label: 'Open Consoles Without Login' },
  { field: 'securityCheckDebugPages', label: 'Debug Pages' },
  { field: 'securityCheckUnfinishedInstallers', label: 'Unfinished Installers' },
  { field: 'securityCheckDevServers', label: 'Development Servers' },
  { field: 'securityCheckDirectoryListing', label: 'Directory Listings' },
  { field: 'securityCheckDefacedPages', label: 'Defaced Pages' },
  { field: 'securityCheckTakeoverErrorPages', label: 'Takeover Error Pages' },
  { field: 'securityCheckTestCertificates', label: 'Test or Default Certificates' },
] as const

test('URLScan section: texts, switches, limits (U-02)', async ({ page }) => {
  test.setTimeout(300_000)
  const errors = watchConsole(page)
  const keyed = await hasUrlscanKey()
  await setStored({ urlscanEnabled: true, routeExposureEnabled: false, subdomainTakeoverEnabled: false })

  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  const s = section(page, 'URLScan.io Enrichment')
  await expect(s.getByText('Passive OSINT enrichment using URLScan.io historical scan data. Discovers ' +
    'subdomains, IPs, ASN info, TLS certificates, server technologies and screenshots, and checks the ' +
    'visits it downloads for leaks, exposed files and problem pages - all without touching the target ' +
    'directly.')).toBeVisible()
  await expect(s.getByText(keyed
    ? 'URLScan API key configured. How far back you can see depends on your urlscan plan.'
    : "No API key: urlscan returns only the last 30 days of visits, 100 per search, without urlscan's " +
      'verdicts; RedAmon reads at most 1,000. Add a key in Global Settings to reach older visits, where ' +
      'the rare leaks are.')).toBeVisible()
  await expect(s.getByText('Values above 10,000 are capped; without a key RedAmon reads at most 1,000.',
    { exact: false })).toBeVisible()
  await expect(s.getByText('+1 urlscan search per domain')).toBeVisible()
  const leakNote = s.getByText('Links containing tokens or passwords are never opened by RedAmon.')
  await expect(leakNote).toBeVisible()
  await expect(leakNote.getByRole('switch')).toHaveCount(0)
  await expect(rowText(s, 'Sensitive Files and Pages')
    .getByText('Turn on Route Exposure to check whether they are still online.', { exact: true })).toBeVisible()
  await expect(rowText(s, 'Takeover Pages')
    .getByText('Subdomain Takeover is off: these hosts get only the DNS and live-page check.', { exact: true })).toBeVisible()
  await expect(page.locator('body')).not.toContainText(/\(item \d+\)/)
  await page.screenshot({ path: `${SHOTS}/urlscan-section${keyed ? '-keyed' : ''}.png`, fullPage: true })

  // Defaults, then every switch flipped, saved, reloaded.
  const before = await stored()
  expect(before.urlscanMaxSearches, 'urlscanMaxSearches default').toBe(60)
  for (const sw of URLSCAN_SWITCHES) expect(before[sw.field], `${sw.field} default`).toBe(sw.byDefault)
  for (const sw of URLSCAN_SWITCHES) {
    const ctl = rowSwitch(s, sw.label)
    await expect(ctl, sw.label).toHaveAttribute('aria-checked', String(sw.byDefault))
    await ctl.click()
    await expect(ctl).toHaveAttribute('aria-checked', String(!sw.byDefault))
  }
  let body = await save(page)
  let after = await stored()
  let viaMcp = await mcpSettings()
  for (const sw of URLSCAN_SWITCHES) {
    expect(body[sw.field], `the PUT never carried ${sw.field}`).toBe(!sw.byDefault)
    expect(after[sw.field], `${sw.field} did not persist`).toBe(!sw.byDefault)
    expect(viaMcp[sw.field], `MCP disagrees on ${sw.field}`).toBe(!sw.byDefault)
  }
  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  for (const sw of URLSCAN_SWITCHES) {
    const ctl = rowSwitch(section(page, 'URLScan.io Enrichment'), sw.label)
    await expect(ctl, `${sw.label} after reload`).toHaveAttribute('aria-checked', String(!sw.byDefault))
    await ctl.click()
  }
  body = await save(page)
  after = await stored()
  viaMcp = await mcpSettings()
  for (const sw of URLSCAN_SWITCHES) {
    expect(after[sw.field], `${sw.field} did not return to its default`).toBe(sw.byDefault)
    expect(viaMcp[sw.field], `MCP disagrees on ${sw.field} after the flip back`).toBe(sw.byDefault)
  }

  // The hints follow the other modules' switches. Max Results starts away from
  // its default so that clearing the field is a change the form can save.
  await setStored({ routeExposureEnabled: true, subdomainTakeoverEnabled: true, urlscanMaxResults: 5000 })
  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  const s2 = section(page, 'URLScan.io Enrichment')
  await expect(rowText(s2, 'Sensitive Files and Pages')
    .getByText('Route Exposure will check whether they are still online.', { exact: true })).toBeVisible()
  await expect(rowText(s2, 'Takeover Pages')
    .getByText("These hosts are added to Subdomain Takeover's list.", { exact: true })).toBeVisible()

  // Max Results: a cleared field shows and saves 10,000; an old project at 50,000 still saves.
  const maxResults = s2.locator('[class*="fieldGroup"]').filter({ hasText: 'Max Results' }).locator('input')
  await maxResults.fill('')
  await expect(maxResults).toHaveValue('10000')
  body = await save(page)
  expect(body.urlscanMaxResults).toBe(10000)
  await setStored({ urlscanMaxResults: 50000 })
  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  await rowSwitch(section(page, 'URLScan.io Enrichment'), 'Outbound Redirects').click()
  body = await save(page)
  expect(body.urlscanMaxResults, 'an old project holding 50,000 saves unchanged').toBe(50000)
  await setStored({ urlscanRedirectSearch: false })

  // Max urlscan searches: 1-1,000, refused outside by the form and by MCP. (The
  // save route checks no field's bounds; the form's input and MCP are the doors.)
  for (const bad of [0, 1001]) {
    const out = await mcp('update_recon_settings', { projectId, settings: { urlscanMaxSearches: bad } })
    expect(out.isError, `MCP accepted urlscanMaxSearches=${bad}: ${out.text.slice(0, 160)}`).toBe(true)
  }
  expect((await stored()).urlscanMaxSearches).toBe(60)
  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  const searches = section(page, 'URLScan.io Enrichment').locator('[class*="fieldGroup"]')
    .filter({ hasText: 'Max urlscan searches per scan' }).locator('input')
  await expect(searches).toHaveAttribute('min', '1')
  await expect(searches).toHaveAttribute('max', '1000')
  for (const bad of ['0', '1001']) {
    await searches.fill(bad)
    const btn = page.getByRole('button', { name: 'Update Settings', exact: true }).first()
    const put = page.waitForResponse(r => r.request().method() === 'PUT' &&
      r.url().includes(`/api/projects/${projectId}`), { timeout: 5_000 }).catch(() => null)
    if (await btn.isEnabled()) await btn.click()
    const sent = await put
    if (sent) {
      expect(sent.request().postDataJSON().urlscanMaxSearches, `the form saved urlscanMaxSearches=${bad}`)
        .not.toBe(Number(bad))
    }
    expect((await stored()).urlscanMaxSearches, `the form stored urlscanMaxSearches=${bad}`).toBe(60)
  }

  // URLScan off hides everything under the description.
  await openTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  const s3 = section(page, 'URLScan.io Enrichment')
  await s3.locator('[class*="sectionHeader"]').getByRole('switch').click()
  await expect(s3.getByText('Max Results', { exact: true })).toHaveCount(0)
  await expect(s3.locator('[class*="toggleRow"]')).toHaveCount(0)
  await expect(s3.getByText('Passive OSINT enrichment using URLScan.io', { exact: false })).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/urlscan-section-off.png`, fullPage: true })

  expect(realErrors(errors), 'console errors while driving the URLScan section').toEqual([])
})

test('Origin Discovery: the urlscan source switch (U-02)', async ({ page }) => {
  test.setTimeout(240_000)
  const errors = watchConsole(page)
  const keyed = await hasUrlscanKey()
  await setStored({ urlscanEnabled: true, originDiscoveryEnabled: true, httpxEnabled: true })
  expect((await stored()).originDiscoveryUrlscan, 'originDiscoveryUrlscan default').toBe(true)

  await openTab(page, 'Discovery & OSINT', 'urlscan history and file fingerprint')
  let row = rowText(page.locator('body'), 'urlscan history and file fingerprint')
  await expect(row.getByText('Two clues from urlscan.io.', { exact: false })).toBeVisible()
  await expect(page.getByText(keyed ? 'urlscan key set.'
    : 'No urlscan key: only the last 30 days. Add a key in Global Settings to reach older addresses.')).toBeVisible()
  await expect(row.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  await row.getByRole('switch').click()
  let body = await save(page)
  expect(body.originDiscoveryUrlscan).toBe(false)
  expect((await mcpSettings()).originDiscoveryUrlscan).toBe(false)

  // URLScan off: greyed out, the sentence appended, the saved value kept.
  await setStored({ urlscanEnabled: false })
  await openTab(page, 'Discovery & OSINT', 'urlscan history and file fingerprint')
  row = rowText(page.locator('body'), 'urlscan history and file fingerprint')
  await expect(row.getByText('Disabled while URLScan is off.', { exact: false })).toBeVisible()
  await expect(row.getByRole('switch')).toBeDisabled()
  await expect(row).toHaveCSS('opacity', '0.5')
  await page.screenshot({ path: `${SHOTS}/origin-urlscan-disabled.png`, fullPage: true })
  await setStored({ urlscanEnabled: true })
  expect((await stored()).originDiscoveryUrlscan, 'the value survived URLScan off').toBe(false)
  await openTab(page, 'Discovery & OSINT', 'urlscan history and file fingerprint')
  row = rowText(page.locator('body'), 'urlscan history and file fingerprint')
  await expect(row.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
  await row.getByRole('switch').click()
  body = await save(page)
  expect(body.originDiscoveryUrlscan).toBe(true)

  // httpx off: the note, and the module itself is not greyed out.
  await setStored({ httpxEnabled: false })
  await openTab(page, 'Discovery & OSINT', 'urlscan history and file fingerprint')
  await expect(page.getByText('httpx is off: in a full scan no host is known to be behind a CDN, so Origin ' +
    'Discovery finds nothing. Partial recon still works on hosts you enter by hand.')).toBeVisible()
  await expect(rowText(page.locator('body'), 'urlscan history and file fingerprint').getByRole('switch')).toBeEnabled()
  await setStored({ httpxEnabled: true })

  expect(realErrors(errors), 'console errors while driving Origin Discovery').toEqual([])
})

test('Security Checks: the Page Content group (U-02)', async ({ page }) => {
  test.setTimeout(240_000)
  const errors = watchConsole(page)
  await setStored({ securityCheckEnabled: true })
  const before = await stored()
  for (const c of PAGE_CONTENT) expect(before[c.field], `${c.field} default`).toBe(true)

  await openTab(page, 'Security Checks', 'Page Content')
  const group = page.locator('[class*="subSection"]').filter({
    has: page.locator('[class*="subSectionTitle"]', { hasText: /^Page Content$/ }),
  })
  await expect(group.getByText('Checks the live page titles, server names and certificates httpx and tlsx ' +
    'already collected. No extra requests.')).toBeVisible()
  await expect(group.locator('[class*="toggleLabel"]')).toHaveText(PAGE_CONTENT.map(c => c.label))
  await page.screenshot({ path: `${SHOTS}/security-page-content.png`, fullPage: true })
  for (const c of PAGE_CONTENT) await rowSwitch(group, c.label).click()
  let body = await save(page)
  const viaMcp = await mcpSettings()
  for (const c of PAGE_CONTENT) {
    expect(body[c.field], `the PUT never carried ${c.field}`).toBe(false)
    expect(viaMcp[c.field], `MCP disagrees on ${c.field}`).toBe(false)
  }
  await openTab(page, 'Security Checks', 'Page Content')
  for (const c of PAGE_CONTENT) {
    const ctl = rowSwitch(group, c.label)
    await expect(ctl, `${c.label} after reload`).toHaveAttribute('aria-checked', 'false')
    await ctl.click()
  }
  body = await save(page)
  for (const c of PAGE_CONTENT) expect((await stored())[c.field], `${c.field} back on`).toBe(true)

  // The section toggle off takes the whole group with it.
  await openTab(page, 'Security Checks', 'Page Content')
  await section(page, 'Security Checks').locator('[class*="sectionHeader"]').getByRole('switch').first().click()
  await expect(page.getByText('Page Content', { exact: true })).toHaveCount(0)

  expect(realErrors(errors), 'console errors while driving Security Checks').toEqual([])
})
