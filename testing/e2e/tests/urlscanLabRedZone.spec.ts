import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'
import { envValue } from './uiLogin'

/**
 * urlscan lab, U-03 to U-05 (testing/guinea_pigs/urlscan_lab/ui_checklist.md), on
 * a lab project after its full run: the Red Zone tabs, the partial window's
 * counts and the current-DNS readers. Read-only. Expected numbers are computed
 * from the project's own graph (MCP query_graph), so the spec holds for any run
 * of the lab, not one frozen graph.
 *
 * URLSCAN_LAB_RUN names the project in the lab's generated/projects.json (default
 * A-p2: run A's settings in a project no later run rewrites). Run T's project
 * adds the Takeover tab. Run:
 *   cd testing/e2e && URLSCAN_LAB_RUN=A-p2 npx playwright test urlscanLabRedZone
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const LAB = join(__dirname, '..', '..', 'guinea_pigs', 'urlscan_lab')
const SHOTS = join(LAB, 'generated', 'ui')
const RUN = process.env.URLSCAN_LAB_RUN || 'A-p2'
const OLD_IP = '192.88.97.98'

function labProject(): string {
  const file = join(LAB, 'generated', 'projects.json')
  if (!existsSync(file)) return ''
  return (JSON.parse(readFileSync(file, 'utf8'))[RUN] || {}).id || ''
}

/** The planted values: compared against page text, never printed. */
function plantedValues(): string[] {
  const file = join(LAB, 'generated', 'tokens.json')
  if (!existsSync(file)) return []
  return Object.values(JSON.parse(readFileSync(file, 'utf8')) as Record<string, string>)
    .filter(v => typeof v === 'string' && v.length >= 8)
}

const projectId = labProject()
test.skip(!projectId, `no lab project for run ${RUN}: run the urlscan lab first`)

let api: APIRequestContext
let mcpSession = ''

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
})

test.afterAll(async () => { await api?.dispose() })

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function mcp(tool: string, args: Record<string, unknown>): Promise<unknown> {
  const token = envValue('MCP_SERVER_TOKEN')
  const post = async (body: Record<string, unknown>) => {
    const res = await api.post('/api/mcp-server', {
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
    expect(out?.result?.isError, `${tool}: ${text.slice(0, 200)}`).toBeFalsy()
    return JSON.parse(text)
  }
  throw new Error(`${tool} stayed rate-limited`)
}

async function cypherValue(cypher: string): Promise<unknown> {
  const out = await mcp('query_graph', { projectId, cypher }) as { records: Array<Record<string, unknown>> }
  return Object.values(out.records[0] || {})[0]
}

async function route(path: string): Promise<{ rows: Array<Record<string, unknown>> } & Record<string, unknown>> {
  const res = await api.get(path)
  expect(res.ok(), `${path} -> ${res.status()}`).toBeTruthy()
  return res.json()
}

async function openTable(page: Page, table: string) {
  await page.goto(`/graph?project=${projectId}&table=${table}`)
  await page.waitForLoadState('networkidle')
}

async function noPlantedValue(page: Page, where: string) {
  const text = await page.locator('body').innerText()
  const leaked = plantedValues().filter(v => text.includes(v)).length
  expect(leaked, `${leaked} planted value(s) visible on ${where}`).toBe(0)
}

test('Web Init-Access lists the open console and the installer (U-03)', async ({ page }) => {
  const body = await route(`/api/analytics/redzone/webInitAccess?projectId=${projectId}`)
  const urls = body.rows.map(r => r.baseUrl)
  expect(urls).toContain('https://jupyter.uslab.test')
  expect(urls).toContain('https://install.uslab.test')
  await openTable(page, 'webInitAccess')
  await expect(page.getByText('jupyter.uslab.test').first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('install.uslab.test').first()).toBeVisible()
  await page.screenshot({ path: `${SHOTS}/redzone-web-init-access-${RUN}.png`, fullPage: true })
})

test('DNS Drift keeps the old address as history, not current DNS (U-03)', async ({ page }) => {
  const body = await route(`/api/analytics/redzone/dnsDrift?projectId=${projectId}`)
  const row = body.rows.find(r => r.domain === 'uslab.test')
  expect(row, 'no DNS Drift row for uslab.test').toBeTruthy()
  expect(row!.currentIps as string[]).not.toContain(OLD_IP)
  const history = (row!.historicResolutions as Array<Record<string, unknown>>)
    .filter(h => h.address === OLD_IP)
  expect(history.map(h => [h.host, h.source])).toContainEqual(['app.uslab.test', 'urlscan'])
  await openTable(page, 'dnsDrift')
  // The history is the tooltip of the Historic IPs count; Current IPs is shown.
  const historic = page.locator(`span[title*="${OLD_IP}"]`).first()
  await expect(historic).toBeAttached({ timeout: 30_000 })
  const tip = await historic.getAttribute('title')
  expect(tip!.split('\n').find(l => l.includes(OLD_IP))).toContain('urlscan history')
  const uslabRow = page.locator('tr', { hasText: 'uslab.test' }).first()
  await expect(uslabRow).toBeVisible()
  expect(await uslabRow.innerText(), 'the old address shown as a current IP').not.toContain(OLD_IP)
  await page.screenshot({ path: `${SHOTS}/redzone-dns-drift-${RUN}.png`, fullPage: true })
})

test('Secrets: urlscan history, masked, no value anywhere (U-03)', async ({ page }) => {
  const body = await route(`/api/analytics/redzone/secrets?projectId=${projectId}`)
  const urlscan = body.rows.filter(r => r.sourceModule === 'urlscan history')
  expect(urlscan.length, 'no urlscan Secret in the table').toBeGreaterThan(0)
  for (const r of urlscan) {
    expect(r.valueSample, `${r.id} carries a value sample`).toBeNull()
    expect(r.matchedText, `${r.id} carries matched text`).toBeNull()
    expect(String(r.sourceUrl), `${r.id} URL is not masked`).toMatch(/\*\*\*|\{token\}/)
  }
  await openTable(page, 'secrets')
  await expect(page.getByText('urlscan history').first()).toBeVisible({ timeout: 30_000 })
  await noPlantedValue(page, 'the Secrets tab')
  await page.screenshot({ path: `${SHOTS}/redzone-secrets-${RUN}.png`, fullPage: true })
})

test('the badges light for the new rows and clear once seen (U-03)', async () => {
  const tabs = ['webInitAccess', 'secrets', 'dnsDrift']
  const lit = await api.post('/api/analytics/unseen', {
    data: { projectId, marks: Object.fromEntries(tabs.map(t => [t, '2000-01-01T00:00:00Z'])) },
  })
  expect(lit.ok()).toBeTruthy()
  const litBody = await lit.json()
  for (const t of tabs) expect(litBody.counts[t], `${t} badge before it was seen`).toBeGreaterThan(0)
  const seen = await api.post('/api/analytics/unseen', {
    data: { projectId, marks: Object.fromEntries(tabs.map(t => [t, litBody.now])) },
  })
  const seenBody = await seen.json()
  for (const t of tabs) expect(seenBody.counts[t], `${t} badge after it was seen`).toBe(0)
})

test('urlscan findings say "seen in a public urlscan scan", never "vulnerable" (U-03)', async () => {
  const total = Number(await cypherValue(
    "MATCH (v:Vulnerability {source: 'urlscan_leak'}) RETURN count(v) AS n"))
  expect(total, 'no urlscan finding in the project').toBeGreaterThan(0)
  const vulnerable = Number(await cypherValue(
    "MATCH (v:Vulnerability {source: 'urlscan_leak'}) WHERE toLower(coalesce(v.name, '') + ' ' + " +
    "coalesce(v.description, '')) CONTAINS 'vulnerable' RETURN count(v) AS n"))
  expect(vulnerable).toBe(0)
  const worded = Number(await cypherValue(
    "MATCH (v:Vulnerability {source: 'urlscan_leak'}) WHERE toLower(coalesce(v.description, '')) " +
    "CONTAINS 'public urlscan scan' RETURN count(v) AS n"))
  expect(worded, 'findings whose description names the public urlscan scan').toBe(total)
})

test('the partial window counts what the tools will read (U-04)', async () => {
  const inScope = "toLower(split(split(split(e.baseurl, '://')[1], '/')[0], ':')[0]) ENDS WITH 'uslab.test'"
  const expected = Number(await cypherValue(
    `MATCH (e:Endpoint) WHERE coalesce(e.quarantined, false) = false AND ${inScope} RETURN count(e) AS n`))
  const quarantined = Number(await cypherValue(
    'MATCH (e:Endpoint) WHERE e.quarantined = true RETURN count(e) AS n'))
  expect(quarantined, 'the lab plants quarantined links').toBeGreaterThan(0)
  for (const tool of ['Nuclei', 'RouteExposure']) {
    const res = await api.get(`/api/recon/${projectId}/graph-inputs/${tool}`)
    expect(res.ok()).toBeTruthy()
    expect((await res.json()).existing_endpoints_count, `${tool}'s endpoint count`).toBe(expected)
  }
  const currentIps = Number(await cypherValue(
    'MATCH (:Subdomain)-[r:RESOLVES_TO]->(i:IP) WHERE r.source IS NULL RETURN count(DISTINCT i) AS n'))
  const oldIsCurrent = Number(await cypherValue(
    `MATCH (:Subdomain)-[r:RESOLVES_TO]->(i:IP {address: '${OLD_IP}'}) WHERE r.source IS NULL RETURN count(r) AS n`))
  expect(oldIsCurrent, `${OLD_IP} reached through current DNS`).toBe(0)
  const res = await api.get(`/api/recon/${projectId}/graph-inputs/Httpx`)
  expect((await res.json()).existing_ips_count, "Httpx's IP count").toBe(currentIps)
})

test('the current-DNS readers never count the old address (U-05)', async () => {
  for (const path of [
    `/api/analytics/graph-overview?projectId=${projectId}`,
    `/api/analytics/attack-surface?projectId=${projectId}`,
    `/api/analytics/redzone/killChain?projectId=${projectId}`,
    `/api/analytics/redzone/sharedInfra?projectId=${projectId}`,
  ]) {
    const res = await api.get(path)
    expect(res.ok(), `${path} -> ${res.status()}`).toBeTruthy()
    expect(await res.text(), path).not.toContain(OLD_IP)
  }
})

test('Takeover lists the urlscan pages and the live error pages with their source (U-03, run T)', async ({ page }) => {
  test.skip(RUN !== 'T', 'the takeover hosts exist only in run T')
  const body = await route(`/api/analytics/redzone/takeover?projectId=${projectId}`)
  const found = body.rows.map(r => `${r.hostname ?? r.host ?? r.subdomain}|${r.foundBy}`)
  expect(found.some(f => f.endsWith('|urlscan history')), `rows: ${found.join(', ')}`).toBe(true)
  expect(found.some(f => f.endsWith('|live check')), `rows: ${found.join(', ')}`).toBe(true)
  await openTable(page, 'takeover')
  await expect(page.getByText('urlscan history').first()).toBeVisible({ timeout: 30_000 })
  await page.screenshot({ path: `${SHOTS}/redzone-takeover-${RUN}.png`, fullPage: true })
})
