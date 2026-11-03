import { test, expect, type Page, type APIRequestContext, type BrowserContext } from '@playwright/test'
import { rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { envValue, loginThroughUi } from './uiLogin'
import { ANSWERS, Driver, LAB_IP, mcpCall, newSession, sessionIds, type Step } from './aitlDriver'

/**
 * Agent in the Loop, end to end, with a scripted driver.
 *
 * The real stack, the real agent, the real MCP server and the local lab
 * `skiller_sqli_csrf` (172.28.0.91:5000 on redamon_pentest-net) only. The
 * driver below plays the external agent: it waits for each step over MCP and
 * answers it by purpose, while the spec drives the RedAmon UI as the person.
 *
 * Needs AGENT_IN_THE_LOOP_ENABLED=true and MCP_SERVER_ENABLED=true; skips
 * otherwise. Signs in once through the form with UI_LOGIN_USERNAME /
 * UI_LOGIN_PASSWORD from .env, mints its own driver tokens through the API
 * (the plaintext stays in memory) and deletes them, and every project it made,
 * at the end.
 */

const USER = envValue('UI_LOGIN_USERNAME')
const PASSWORD = envValue('UI_LOGIN_PASSWORD')
const ENV_TOKEN = envValue('MCP_SERVER_TOKEN')
const MASTER_KEY = envValue('INTERNAL_API_KEY')
const AGENT_URL = `http://localhost:${envValue('AGENT_PORT') || '8090'}`
const STATE_PATH = join(tmpdir(), `redamon-e2e-aitl-${process.pid}.json`)
const OBJECTIVE = 'AitL e2e: fingerprint the lab web server'

test.use({ trace: 'off', storageState: async ({}, use) => use(STATE_PATH) })
test.describe.configure({ mode: 'serial' })
test.setTimeout(240_000)
test.skip(!USER || !PASSWORD, 'UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env')

let api: APIRequestContext
let userId = ''
let projectId = ''
const cleanupProjects: string[] = []
const cleanupTokens: string[] = []
let driveToken = ''
let broadToken = ''

// --- the UI --------------------------------------------------------------------

async function acceptOverlays(context: BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
}

async function openChat(page: Page, project = projectId) {
  await page.goto(`/graph?project=${project}`)
  // /graph closes every drawer when its project changes, and the ?project= one is applied
  // after the first render: wait for the graph, then open the chat until it stays open
  // (the pattern of pluginsSkiller.spec.ts).
  await page.waitForFunction(() => document.documentElement.style.getPropertyValue('--drawer-bottom') !== '')
  const fresh = page.getByRole('button', { name: 'Start new session' })
  await expect(async () => {
    if (!(await fresh.isVisible())) await page.getByRole('button', { name: 'Toggle AI Agent' }).click()
    await expect(fresh).toBeVisible({ timeout: 3_000 })
    await page.waitForTimeout(500)
    await expect(fresh).toBeVisible()
  }).toPass({ timeout: 60_000 })
  await fresh.click()
  await expect(page.getByPlaceholder('Ask a question or type /skill...')).toBeEnabled({ timeout: 30_000 })
}

/** Send the objective, and scope `d` to the chat it starts. */
async function send(page: Page, d: Driver, project = projectId, text = OBJECTIVE) {
  const before = await sessionIds(api, project)
  await page.getByPlaceholder('Ask a question or type /skill...').fill(text)
  await page.getByRole('button', { name: 'Send message' }).click()
  d.session = await newSession(api, project, before)
}

async function createLoopProject(name: string, extra: Record<string, unknown> = {}): Promise<string> {
  const res = await api.post('/api/projects', {
    data: {
      name, ipMode: true, targetIps: [LAB_IP], agentOpenaiModel: 'loop/mcp',
      aiPipelineModel: 'claude-opus-4-6', targetGuardrailEnabled: false, ...extra,
    },
  })
  expect(res.ok(), await res.text()).toBeTruthy()
  const id = (await res.json()).id as string
  cleanupProjects.push(id)
  return id
}

async function mint(name: string, scopes: string[], profile: string): Promise<string> {
  const res = await api.post(`/api/users/${userId}/mcp-tokens`, {
    data: { name, scopes, profile, expiresInDays: 30, password: PASSWORD },   // the shortest preset; afterAll revokes it
  })
  expect(res.status(), await res.text()).toBe(201)
  const body = await res.json()
  cleanupTokens.push(body.token.id)
  return body.plaintext as string
}

// --- lifecycle -------------------------------------------------------------------

test.beforeAll(async ({ browser }) => {
  const context = await browser.newContext({ storageState: undefined })
  await acceptOverlays(context)
  const page = await context.newPage()
  await loginThroughUi(page)
  await context.storageState({ path: STATE_PATH })
  api = context.request
  userId = (await (await api.get('/api/auth/me')).json()).id

  const list = await api.post('/api/mcp-server', {
    headers: { Authorization: `Bearer ${ENV_TOKEN}`, Accept: 'application/json, text/event-stream' },
    data: { jsonrpc: '2.0', id: 0, method: 'tools/list' },
  })
  const names = list.ok() ? ((await list.json()).result?.tools ?? []).map((t: { name: string }) => t.name) : []
  test.skip(!names.includes('loop_wait_step'), 'Agent in the Loop is off on this deployment (or the MCP server is)')

  driveToken = await mint('AitL e2e driver', ['recon:read', 'agent:loop'], 'agent_in_the_loop')
  broadToken = await mint('AitL e2e broad', ['recon:read', 'agent:loop', 'kali:exec'], 'custom')
  projectId = await createLoopProject(`e2e AitL lab ${Date.now()}`)
})

test.afterAll(async () => {
  for (const id of cleanupProjects) await api?.delete(`/api/projects/${id}`)
  for (const id of cleanupTokens) await api?.delete(`/api/users/${userId}/mcp-tokens/${id}`)
  rmSync(STATE_PATH, { force: true })
})

test.beforeEach(async ({ context }) => {
  await acceptOverlays(context)
})

// --- scenarios -------------------------------------------------------------------

test('1. happy path: a confirmed tool, a phase approval, the report', async ({ page }) => {
  const d = new Driver(api, driveToken)   // no driver name: every prompt arrives in full
  await openChat(page)
  await send(page, d)

  // The status chip, not the model badge, which shows the same name.
  await expect(page.locator('[class*="AgentStatusChips-module"]').getByText('Agent in the Loop', { exact: true }))
    .toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('Waiting for your agent…')).toBeVisible()

  const think1 = await d.firstThink()
  expect(think1.contractVersion).toBe(1)
  expect(think1.answerFormat).toBe('json')
  expect(think1.fullPrompt).not.toContain('[[part')

  // Counts only, master key, never on /health.
  const stats = await (await fetch(`${AGENT_URL}/loop/stats`, { headers: { 'x-internal-key': MASTER_KEY } })).json()
  expect(stats.claimed_steps + stats.open_steps).toBeGreaterThanOrEqual(1)
  const health = await (await fetch(`${AGENT_URL}/health`)).json()
  expect(health.loop_enabled).toBe(true)
  expect(health).not.toHaveProperty('open_steps')

  await d.submit(think1.stepId, ANSWERS.curl)
  // execute_curl is a dangerous tool: a loop run always asks the person.
  await page.getByRole('button', { name: 'Allow' }).first().click({ timeout: 60_000 })
  await expect(page.getByText('execute_curl').first()).toBeVisible()

  const think2 = await d.next(180_000)
  expect(think2.purpose).toBe('think')
  expect(think2.fullPrompt).toContain('HTTP/1')   // the real lab answer reached the next step
  await d.submit(think2.stepId, ANSWERS.toExploitation)

  // A phase change waits for the person; the driver sees awaiting_human meanwhile.
  await d.until('awaiting_human', [projectId, ...cleanupProjects])
  await page.getByRole('button', { name: 'Approve' }).click({ timeout: 60_000 })

  await d.finish()
  await expect(page.getByText('This report was written by the e2e driver.')).toBeVisible({ timeout: 60_000 })
  await d.until('finished', [projectId, ...cleanupProjects])
})

test('2-3. a validation retry, paging, and dedup by driver name', async ({ page }) => {
  const d = new Driver(api, driveToken, 'e2e-dedup')
  await openChat(page)
  await send(page, d)

  const think1 = await d.firstThink()
  expect(think1.page.totalChars).toBeGreaterThan(40_000)
  expect(think1.page.nextCursor).not.toBeNull()
  expect(think1.fullPrompt.length).toBe(think1.page.totalChars)

  await d.submit(think1.stepId, '{"thought": "x"')
  const retry = await d.next()
  expect(retry.purpose).toBe('think')
  expect(retry.attempt).toBe(1)
  expect(retry.lastInstruction).toContain('failed validation')
  // The unchanged system tiers arrive as placeholders for this driver name...
  expect(retry.fullPrompt).toContain('[[part ')
  // ...and in full on request.
  const full = await d.readAll(await d.get(retry.stepId, 0, true), true)
  expect(full.fullPrompt).not.toContain('[[part ')

  await d.submit(retry.stepId, ANSWERS.complete)
  await d.finish()
  await d.until('finished', [projectId, ...cleanupProjects])
})

test('4. a dangerous tool the person rejects', async ({ page }) => {
  const d = new Driver(api, driveToken)
  await openChat(page)
  await send(page, d)
  const think1 = await d.firstThink()
  await d.submit(think1.stepId, ANSWERS.curl)
  await page.getByRole('button', { name: 'Deny' }).first().click({ timeout: 60_000 })
  const think2 = await d.next()
  expect(think2.fullPrompt).toContain('User rejected execution of')
  await d.submit(think2.stepId, ANSWERS.complete)
  await d.finish()
})

test('5. a Stop while a step is held', async ({ page }) => {
  const d = new Driver(api, driveToken)
  await openChat(page)
  await send(page, d)
  const think1 = await d.firstThink()
  await page.getByRole('button', { name: 'Stop agent' }).click()
  await d.until('stopped', [projectId, ...cleanupProjects])
  const late = await d.submit(think1.stepId, ANSWERS.complete)
  expect(late.isError).toBe(true)
  expect(late.text).toMatch(/already answered, expired or cancelled/)
})

test('6. a declined step ends the run cleanly', async ({ page }) => {
  const d = new Driver(api, driveToken)
  await openChat(page)
  await send(page, d)
  const think1 = await d.firstThink()
  await d.decline(think1.stepId, 'e2e decline')
  await expect(page.getByText('Your agent declined this step: e2e decline')).toBeVisible({ timeout: 30_000 })
  await d.finish()
  await expect.poll(async () => {
    const res = await api.get(`/api/conversations?projectId=${projectId}`)
    const rows = (await res.json()) as { agentRunning?: boolean }[]
    return Array.isArray(rows) && rows.every(r => !r.agentRunning)
  }, { timeout: 30_000 }).toBe(true)
})

test('7. refusals: no permission, a too-broad token, an unknown step, NL graph queries', async () => {
  const noScope = await mcpCall(api, ENV_TOKEN, 'loop_wait_step', { waitSeconds: 1 })
  expect(noScope.isError).toBe(true)
  expect(noScope.text).toContain('agent:loop')

  const broad = await mcpCall(api, broadToken, 'loop_wait_step', { waitSeconds: 1 })
  expect(broad.isError).toBe(true)
  expect(broad.text).toMatch(/can also kali:exec/)

  const unknown = await mcpCall(api, driveToken, 'loop_submit_step', { stepId: 'e'.repeat(32), answer: '{}' })
  expect(unknown.isError).toBe(true)

  const nl = await mcpCall(api, ENV_TOKEN, 'query_graph', { projectId, question: 'list every domain' })
  expect(nl.isError).toBe(true)
  expect(nl.text).toContain('Agent in the Loop')
})

test('8. no agent connected, then one connects', async ({ page }) => {
  test.setTimeout(300_000)
  const d = new Driver(api, driveToken)
  await openChat(page)
  await send(page, d)
  // The driver stays silent past LOOP_DRIVER_SEEN_S (60 s).
  await expect(page.getByText(/No agent is connected/)).toBeVisible({ timeout: 120_000 })
  await expect(page.getByRole('link', { name: 'Set up Agent in the Loop' })).toBeVisible()
  const think1 = await d.firstThink()
  await expect(page.getByText(/No agent is connected/)).toBeHidden({ timeout: 30_000 })
  await d.submit(think1.stepId, ANSWERS.complete)
  await d.finish()
})

test('10. deleting the project mid-run stops it', async ({ page }) => {
  const doomed = await createLoopProject(`e2e AitL doomed ${Date.now()}`)
  const d = new Driver(api, driveToken)
  await openChat(page, doomed)
  await send(page, d, doomed)
  const think1 = await d.firstThink()
  expect((await api.delete(`/api/projects/${doomed}`)).ok()).toBeTruthy()
  cleanupProjects.splice(cleanupProjects.indexOf(doomed), 1)
  const late = await d.submit(think1.stepId, ANSWERS.complete)
  expect(late.isError).toBe(true)
  // The conversation went with the project: a wait scoped to it is refused, and an
  // unscoped one lists no session of the deleted project.
  const scoped = await mcpCall(api, driveToken, 'loop_wait_step', { waitSeconds: 1, sessionId: d.session })
  expect(scoped.isError).toBe(true)
  expect(scoped.text).toContain('Session not found')
  const after = await d.wait(2, '')
  expect(after.sessions.filter((s: Step) => s.projectId === doomed)).toEqual([])
})

test('12. dangerous tools always ask in a loop run, whatever the project setting', async ({ page }) => {
  const lax = await createLoopProject(`e2e AitL no-confirm ${Date.now()}`, { requireToolConfirmation: false })
  const d = new Driver(api, driveToken)
  await openChat(page, lax)
  await send(page, d, lax)
  const think1 = await d.firstThink()
  await d.submit(think1.stepId, ANSWERS.curl)
  await expect(page.getByRole('button', { name: 'Deny' }).first()).toBeVisible({ timeout: 60_000 })
  await page.getByRole('button', { name: 'Deny' }).first().click()
  const think2 = await d.next()
  await d.submit(think2.stepId, ANSWERS.complete)
  await d.finish()
})

test('14. an imported project never arrives on Agent in the Loop', async () => {
  const exported = await api.get(`/api/projects/${projectId}/export`)
  expect(exported.ok()).toBeTruthy()
  const res = await api.post('/api/projects/import', {
    multipart: { file: { name: 'aitl.zip', mimeType: 'application/zip', buffer: Buffer.from(await exported.body()) } },
  })
  expect(res.ok(), await res.text()).toBeTruthy()
  const body = await res.json()
  cleanupProjects.push(body.projectId)
  expect(body.warnings.join('\n')).toMatch(/used Agent in the Loop; it was imported with/)
  const imported = await (await api.get(`/api/projects/${body.projectId}`)).json()
  expect(imported.agentOpenaiModel).not.toMatch(/^loop\//)
})
