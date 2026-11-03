import { test, expect, type APIRequestContext, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { envValue, loginThroughUi } from './uiLogin'
import { Driver, LAB_IP, newSession, sessionIds } from './aitlDriver'

/**
 * Regenerates the screenshots on the wiki's Agent in the Loop page. Not an
 * assertion suite: run it when the token form, the onboarding modal or the
 * drawer's loop status changes.
 *
 *   npx playwright test tests/captureAgentInTheLoopDocsShots.spec.ts
 *
 * The token LIST is stubbed (a dev box shows real prefixes and names). The run
 * shots need a live loop run against the local lab `skiller_sqli_csrf`, driven by
 * the scripted driver with a throwaway token that afterAll revokes; every token
 * prefix on screen is replaced with a synthetic one before a shot. Needs
 * AGENT_IN_THE_LOOP_ENABLED=true and MCP_SERVER_ENABLED=true; skips otherwise.
 */

const PASSWORD = envValue('UI_LOGIN_PASSWORD')
const ENV_TOKEN = envValue('MCP_SERVER_TOKEN')
const OUT = join(__dirname, '..', '..', '..', 'redamon.wiki', 'images')
const STATE_PATH = join(tmpdir(), `redamon-e2e-aitl-shots-${process.pid}.json`)
const SHOWN_PREFIX = 'rdmn_mcp_4f1a9c2e'
const DRIVER_NAME = 'Claude Code (laptop)'

test.use({ trace: 'off', storageState: async ({}, use) => use(STATE_PATH) })
test.describe.configure({ mode: 'serial' })
test.setTimeout(300_000)
test.skip(!envValue('UI_LOGIN_USERNAME') || !PASSWORD, 'UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env')

let api: APIRequestContext
let userId = ''
let projectId = ''
let tokenId = ''
let driveToken = ''

const day = 86_400_000
const iso = (offsetDays: number) => new Date(Date.now() + offsetDays * day).toISOString()
const TOKENS = [
  {
    id: 'doc-token-1', name: DRIVER_NAME, tokenPrefix: SHOWN_PREFIX, profile: 'agent_in_the_loop',
    scopes: ['recon:read', 'agent:loop'],
    lastUsedAt: iso(0), expiresAt: iso(29), revokedAt: null, createdAt: iso(-1),
  },
  {
    id: 'doc-token-2', name: 'CI nightly rescan', tokenPrefix: 'rdmn_mcp_b83d07e5', profile: 'custom',
    scopes: ['recon:read', 'recon:scan', 'recon:settings', 'recon:queue'],
    lastUsedAt: iso(-1), expiresAt: iso(340), revokedAt: null, createdAt: iso(-25),
  },
]

async function acceptOverlays(context: BrowserContext) {
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
}

async function stubTokenList(page: Page) {
  await page.route(`**/api/users/${userId}/mcp-tokens`, async route => {
    if (route.request().method() === 'GET') {
      const res = await route.fetch()
      const body = await res.json()
      await route.fulfill({ json: { ...body, tokens: TOKENS } })
      return
    }
    await route.abort()
  })
}

async function shoot(page: Page, target: Locator, name: string) {
  // The run shots show the answering token's prefix: publish a synthetic one.
  await page.evaluate((shown) => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n.nodeValue && /rdmn_mcp_[0-9a-f]{4,}/.test(n.nodeValue)) {
        n.nodeValue = n.nodeValue.replace(/rdmn_mcp_[0-9a-f]{4,}/g, shown)
      }
    }
  }, SHOWN_PREFIX)
  await page.waitForTimeout(300)
  await target.screenshot({ path: join(OUT, name) })
}

async function openTokenTab(page: Page) {
  await stubTokenList(page)
  await page.goto('/settings?tab=mcp-tokens')
  await expect(page.getByRole('heading', { name: /^MCP Server/ })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('CI nightly rescan')).toBeVisible()
  await page.addStyleTag({ content: `
    header, footer, [class*="stickyHeader"], [class*="statusBar"] { position: static !important; }
    * { animation: none !important; transition: none !important; }
  ` })
}

function newTokenForm(page: Page) {
  return page.getByRole('heading', { name: 'New access token' })
    .locator('xpath=ancestor::div[contains(@class,"__formBlock")][1]')
}

async function openDrawer(page: Page) {
  await page.goto(`/graph?project=${projectId}`)
  // /graph closes every drawer when its project changes, and the ?project= one is applied
  // after the first render (the pattern of pluginsSkiller.spec.ts).
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

const drawer = (page: Page) => page.locator('[class*="__drawerOpen"]').first()

test.beforeAll(async ({ browser }) => {
  mkdirSync(OUT, { recursive: true })
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

  const minted = await api.post(`/api/users/${userId}/mcp-tokens`, {
    data: { name: DRIVER_NAME, scopes: ['recon:read', 'agent:loop'], profile: 'agent_in_the_loop', expiresInDays: 30, password: PASSWORD },
  })
  expect(minted.status(), await minted.text()).toBe(201)
  const body = await minted.json()
  tokenId = body.token.id
  driveToken = body.plaintext

  const project = await api.post('/api/projects', {
    data: {
      name: 'AitL lab', ipMode: true, targetIps: [LAB_IP], agentOpenaiModel: 'loop/mcp',
      aiPipelineModel: 'claude-opus-4-6', targetGuardrailEnabled: false,
    },
  })
  expect(project.ok(), await project.text()).toBeTruthy()
  projectId = (await project.json()).id
  // The context stays open: `api` is its request client, used until afterAll.
})

test.afterAll(async () => {
  if (projectId) await api?.delete(`/api/projects/${projectId}`)
  if (tokenId) await api?.delete(`/api/users/${userId}/mcp-tokens/${tokenId}`)
  rmSync(STATE_PATH, { force: true })
})

test.beforeEach(async ({ context, page }) => {
  await acceptOverlays(context)
  await page.setViewportSize({ width: 1400, height: 2400 })
})

test('the driver token: the Agent in the Loop profile', async ({ page }) => {
  // The whole form must fit: an element shot past the viewport renders blank.
  await page.setViewportSize({ width: 1400, height: 3600 })
  await openTokenTab(page)
  await page.getByRole('button', { name: 'New token' }).click()
  await page.getByLabel('Name', { exact: true }).fill(DRIVER_NAME)
  await page.getByLabel('Agent Profile').selectOption('agent_in_the_loop')
  await page.getByLabel('Expires').selectOption('30')
  const form = newTokenForm(page)
  await form.scrollIntoViewIfNeeded()
  await shoot(page, form, 'agent-in-the-loop-token-scopes.png')
})

test('the too-broad warning', async ({ page }) => {
  await openTokenTab(page)
  await page.getByRole('button', { name: 'New token' }).click()
  await page.getByLabel('Name', { exact: true }).fill('one token for everything')
  await page.locator('label', { hasText: 'agent:loop' }).locator('input[type="checkbox"]').check()
  // The Custom profile also ticks kali:exec: the group holding agent:loop shows the warning.
  const group = page.locator('[class*="__scopeGroup"]', { has: page.locator('label', { hasText: 'agent:loop' }) })
  await expect(group.getByRole('alert')).toBeVisible()
  await group.scrollIntoViewIfNeeded()
  await shoot(page, group, 'agent-in-the-loop-token-warning.png')
})

const PACKS = [
  { client: 'claude-code', tab: 'templates/claude-settings.json', file: 'agent-in-the-loop-onboarding-claude.png' },
  { client: 'codex', tab: 'templates/codex-config.toml', file: 'agent-in-the-loop-onboarding-codex.png' },
] as const

for (const { client, tab, file } of PACKS) {
  test(`the onboarding pack for ${client}`, async ({ page }) => {
    await openTokenTab(page)
    await page.getByRole('button', { name: 'Agent Onboarding' }).click()
    await page.locator('#onboardProfile').selectOption('agent_in_the_loop')
    await page.locator('#onboardClient').selectOption(client)
    await page.getByRole('button', { name: 'Generate' }).click()
    await expect(page.getByRole('button', { name: /Download all/ })).toBeVisible({ timeout: 30_000 })
    // The result panel: the pack's files, one template open, the download and where it goes.
    await page.getByRole('button', { name: tab }).click()
    const result = page.locator('[class*="__onboardResult"]').first()
    await result.scrollIntoViewIfNeeded()
    await shoot(page, result, file)
  })
}

test('a live loop run: picker, waiting, no agent, a tool, an approval, the report', async ({ page }) => {
  test.setTimeout(420_000)
  await page.setViewportSize({ width: 1600, height: 1000 })
  const d = new Driver(api, driveToken, 'claude-code')
  await openDrawer(page)

  await page.locator('[class*="__modelBadge"]').first().click()
  await page.getByPlaceholder('Search models...').fill('loop')
  const picker = page.getByRole('heading', { name: 'Change Model' }).locator('xpath=ancestor::div[contains(@class,"__modelModal")][1]')
  await expect(picker.getByText('Agent in the Loop').first()).toBeVisible({ timeout: 30_000 })
  await shoot(page, picker, 'agent-in-the-loop-model-picker.png')
  await page.keyboard.press('Escape')

  const before = await sessionIds(api, projectId)
  await page.getByPlaceholder('Ask a question or type /skill...').fill(
    `Fingerprint the web server on ${LAB_IP}:5000 and tell me what it runs.`)
  await page.getByRole('button', { name: 'Send message' }).click()
  d.session = await newSession(api, projectId, before)
  await expect(page.getByText('Waiting for your agent…')).toBeVisible({ timeout: 30_000 })
  await shoot(page, drawer(page), 'agent-in-the-loop-drawer-waiting.png')

  // No call from any agent for LOOP_DRIVER_SEEN_S (60 s).
  await expect(page.getByText(/No agent is connected/)).toBeVisible({ timeout: 120_000 })
  await shoot(page, drawer(page), 'agent-in-the-loop-no-agent.png')

  const think1 = await d.firstThink()
  await d.submit(think1.stepId, JSON.stringify({
    thought: 'Nothing is known about the server yet: start with its landing page and headers.',
    reasoning: 'A plain GET shows the server banner, the framework and the first forms.',
    action: 'use_tool', tool_name: 'execute_curl', tool_args: { args: `-s -i http://${LAB_IP}:5000/` },
    updated_todo_list: [{ description: 'Fetch the landing page', status: 'in_progress' }],
  }))
  await page.getByRole('button', { name: 'Allow' }).first().click({ timeout: 60_000 })
  const think2 = await d.next(180_000)
  // Tool cards start collapsed: open the curl card to show the lab's real answer.
  await page.locator('[class*="__cardHeaderWrapper"]', { hasText: 'execute_curl' }).last().click()
  await expect(page.getByText(/HTTP\/1/).first()).toBeVisible({ timeout: 30_000 })
  await shoot(page, drawer(page), 'agent-in-the-loop-drawer-run.png')

  await d.submit(think2.stepId, JSON.stringify({
    thought: 'The server answers with a login form; testing it needs the exploitation phase.',
    reasoning: 'Probing the form for injection is active testing, which the person must approve.',
    action: 'transition_phase',
    phase_transition: {
      to_phase: 'exploitation', reason: 'test the login form for SQL injection',
      planned_actions: ['probe the login form'], risks: ['failed logins in the lab log'],
    },
    updated_todo_list: [],
  }))
  const approve = page.getByRole('button', { name: 'Approve' })
  await expect(approve).toBeVisible({ timeout: 60_000 })
  await shoot(page, drawer(page), 'agent-in-the-loop-approval.png')
  await approve.click()

  await d.finish('# Lab web server\n\nThe server on port 5000 answers with a login form. ' +
    'This run stopped after fingerprinting, as the objective asked.')
  await expect(page.getByText('The server on port 5000 answers with a login form.').first()).toBeVisible({ timeout: 60_000 })
  await shoot(page, drawer(page), 'agent-in-the-loop-report.png')
  await d.until('finished', [projectId])
})
