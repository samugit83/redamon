import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'
import { ownerJevProviderId } from './jevProvider'

/**
 * The three Route Exposure Jev hooks, driven through the real settings UI.
 *
 * routeExposureJevRank, routeExposureJevWallCheck and routeExposureJevAssess each
 * have two controls bound to one field: a row under "Jev decisions" on
 * the Route Exposure card (Vulnerability Scanning tab) and a card under Target &
 * Modules -> AI in Pipeline. A change on one must show on the other with no copy
 * step, leave the form in the PUT, and persist. Turning one on is refused
 * server-side unless the project selects one of the owner's Jev providers, so the
 * account this signs in as must hold one; the throwaway project selects it.
 *
 * A throwaway project on a .test domain, deleted afterwards. Requires the stack up
 * and the webapp image built. Run:
 *   cd testing/e2e && npx playwright test routeExposureJev
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

const HOOKS = [
  { field: 'routeExposureJevRank', row: 'Rank routes with Jev' },
  { field: 'routeExposureJevWallCheck', row: 'Spot disguised login walls with Jev' },
  { field: 'routeExposureJevAssess', row: 'Assess leads with Jev' },
] as const

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const jevProviderId = await ownerJevProviderId(api, USER)
  test.skip(!jevProviderId, 'the signed-in account holds no Jev provider (Global Settings -> LLM providers)')
  // The module card's rows render only with Route Exposure on, and stay disabled
  // until AI in Pipeline is on.
  const res = await api.post('/api/projects', {
    data: { name: 'route-exposure-jev-ui', targetDomain: 'example.test',
            aiInPipeline: true, routeExposureEnabled: true, jevProviderId },
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

async function openSettings(page: Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
}

async function openTab(page: Page, tab: string) {
  await page.getByRole('button', { name: tab, exact: true }).first().click()
}

function moduleControl(page: Page, row: string) {
  return page.getByText(row, { exact: true }).first()
    .locator('xpath=ancestor::div[.//*[@role="group"]][1]')
    .getByRole('group', { name: 'Jev hook' })
}

function aiPanelControl(page: Page, field: string) {
  return page.getByTestId(`ai-hook-${field}`).getByRole('group', { name: 'Jev hook' })
}

/** Saves the form and returns the body it PUT. Waits for the RESPONSE, so a
 *  read-back never races the write. */
async function save(page: Page): Promise<Record<string, unknown>> {
  // Exact name: "Save as Preset" sits earlier in the DOM and saves nothing.
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

test('each module row and its AI in Pipeline card are one switch, and it persists', async ({ page }) => {
  const initial = await stored()
  for (const { field } of HOOKS) {
    expect(initial[field], `a new project must start with ${field} off`).toBe(false)
  }

  await openSettings(page)

  // On from the module card...
  await openTab(page, 'Vulnerability Scanning')
  for (const { row } of HOOKS) {
    const control = moduleControl(page, row)
    await expect(control, row).toBeVisible({ timeout: 15_000 })
    await expect(control.getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')
    const jev = control.getByRole('button', { name: 'Jev' })
    // Enabled only once the project's Jev provider has been looked up.
    await expect(jev, 'Jev stayed disabled: does the project select a Jev provider?').toBeEnabled({ timeout: 15_000 })
    await jev.click()
    await expect(jev).toHaveAttribute('aria-pressed', 'true')
  }

  // ...shows on the AI in Pipeline cards before anything is saved.
  await openTab(page, 'Target & Modules')
  for (const { field } of HOOKS) {
    const panel = aiPanelControl(page, field)
    await expect(panel, field).toBeVisible({ timeout: 15_000 })
    await expect(panel.getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')
  }

  let body = await save(page)
  let after = await stored()
  for (const { field } of HOOKS) {
    expect(body[field], `the form never sent ${field} on`).toBe(true)
    expect(after[field], `${field} on did not persist`).toBe(true)
  }

  // Saving leaves the form for the graph. Reopened, off from the AI in Pipeline
  // cards shows on the module card, and persists.
  await openSettings(page)
  await openTab(page, 'Target & Modules')
  for (const { field } of HOOKS) {
    const panel = aiPanelControl(page, field)
    await expect(panel.getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')
    await panel.getByRole('button', { name: 'Off' }).click()
    await expect(panel.getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')
  }
  await openTab(page, 'Vulnerability Scanning')
  for (const { row } of HOOKS) {
    await expect(moduleControl(page, row).getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')
  }

  body = await save(page)
  after = await stored()
  for (const { field } of HOOKS) {
    expect(body[field], `the form never sent ${field} off`).toBe(false)
    expect(after[field], `${field} off did not persist`).toBe(false)
  }
})

test('with AI in Pipeline off both controls are disabled, and the master switch never moves them', async ({ page }) => {
  await openSettings(page)
  await openTab(page, 'Target & Modules')
  for (const { field } of HOOKS) {
    const jev = aiPanelControl(page, field).getByRole('button', { name: 'Jev' })
    await expect(jev, 'Jev stayed disabled: does the project select a Jev provider?').toBeEnabled({ timeout: 15_000 })
    await jev.click()
    await expect(jev).toHaveAttribute('aria-pressed', 'true')
  }

  const master = page.getByText('Enable AI in Pipeline', { exact: true }).first()
    .locator('xpath=ancestor::div[.//*[@role="switch"]][1]').getByRole('switch').first()
  await expect(master).toHaveAttribute('aria-checked', 'true')
  await master.click()
  await expect(master).toHaveAttribute('aria-checked', 'false')

  // With the master off the AI in Pipeline panel hides every hook card, as for
  // every other hook; the module card keeps its rows, disabled with the hint.
  await expect(page.getByTestId('ai-hook-list')).toHaveCount(0)
  const hint = 'Enable "AI in Pipeline" in the Target tab to turn this on.'
  await openTab(page, 'Vulnerability Scanning')
  for (const { row } of HOOKS) {
    const jev = moduleControl(page, row).getByRole('button', { name: 'Jev' })
    await expect(jev).toBeDisabled()
    await expect(jev).toHaveAttribute('title', hint)
    await expect(jev).toHaveAttribute('aria-pressed', 'true')
  }

  const body = await save(page)
  const after = await stored()
  expect(body.aiInPipeline).toBe(false)
  for (const { field } of HOOKS) {
    expect(after[field], `the master switch reset ${field}`).toBe(true)
  }

  // Back on, the cards return holding the stored value: the master never moved it.
  await openSettings(page)
  await openTab(page, 'Target & Modules')
  const masterAgain = page.getByText('Enable AI in Pipeline', { exact: true }).first()
    .locator('xpath=ancestor::div[.//*[@role="switch"]][1]').getByRole('switch').first()
  await masterAgain.click()
  await expect(masterAgain).toHaveAttribute('aria-checked', 'true')
  for (const { field } of HOOKS) {
    await expect(aiPanelControl(page, field).getByRole('button', { name: 'Jev' }), field)
      .toHaveAttribute('aria-pressed', 'true')
  }
})
