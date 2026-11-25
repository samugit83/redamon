import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'
import { ownerJevProviderId } from './jevProvider'

/**
 * The serialized-object Jev ranking switch, driven through the real settings UI.
 *
 * serializedScanJevRank has two controls bound to one field: "Rank candidates
 * with Jev" on the Serialized Object Scan card (JS Recon tab) and the Serialized
 * Objects card under Target & Modules -> AI in Pipeline. A change on one must show
 * on the other with no copy step, leave the form in the PUT, and persist. Turning
 * it on is refused server-side unless the project selects one of the owner's Jev providers, so the
 * account this signs in as must hold one; the throwaway project selects it.
 *
 * A throwaway project on a .test domain, deleted afterwards. Requires the stack up
 * and the webapp image built. Run:
 *   cd testing/e2e && npx playwright test serializedJevRank
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const jevProviderId = await ownerJevProviderId(api, USER)
  test.skip(!jevProviderId, 'the signed-in account holds no Jev provider (Global Settings -> LLM providers)')
  // The scan card's control stays disabled until AI in Pipeline is on.
  const res = await api.post('/api/projects', {
    data: { name: 'serialized-jev-ui', targetDomain: 'example.test',
            aiInPipeline: true, serializedScanEnabled: true, jevProviderId },
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

async function stored(): Promise<unknown> {
  const res = await api.get(`/api/projects/${projectId}`)
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return (await res.json()).serializedScanJevRank
}

async function openSettings(page: Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
}

async function openTab(page: Page, tab: string) {
  await page.getByRole('button', { name: tab, exact: true }).first().click()
}

function scanCardControl(page: Page) {
  const toggle = page.getByRole('switch', { name: 'Enable Serialized Object Scan' })
  // The header alone also holds the heading; the card is the ancestor that also
  // holds the Jev control.
  return toggle.locator(
    'xpath=ancestor::div[.//h2[contains(normalize-space(.), "Serialized Object Scan")] and .//*[@role="group"]][1]',
  ).getByRole('group', { name: 'Jev hook' })
}

function aiPanelControl(page: Page) {
  return page.getByTestId('ai-hook-serializedScanJevRank').getByRole('group', { name: 'Jev hook' })
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

test('the scan card and the AI in Pipeline card are one switch, and it persists', async ({ page }) => {
  expect(await stored(), 'a new project must start with the ranking off').toBe(false)

  await openSettings(page)

  // On from the scan card...
  await openTab(page, 'JS Recon')
  const scan = scanCardControl(page)
  await expect(scan).toBeVisible({ timeout: 15_000 })
  await expect(scan.getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')
  const scanJev = scan.getByRole('button', { name: 'Jev' })
  // Enabled only once the project's Jev provider has been looked up.
  await expect(scanJev, 'Jev stayed disabled: does the project select a Jev provider?').toBeEnabled({ timeout: 15_000 })
  await scanJev.click()
  await expect(scanJev).toHaveAttribute('aria-pressed', 'true')

  // ...shows on the AI in Pipeline card before anything is saved.
  await openTab(page, 'Target & Modules')
  const panel = aiPanelControl(page)
  await expect(panel).toBeVisible({ timeout: 15_000 })
  await expect(panel.getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')

  let body = await save(page)
  expect(body.serializedScanJevRank, 'the form never sent the switch-on').toBe(true)
  expect(await stored(), 'the switch-on did not persist').toBe(true)

  // Saving leaves the form for the graph. Reopened, both controls show the
  // stored value; off from the AI in Pipeline card shows on the scan card, and
  // persists.
  await openSettings(page)
  await openTab(page, 'JS Recon')
  await expect(scanCardControl(page).getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')
  await openTab(page, 'Target & Modules')
  const reopened = aiPanelControl(page)
  await expect(reopened.getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')
  await reopened.getByRole('button', { name: 'Off' }).click()
  await expect(reopened.getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')
  await openTab(page, 'JS Recon')
  await expect(scanCardControl(page).getByRole('button', { name: 'Off' })).toHaveAttribute('aria-pressed', 'true')

  body = await save(page)
  expect(body.serializedScanJevRank, 'the form never sent the switch-off').toBe(false)
  expect(await stored(), 'the switch-off did not persist').toBe(false)
})
