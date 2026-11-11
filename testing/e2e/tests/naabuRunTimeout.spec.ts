import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * R-9 (B-NAABUSET): the Naabu section's "Run Timeout (s)" field saves to
 * projects.naabu_run_timeout, at full width and at 390 px.
 *
 * The column was added for the naabu container's whole-run cap (default
 * 1800 s). A field that renders and edits but never reaches the row would cap
 * every run at the default whatever the form shows; the spec reads the value
 * back from the project API after each save.
 *
 * A throwaway IP-mode project on an FP-lab address (never scanned), deleted
 * afterwards. Run:
 *   cd testing/e2e && npx playwright test naabuRunTimeout
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: {
      name: 'e2e naabu run timeout (temp)', ipMode: true, targetIps: ['192.88.94.34'],
      engagementKind: 'internal', targetGuardrailEnabled: false,
    },
  })
  expect(res.ok(), `create project: ${res.status()} ${await res.text()}`).toBeTruthy()
  projectId = (await res.json()).id
  expect(await stored(), 'a new project starts at the 1800 s default').toBe(1800)
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
  return (await res.json()).naabuRunTimeout
}

/** Tab view -> Port Scanning; the label is not bound to its input, so the
 *  input is found beside it. */
async function runTimeoutInput(page: Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await page.locator('[title="Tab view"]').first().click({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Port Scanning', exact: true }).first().click()
  const label = page.locator('label', { hasText: /^Run Timeout \(s\)$/ }).first()
  await expect(label).toBeVisible({ timeout: 20_000 })
  return label.locator('xpath=..').locator('input').first()
}

for (const [width, height, value] of [[1600, 1000, '900'], [390, 844, '1200']] as const) {
  test(`Run Timeout (s) saves at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height })
    const input = await runTimeoutInput(page)
    await input.fill(value)
    const save = page.getByRole('button', { name: 'Update Settings', exact: true }).first()
    await expect(save, 'Save stayed disabled, so the form never saw the change').toBeEnabled()
    const [response] = await Promise.all([
      page.waitForResponse(r => r.request().method() === 'PUT'
        && r.url().includes(`/api/projects/${projectId}`), { timeout: 20_000 }),
      save.click(),
    ])
    expect(response.status(), `PUT -> ${response.status()}`).toBeLessThan(400)
    expect(await stored()).toBe(Number(value))
  })
}
