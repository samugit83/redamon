import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * R-3b: the project form saves a project whose RoE never-touch hosts hold a
 * path-form entry (`192.88.94.11/admin`) and a `*.domain`, and refuses, before
 * any PUT, an entry that would exclude nothing (`0.5`, `010.0.0.5`).
 *
 * Before R-3b the form's own validator rejected the path form the registry,
 * MCP and the RoE parser all store, so editing ANY other field of such a
 * project failed to save. Checked at full width and at 390 px.
 *
 * A throwaway IP-mode project on an FP-lab address (never scanned), deleted
 * afterwards. Run:
 *   cd testing/e2e && npx playwright test roeExclusionForm
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const STORED = ['192.88.94.11/admin', '*.example.test']

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: {
      name: 'e2e roe path-form exclusions (temp)', ipMode: true, targetIps: ['192.88.94.34'],
      engagementKind: 'internal', targetGuardrailEnabled: false, roeExcludedHosts: STORED,
    },
  })
  expect(res.ok(), `create project: ${res.status()} ${await res.text()}`).toBeTruthy()
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

async function row(): Promise<Record<string, unknown>> {
  const res = await api.get(`/api/projects/${projectId}`)
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return await res.json()
}

/** The text input named `name` ("Excluded host 1" also names its Remove button). */
const box = (page: Page, name: string) => page.getByRole('textbox', { name, exact: true })

/** Tab view -> Target & Modules, where the never-touch hosts live. */
async function openTargetSection(page: Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i }).or(page.getByText('Project Settings').first()))
    .toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'Target & Modules', exact: true }).first().click()
  await expect(box(page, 'Excluded host 1')).toBeVisible({ timeout: 20_000 })
}

for (const [width, height] of [[1600, 1000], [390, 844]] as const) {
  test.describe(`at ${width} px`, () => {
    test.use({ viewport: { width, height } })

    test('a project with a path-form exclusion saves an edit to another field', async ({ page }) => {
      await openTargetSection(page)
      await expect(box(page, 'Excluded host 1')).toHaveValue(STORED[0])
      await expect(box(page, 'Excluded host 2')).toHaveValue(STORED[1])

      const reason = `R-3b reason at ${width} px`
      await box(page, 'Exclusion reason 1').fill(reason)
      const save = page.getByRole('button', { name: 'Update Settings', exact: true }).first()
      await expect(save, 'Save stayed disabled, so the form never saw the change').toBeEnabled()
      // Wait for the RESPONSE: reading the row back while the PUT is in flight
      // reports the old value and looks like a save that did not persist.
      const [response] = await Promise.all([
        page.waitForResponse(r => r.request().method() === 'PUT'
          && r.url().includes(`/api/projects/${projectId}`), { timeout: 20_000 }),
        save.click(),
      ])
      expect(response.status(), `PUT -> ${response.status()}`).toBeLessThan(400)
      const stored = await row()
      expect(stored.roeExcludedHosts).toEqual(STORED)
      expect((stored.roeExcludedHostReasons as string[])[0]).toBe(reason)
    })

    for (const bad of ['0.5', '010.0.0.5']) {
      test(`an entry that excludes nothing ("${bad}") is refused before any PUT`, async ({ page }) => {
        await openTargetSection(page)
        let puts = 0
        page.on('request', r => {
          if (r.method() === 'PUT' && r.url().includes(`/api/projects/${projectId}`)) puts++
        })
        await page.getByRole('button', { name: 'Add excluded host' }).click()
        await box(page, 'Excluded host 3').fill(bad)
        await page.getByRole('button', { name: 'Update Settings', exact: true }).first().click()
        await expect(page.getByText(
          `Excluded host 3 names no host, IP, CIDR or *.domain, so it would exclude nothing: "${bad}"`,
          { exact: false },
        )).toBeVisible()
        await page.waitForTimeout(1000)
        expect(puts, 'the form sent the refused entry').toBe(0)
        expect((await row()).roeExcludedHosts).toEqual(STORED)
      })
    }
  })
}
