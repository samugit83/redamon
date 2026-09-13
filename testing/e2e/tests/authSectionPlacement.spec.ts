import { test, expect, type APIRequestContext } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * The Authenticated Session section must be reachable in BOTH project-form views:
 * the tabbed view (Target tab) and the workflow/diagram view (Target Input node ->
 * "Target & Modules" modal). And its "Record login" must open the recording modal
 * IN PLACE, not navigate away to /traffic.
 *
 * Requires the stack up and a rebuilt webapp image.
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: `e2e-auth-placement-${Date.now()}`, targetDomain: 'authpig.test' },
  })
  expect(res.ok(), `create project: ${res.status()}`).toBeTruthy()
  projectId = (await res.json()).id
})

test.afterAll(async () => {
  if (projectId) await api.delete(`/api/projects/${projectId}`)
  await api.dispose()
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

test('Authenticated Session + Record login appear in the WORKFLOW (diagram) view', async ({ page }) => {
  await page.goto(`/projects/${projectId}/settings`)
  // The settings form defaults to the workflow view. Open the Target Input node.
  await page.getByText('Target Input', { exact: false }).first().click()

  // The "Target & Modules" modal now carries the Authenticated Session section.
  await expect(page.getByText('Authenticated Session')).toBeVisible()
  await page.getByText('Authenticated Session').click() // expand
  const record = page.getByRole('button', { name: /Record login/i })
  await expect(record).toBeVisible()

  // "Record login" opens the recording modal IN PLACE (no navigation to /traffic).
  await record.click()
  await expect(page.getByRole('button', { name: 'Start recording' })).toBeVisible()
  expect(page.url()).toContain(`/projects/${projectId}/settings`)
})

test('Authenticated Session appears in the TABS view (Target tab)', async ({ page }) => {
  await page.goto(`/projects/${projectId}/settings`)
  // Switch to the tabbed view (icon button, title="Tab view"), then the Target
  // tab (labelled "Target & Modules"; tabs are hidden until this view is active).
  await page.getByTitle('Tab view').click()
  await page.getByRole('button', { name: 'Target & Modules' }).first().click()
  await expect(page.getByText('Authenticated Session')).toBeVisible()
  await page.getByText('Authenticated Session').click()
  await expect(page.getByRole('button', { name: /Record login/i })).toBeVisible()
})
