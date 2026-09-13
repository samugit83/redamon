import { test, expect, type APIRequestContext } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * The two independent consumer switches ("Apply this identity to: Recon / AI
 * agent") must render default-ON and persist across a reload — driven through
 * the real UI + real save route. Also asserts the /traffic "Record login" button
 * was removed (recording now lives only in the auth section).
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: `e2e-auth-gates-${Date.now()}`, targetDomain: 'authpig.test' },
  })
  expect(res.ok()).toBeTruthy()
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

async function openAuthSection(page: import('@playwright/test').Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await page.getByText('Target Input', { exact: false }).first().click()
  await page.getByText('Authenticated Session').click() // expand
}

test('both consumer switches render default-ON and persist a change', async ({ page }) => {
  await openAuthSection(page)

  const recon = page.getByRole('switch', { name: 'Apply to recon' })
  const agent = page.getByRole('switch', { name: 'Apply to agent' })
  await expect(recon).toHaveAttribute('aria-checked', 'true')
  await expect(agent).toHaveAttribute('aria-checked', 'true')

  // Turn the agent switch off; wait for the immediate-apply PUT to land.
  const saved = page.waitForResponse(r =>
    r.url().includes(`/projects/${projectId}/auth-profile`) && r.request().method() === 'PUT')
  await agent.click()
  await saved
  await expect(agent).toHaveAttribute('aria-checked', 'false')

  // Persisted server-side (independent of the UI): the metadata reflects it.
  const meta = (await (await api.get(`/api/projects/${projectId}/auth-profile`)).json()).authProfile
  expect(meta.agentEnabled).toBe(false)
  expect(meta.reconEnabled).toBe(true)

  // And it survives a full reload.
  await openAuthSection(page)
  await expect(page.getByRole('switch', { name: 'Apply to agent' })).toHaveAttribute('aria-checked', 'false')
  await expect(page.getByRole('switch', { name: 'Apply to recon' })).toHaveAttribute('aria-checked', 'true')
})

test('the /traffic page no longer shows a Record login button', async ({ page }) => {
  await page.goto('/traffic')
  await page.waitForLoadState('networkidle')
  await expect(page.getByRole('button', { name: /Record login/i })).toHaveCount(0)
})
