import { test, expect, type APIRequestContext } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { mintToken, signIn } from './auth'

/**
 * Regenerates the Jev screenshots on the wiki (the AI in Pipeline panel with its
 * complete hook list, the Jev providers card, and the Serialized Object Scan card
 * with its Jev ranking control). Not an assertion suite: run it when one of them
 * changes so the docs stop drifting from the product.
 *
 *   npx playwright test tests/captureJevDocsShots.spec.ts
 *
 * Shots land in redamon.wiki/images/ under the names the pages link. The project
 * is a throwaway on a .test domain and is deleted afterwards: a screenshot is
 * published, so it must never carry a real hostname. The account's Jev providers are
 * hidden from the BROWSER only (the providers response is filtered in flight), so
 * the shots show the "no provider yet" state without touching the stored ones or
 * printing a masked key.
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const OUT = join(__dirname, '..', '..', '..', 'redamon.wiki', 'images')

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  mkdirSync(OUT, { recursive: true })
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: 'acme-staging', targetDomain: 'example.test' },
  })
  expect(res.ok(), `create project: ${res.status()}`).toBeTruthy()
  projectId = (await res.json()).id
})

test.afterAll(async () => {
  if (projectId) await api.delete(`/api/projects/${projectId}`)
  await api.dispose()
})

test.beforeEach(async ({ page, context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
  // Show the account as having no Jev provider, of either type (llmProviderKinds.ts).
  await page.route('**/api/users/*/llm-providers', async route => {
    if (route.request().method() !== 'GET') return route.continue()
    const res = await route.fetch()
    const rows = await res.json()
    const body = Array.isArray(rows) ? rows.filter((r: { providerType?: string }) => !['jev', 'jev_openrouter'].includes(r?.providerType ?? '')) : rows
    await route.fulfill({ response: res, json: body })
  })
})

const NO_MOTION = `
  header, footer, [class*="stickyHeader"], [class*="statusBar"],
  [class*="tabsBar"], [class*="toolbar"] { position: static !important; }
  * { animation: none !important; transition: none !important; }
`

test('AI in Pipeline panel', async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1700 })
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'Target & Modules', exact: true }).first().click()

  const label = page.getByText('Enable AI in Pipeline', { exact: true }).first()
  await label.scrollIntoViewIfNeeded()
  const list = page.getByTestId('ai-hook-list')
  if (!(await list.isVisible().catch(() => false))) {
    await label.locator('xpath=ancestor::*[.//*[@role="switch"]][1]').getByRole('switch').first().click()
  }
  await expect(list).toBeVisible({ timeout: 15_000 })
  await expect(page.getByTestId('ai-hook-httpxJevPageType')).toBeAttached()
  await expect(page.getByTestId('ai-hook-serializedScanJevRank')).toBeAttached()
  // The model picker fills from a fetch that is slow on a freshly started webapp.
  await expect(page.getByText('Loading models...')).toHaveCount(0, { timeout: 30_000 })

  await page.addStyleTag({ content: NO_MOTION })
  // The hook list scrolls inside the panel; lift its height cap so the shot
  // shows the complete list, every LLM hook and every Jev-only hook.
  await list.evaluate(el => {
    (el as HTMLElement).style.maxHeight = 'none'
    ;(el as HTMLElement).style.overflow = 'visible'
  })
  const panel = list.locator('xpath=ancestor::div[.//*[normalize-space(text())="Enable AI in Pipeline"]][1]')
  await panel.scrollIntoViewIfNeeded()
  await page.waitForTimeout(400)
  await panel.screenshot({ path: join(OUT, 'ai-in-pipeline-target-tab.png') })
})

test('Jev providers card', async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 1200 })
  await page.goto('/settings')
  const section = page.locator('section[aria-labelledby="jev-provider-title"]')
  await expect(section).toBeVisible({ timeout: 30_000 })
  await section.getByRole('button', { name: /Add Jev provider/i }).click()
  // LlmProviderForm.tsx names the button "Check key (free)" for a Jev provider.
  await expect(section.getByRole('button', { name: 'Check key (free)' })).toBeVisible()
  await page.addStyleTag({ content: NO_MOTION })
  await section.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await section.screenshot({ path: join(OUT, 'typesafe-jev-settings-section.png') })
})

test('Serialized Object Scan card', async ({ page }) => {
  // Scan ON, the Insecure Deserialization skill OFF (the project default), so the
  // "half a cycle" alert renders. Client-side state only: nothing is saved.
  await page.setViewportSize({ width: 1400, height: 1400 })
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'JS Recon', exact: true }).first().click()

  const toggle = page.getByRole('switch', { name: 'Enable Serialized Object Scan' })
  await expect(toggle).toBeVisible({ timeout: 15_000 })
  if ((await toggle.getAttribute('aria-checked')) !== 'true') await toggle.click()
  // The whole card: the nearest ancestor holding both its heading and its Jev
  // control (the header alone also holds the heading).
  const card = toggle.locator(
    'xpath=ancestor::div[.//h2[contains(normalize-space(.), "Serialized Object Scan")] and .//*[@role="group"]][1]')
  await expect(card.getByRole('alert')).toBeVisible()
  await expect(card.getByRole('group', { name: 'Jev hook' })).toBeVisible()

  await page.addStyleTag({ content: NO_MOTION })
  await card.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await card.screenshot({ path: join(OUT, 'serialized-object-scan-settings.png') })
})
