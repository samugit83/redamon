import { test, expect, type APIRequestContext } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { mintToken, signIn } from './auth'

/**
 * Regenerates the two screenshots on the wiki's Authenticated Session Recording
 * page. Not an assertion suite: run it when that UI changes so the docs stop
 * drifting from the product.
 *
 *   npx playwright test tests/captureAuthDocsShots.spec.ts
 *
 * Shots land in redamon.wiki/images/ under the names the page already links.
 * The target domain is a .test placeholder on purpose - a screenshot is
 * published, so it must never carry a real hostname.
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

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

test('capture: Authenticated Session section + Record-login modal', async ({ page }) => {
  // Tall enough that the whole section fits on screen. An element screenshot of
  // something taller than the viewport comes back clipped, with the sticky
  // status footer painted over its last rows.
  await page.setViewportSize({ width: 1500, height: 1400 })
  await page.goto(`/projects/${projectId}/settings`)
  await page.getByTitle('Tab view').click()
  await page.getByRole('button', { name: 'Target & Modules' }).first().click()

  const heading = page.getByText('Authenticated Session')
  await expect(heading).toBeVisible()
  await heading.click() // expand

  await expect(page.getByRole('button', { name: /Record login/i })).toBeVisible()
  await expect(page.getByRole('switch', { name: 'Apply to recon' })).toBeVisible()

  // Frame the section itself rather than the whole page: a full-page shot of a
  // settings form reduces the part being documented to unreadable pixels.
  // Climb from the heading to the section container - a `filter({hasText})`
  // match settles on the innermost div and silently ships a crop of one
  // sub-block, which is how the first run produced a shot of just the toggles.
  // Climb to the nearest ancestor that holds BOTH the heading and the record
  // button. Matching the container by class fails: the collapsed-header div is
  // `sectionHeader`, which also contains the substring "section".
  const section = page.getByRole('heading', { name: 'Authenticated Session' })
    .locator('xpath=ancestor::div[.//button[contains(., "Record login")]][1]')

  // Assert the frame, so a markup change narrows the shot loudly instead of
  // quietly publishing a crop.
  for (const mustShow of ['Authenticated Session', 'Apply this identity to', 'Manual entry']) {
    await expect(section.getByText(mustShow, { exact: false }).first()).toBeVisible()
  }
  await expect(section.getByRole('button', { name: /Record login/i })).toBeVisible()

  await section.screenshot({ path: join(OUT, 'auth-session-profile-section.png') })

  await page.getByRole('button', { name: /Record login/i }).click()
  await expect(page.getByRole('button', { name: 'Start recording' })).toBeVisible()

  const modal = page.locator('[role="dialog"]').first()
  await expect(modal).toBeVisible()
  await modal.screenshot({ path: join(OUT, 'auth-session-record-modal.png') })
})
