import { test, expect, type APIRequestContext } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { mintToken, signIn } from './auth'

/**
 * Regenerates the screenshot on the wiki's TLS Certificate Grab page. Not an
 * assertion suite: run it when that section changes so the docs stop drifting
 * from the product.
 *
 *   npx playwright test tests/captureTlsxDocsShots.spec.ts
 *
 * Shots land in redamon.wiki/images/ under the name the page links. The project
 * is a throwaway on a .test domain and is deleted afterwards: a screenshot is
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

test('TLS Certificate Grab settings section', async ({ page }) => {
  // Tall enough that the whole section fits in one frame: an element screenshot
  // of a section taller than the viewport comes back clipped.
  await page.setViewportSize({ width: 1400, height: 1800 })
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i }))
    .toBeVisible({ timeout: 30_000 })

  // The page opens in Workflow view; the docs shot wants the plain form, and
  // tlsx sits under Port Scanning because it consumes the ports that phase found.
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'Port Scanning', exact: true }).first().click()

  const header = page.getByText('TLS Certificate Grab', { exact: false }).first()
  await header.waitFor({ state: 'visible', timeout: 20_000 })
  if (!(await page.getByText('Deeper probes', { exact: false }).first()
                  .isVisible().catch(() => false))) {
    await header.click()
  }
  // Every parameter must be in frame, including the loud sub-probes.
  const deeper = page.getByText('Deeper probes', { exact: false }).first()
  await expect(deeper).toBeVisible()
  await expect(page.getByText('Reverse-PTR SNI', { exact: false }).first()).toBeVisible()

  // The nearest "section" ancestor is the HEADER row, whose hashed class also
  // contains "section" -- taking it crops the shot to the title bar.
  const section = header.locator(
    'xpath=ancestor::div[contains(@class,"__section") and not(contains(@class,"sectionHeader"))][1]')

  // The sticky tab bar and the status footer are painted OVER the element's
  // box, so they crop the top and bottom of an element screenshot. Dropping
  // them out of fixed positioning takes them off the section.
  await page.addStyleTag({ content: `
    header, footer, [class*="stickyHeader"], [class*="statusBar"],
    [class*="tabsBar"], [class*="toolbar"] { position: static !important; }
    * { animation: none !important; transition: none !important; }
  ` })
  await section.scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await section.screenshot({ path: join(OUT, 'tlsx-settings.png') })
})
