import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mintToken, signIn } from './auth'

/**
 * Regenerates the wiki screenshots for URLScan's history checks: the URLScan,
 * Origin Discovery and Security Checks settings, and the Red Zone's Secrets and
 * Web Init-Access tables. Not an assertion suite: run it when those surfaces
 * change.
 *
 *   npx playwright test tests/captureUrlscanDocsShots.spec.ts
 *
 * Settings shots use a throwaway project on a .test domain, deleted afterwards.
 * The Red Zone shots need a project the urlscan lab scanned
 * (testing/guinea_pigs/urlscan_lab, run A-p2 by default: URLSCAN_LAB_RUN), whose
 * targets are the lab's reserved .test names: a published screenshot must never
 * carry a real hostname. Shots land in redamon.wiki/images/ under the names the
 * pages link.
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const OUT = join(__dirname, '..', '..', '..', 'redamon.wiki', 'images')
const LAB = join(__dirname, '..', '..', 'guinea_pigs', 'urlscan_lab')
const RUN = process.env.URLSCAN_LAB_RUN || 'A-p2'

function labProject(): string {
  const file = join(LAB, 'generated', 'projects.json')
  if (!existsSync(file)) return ''
  return (JSON.parse(readFileSync(file, 'utf8'))[RUN] || {}).id || ''
}

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  mkdirSync(OUT, { recursive: true })
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: 'acme-staging', targetDomain: 'example.test', originDiscoveryEnabled: true },
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

async function openSettingsTab(page: Page, tab: string, waitFor: string) {
  // Tall enough that a whole section fits in one frame: an element screenshot of
  // a section taller than the viewport comes back clipped.
  await page.setViewportSize({ width: 1400, height: 2400 })
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: tab, exact: true }).first().click()
  await expect(page.getByText(waitFor).first()).toBeVisible({ timeout: 20_000 })
  // The sticky tab bar and the status footer are painted over the element's box.
  await page.addStyleTag({ content: `
    header, footer, [class*="stickyHeader"], [class*="statusBar"],
    [class*="tabsBar"], [class*="toolbar"] { position: static !important; }
    * { animation: none !important; transition: none !important; }
  ` })
}

async function shoot(target: Locator, name: string) {
  await target.scrollIntoViewIfNeeded()
  await target.page().waitForTimeout(300)
  await target.screenshot({ path: join(OUT, name) })
}

test('URLScan.io Enrichment section', async ({ page }) => {
  await openSettingsTab(page, 'Discovery & OSINT', 'URLScan.io Enrichment')
  await expect(page.getByText('Problem Pages from Titles and Certificates').first()).toBeVisible()
  // The key line reads "No API key" until the account's keys are read: wait for
  // the settled answer, whichever it is.
  await page.waitForLoadState('networkidle')
  await page.waitForTimeout(500)
  const section = page.locator('h2[class*="sectionTitle"]', { hasText: 'URLScan.io Enrichment' }).first()
    .locator('xpath=ancestor::div[contains(@class, "formSkin")][1]')
  await shoot(section, 'urlscan-settings-section.png')
})

test('Origin Discovery: the urlscan source', async ({ page }) => {
  await openSettingsTab(page, 'Discovery & OSINT', 'urlscan history and file fingerprint')
  await expect(page.getByText(/urlscan key set\.|No urlscan key/).first()).toBeVisible()
  // The urlscan row alone: the other groups' lines name which provider keys the
  // account holds, which a published shot has no reason to show.
  const row = page.locator('[class*="toggleRow"]').filter({
    has: page.locator('[class*="toggleLabel"]', { hasText: 'urlscan history and file fingerprint' }),
  }).first()
  await shoot(row, 'origin-discovery-urlscan-source.png')
})

test('Security Checks: the Page Content group', async ({ page }) => {
  await openSettingsTab(page, 'Security Checks', 'Page Content')
  const group = page.locator('[class*="subSection"]').filter({
    has: page.locator('[class*="subSectionTitle"]', { hasText: /^Page Content$/ }),
  }).first()
  await shoot(group, 'security-checks-page-content.png')
})

for (const [table, name, waitFor] of [
  ['secrets', 'red-zone-secrets-urlscan.png', 'urlscan history'],
  ['webInitAccess', 'red-zone-web-init-access-open-doors.png', 'jupyter.uslab.test'],
] as const) {
  test(`Red Zone ${table} on the urlscan lab`, async ({ page }) => {
    const lab = labProject()
    test.skip(!lab, `no urlscan lab project for run ${RUN}`)
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.goto(`/graph?project=${lab}&table=${table}`)
    await expect(page.getByText(waitFor).first()).toBeVisible({ timeout: 30_000 })
    // Only the lab's own rows: another suite may have written its synthetic
    // findings into the same project.
    await page.getByPlaceholder(/^Search/).first().fill('uslab.test')
    await page.waitForTimeout(500)
    await page.addStyleTag({ content: '* { animation: none !important; transition: none !important; }' })
    await page.waitForTimeout(800)
    await page.screenshot({ path: join(OUT, name) })
  })
}
