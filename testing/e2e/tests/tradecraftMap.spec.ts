import { test, expect, type Page } from '@playwright/test'
import { cleanupTradecraft, loginTradecraft, seedTradecraft, type TradecraftSeed } from './tradecraftFixtures'

/**
 * The Map view and curation (T6.12, §6.10, §3.4; R-045, R-165 - R-167, AC-14, AC-39, D-29): search
 * and the count, a stored page viewed as plain text, Block all matching the search with its count,
 * the Blocked filter and Unblock, restoring a page the focus dropped, the read-only Map view of the
 * project accordion's Pages, and that no answer the page receives carries the fake site login.
 * The Map account's synthetic fixtures (webapp/scripts/e2e-tradecraft-seed.mjs); no agent, no site.
 * Run: cd testing/e2e && npx playwright test tradecraftMap
 */

test.describe.configure({ mode: 'serial' })
test.setTimeout(120_000)

type MapSeed = TradecraftSeed & Record<'TC_MAP_USER_ID' | 'TC_MAP_EMAIL' | 'TC_MAP_PASSWORD' | 'TC_MAP_PROJECT_ID' | 'TC_MAP_LIBRARY_ID' | 'TC_MAP_KB_ID', string>

const FAKE_SECRET = 'fake-session'
let seed: MapSeed
const bodies: { url: string; text: string }[] = []

test.beforeAll(() => {
  seed = seedTradecraft() as MapSeed
  if (!seed.TC_MAP_LIBRARY_ID) throw new Error('the Tradecraft seed printed no Map view fixtures')
})
test.afterAll(() => {
  cleanupTradecraft()
  // Every answer the page received over the whole spec (R-152, R-157): the login is never in one.
  expect(bodies.length).toBeGreaterThan(0)
  const leaked = bodies.filter(b => b.text.includes(FAKE_SECRET)).map(b => b.url)
  expect(leaked).toEqual([])
})
test.beforeEach(async ({ page }) => {
  page.on('response', async res => {
    if (!res.url().includes('/api/')) return
    try { bodies.push({ url: res.url(), text: await res.text() }) } catch { /* a body already gone, e.g. a redirect */ }
  })
  await loginTradecraft(page, { ...seed, TC_EMAIL: seed.TC_MAP_EMAIL, TC_PASSWORD: seed.TC_MAP_PASSWORD })
})

const MAP = () => `/api/users/${seed.TC_MAP_USER_ID}/tradecraft-resources/${seed.TC_MAP_LIBRARY_ID}/map`
const mapView = (page: Page) => page.getByTestId('tc-map-view')
const entry = (page: Page, path: string) => mapView(page).locator(`[data-entry="https://library.tc-e2e.test/${path}"]`)

async function openMap(page: Page, resourceName = 'TC Map Library') {
  await page.goto('/settings?tab=tradecraft')
  await page.getByRole('button', { name: `Map of ${resourceName}` }).click({ timeout: 30_000 })
  await expect(mapView(page).getByTestId('tc-map-count')).toBeVisible()
}

async function search(page: Page, text: string) {
  await mapView(page).getByRole('textbox', { name: 'Search the map' }).fill(text)
  await mapView(page).getByRole('button', { name: 'Search' }).click()
}

test('search and the count; a stored page viewed as plain text', async ({ page }) => {
  await openMap(page)
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText('4 pages · from sitemap, crawl')
  await expect(entry(page, 'sqli/')).toContainText('Union and blind payloads.')
  await search(page, 'scripting')
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText(/^1 page match/)
  await entry(page, 'xss/').getByRole('button', { name: 'View' }).click()
  const pre = mapView(page).getByTestId('tc-page-text')
  await expect(pre).toContainText('<script>alert(document.domain)</script> is shown here as text, never run.')
  // Text, never markup: the page's HTML is not an element of the view.
  expect(await pre.evaluate(el => el.tagName)).toBe('PRE')
  expect(await pre.locator('script').count()).toBe(0)
  await expect(entry(page, 'xss/').getByRole('link', { name: /Open on the site/ })).toHaveAttribute('target', '_blank')
})

test('Block all matching the search: the confirmation shows the count; the Blocked filter and Unblock', async ({ page }) => {
  await openMap(page)
  await search(page, '/tag/')
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText(/^2 pages match/)
  await mapView(page).getByRole('button', { name: 'Block all matching the search' }).click()
  const confirm = mapView(page).getByRole('alertdialog', { name: 'Confirm the block' })
  await expect(confirm).toContainText('Block 2 pages matching "/tag/"?')
  await confirm.getByRole('button', { name: 'Block' }).click()
  await expect(mapView(page).getByRole('status')).toHaveText('Blocked 2 pages')
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText(/^0 pages match/)
  // The stored text went at once (§6.10): the page view says it is blocked.
  const blocked = await (await page.request.get(`${MAP()}?status=blocked`)).json()
  expect(blocked.entries.map((e: { url: string }) => e.url).sort()).toEqual(['https://library.tc-e2e.test/tag/events', 'https://library.tc-e2e.test/tag/news'])
  const view = await (await page.request.get(`/api/users/${seed.TC_MAP_USER_ID}/tradecraft-resources/${seed.TC_MAP_LIBRARY_ID}/pages/${blocked.entries[0].pageId}`)).json()
  expect(view).toMatchObject({ blocked: true, stored: false, text: '' })

  await search(page, '')
  await mapView(page).getByRole('button', { name: 'Blocked' }).click()
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText(/^2 pages( ·|$)/)
  await entry(page, 'tag/news').getByRole('button', { name: 'Unblock' }).click()
  await expect(mapView(page).getByRole('status')).toHaveText('Unblocked 1 page: back in the map at the next refresh')
  await expect(mapView(page).getByTestId('tc-map-count')).toHaveText(/^1 page( ·|$)/)
  await expect.poll(async () => (await (await page.request.get(`${MAP()}?status=blocked`)).json()).total).toBe(1)
})

test('restore a dropped page: listed with its reason; restored, it is kept and pinned (AC-14)', async ({ page }) => {
  await openMap(page)
  await mapView(page).getByRole('button', { name: 'Dropped' }).click()
  await expect(entry(page, 'theory/')).toContainText('dropped: theory without payloads')
  await entry(page, 'theory/').getByRole('button', { name: 'Restore' }).click()
  await expect(mapView(page).getByRole('status')).toHaveText('Restored and pinned: Injection theory')
  await mapView(page).getByRole('button', { name: 'In the map' }).click()
  await expect(entry(page, 'theory/')).toContainText('pinned')
  const kept = await (await page.request.get(`${MAP()}?query=theory`)).json()
  expect(kept.entries[0]).toMatchObject({ status: 'kept', pinned: true })
})

test('the project accordion\'s Pages: the Map view read-only', async ({ page }) => {
  await page.goto(`/projects/${seed.TC_MAP_PROJECT_ID}/settings`)
  await page.getByRole('button', { name: 'Agent Skills & Tradecraft' }).click({ timeout: 30_000 })
  const accordion = page.getByTestId('tradecraft-accordion')
  await accordion.getByRole('button', { name: 'Details of TC Map Library' }).click()
  await accordion.getByRole('button', { name: 'Pages' }).click()
  await expect(mapView(page).getByText(/^Read-only:/)).toBeVisible()
  await expect(entry(page, 'sqli/')).toBeVisible()
  for (const name of [/^Block/, /^Pin$/, /^Rename$/, /^Restore$/, /^Unblock/, /^Dropped$/, /^Blocked$/]) {
    await expect(mapView(page).getByRole('button', { name })).toHaveCount(0)
  }
  await entry(page, 'sqli/').getByRole('button', { name: 'View' }).click()
  await expect(mapView(page).getByTestId('tc-page-text')).toContainText("' UNION SELECT username, password FROM users --")
})

test('the resource with a login: its card, map, page and form show the login as "set" only', async ({ page }) => {
  await openMap(page, 'TC Map KB')
  await mapView(page).locator('[data-entry="https://kb.tc-e2e.test/runbook"]').getByRole('button', { name: 'View' }).click()
  await expect(mapView(page).getByTestId('tc-page-text')).toBeVisible()
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Edit TC Map KB' }).click()
  await page.getByRole('button', { name: /^Access/ }).click()
  await expect(page.getByLabel('Cookies')).toHaveAttribute('placeholder', 'set: type a new value to replace it')
  await expect(page.getByLabel('Cookies')).toHaveValue('')
  const list = await page.request.get(`/api/users/${seed.TC_MAP_USER_ID}/tradecraft-resources`)
  expect(await list.text()).not.toContain(FAKE_SECRET)
})
