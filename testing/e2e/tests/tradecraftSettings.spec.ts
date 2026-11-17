import { test, expect } from '@playwright/test'
import { cleanupTradecraft, loginTradecraft, seedTradecraft, type TradecraftSeed } from './tradecraftFixtures'

/**
 * Tradecraft 2.0 in Global Settings (T4.10, D-29): the preview switch, Configure ingestion (a value
 * saved and kept, a value out of range refused in the dialog and by the server), a card's stale
 * badge and ingestion report, and the delete confirmation. Synthetic account and resources only
 * (webapp/scripts/e2e-tradecraft-seed.mjs); no agent, no site.
 * Run: cd testing/e2e && npx playwright test tradecraftSettings
 */

test.describe.configure({ mode: 'serial' })

let seed: TradecraftSeed

test.beforeAll(() => { seed = seedTradecraft() })
test.afterAll(() => { cleanupTradecraft() })
test.beforeEach(async ({ page }) => { await loginTradecraft(page, seed) })

const SETTINGS_URL = () => `/api/users/${seed.TC_USER_ID}/tradecraft-settings`
const card = (page: import('@playwright/test').Page, id: string) => page.getByTestId(`tc-card-${id}`)

async function openTab(page: import('@playwright/test').Page) {
  await page.goto('/settings?tab=tradecraft')
  await expect(card(page, seed.TC_WIKI_ID)).toBeVisible({ timeout: 30_000 })
}

async function openDialog(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: /Configure ingestion/ }).click()
  const dialog = page.getByRole('dialog', { name: 'Configure ingestion' })
  await expect(dialog.getByText('Applies to all your resources the next time each one is added or refreshed.')).toBeVisible()
  await dialog.getByRole('navigation', { name: 'Ingestion stages' }).getByRole('button', { name: /^Website crawl/ }).click()
  return dialog
}

test('the 2.0 library for every account: no preview switch, and the three resources show as 2.0 cards', async ({ page }) => {
  await openTab(page)
  for (const id of [seed.TC_WIKI_ID, seed.TC_BLOG_ID, seed.TC_DISABLED_ID]) await expect(card(page, id)).toBeVisible()
  // The switch left at the cut-over (T9.3): the tab is 2.0 whatever the account's old row says.
  await expect(page.getByRole('switch', { name: /Tradecraft 2\.0/ })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Configure ingestion/ })).toBeVisible()
})

test('Configure ingestion: a value out of range is refused in the dialog and by the server', async ({ page }) => {
  await openTab(page)
  const dialog = await openDialog(page)
  await dialog.getByLabel('Max pages visited').fill('9000')
  await expect(dialog.getByText('Must be an integer from 1 to 500')).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  const res = await page.request.put(SETTINGS_URL(), { data: { ingestion: { 'crawl.maxPages': 9000 } } })
  expect(res.status()).toBe(400)
  const body = await res.json()
  expect(body.code).toBe('invalid_settings')
  expect(body.errors[0]).toMatchObject({ key: 'crawl.maxPages', code: 'bad_value' })
})

test('Configure ingestion: a saved value is kept, marked changed, and read back', async ({ page }) => {
  await openTab(page)
  const dialog = await openDialog(page)
  await dialog.getByLabel('Max pages visited').fill('150')
  await dialog.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText(/Saved: each resource uses the new settings/)).toBeVisible()
  const view = await (await page.request.get(SETTINGS_URL())).json()
  expect(view.ingestion.values['crawl.maxPages']).toBe(150)
  expect(view.ingestion.changed).toContain('crawl.maxPages')
  const again = await openDialog(page)
  await expect(again.getByLabel('Max pages visited')).toHaveValue('150')
  await expect(again.locator('[data-setting="crawl.maxPages"]').getByText('● changed')).toBeVisible()
  await again.getByRole('button', { name: 'Reset Website crawl to defaults' }).click()
  await again.getByRole('button', { name: 'Save', exact: true }).click()
  await expect.poll(async () => (await (await page.request.get(SETTINGS_URL())).json()).ingestion.changed).toEqual([])
})

test("the card: the stale badge and the ingestion report", async ({ page }) => {
  await openTab(page)
  const wiki = card(page, seed.TC_WIKI_ID)
  await expect(wiki.getByText('Ingested with older settings')).toBeVisible()
  await expect(wiki.getByTestId('tc-report')).toHaveText('40 visited, 31 kept, stopped: frontier_empty')
  await expect(wiki.getByText('Stored', { exact: true })).toBeVisible()
  // Ingested by 2.0 with no settings hash: current, no badge.
  await expect(card(page, seed.TC_BLOG_ID).getByText('Ingested with older settings')).toHaveCount(0)
})

test('the delete confirmation names what goes; Cancel keeps the resource, Delete removes it', async ({ page }) => {
  await openTab(page)
  await page.getByRole('button', { name: 'Delete TC E2E Wiki' }).click()
  const confirmList = page.getByRole('list', { name: 'What is deleted' })
  await expect(confirmList).toContainText('its map and the 3 stored pages')
  await expect(confirmList).toContainText('the choices every project made for it')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(card(page, seed.TC_WIKI_ID)).toBeVisible()

  await page.getByRole('button', { name: 'Delete TC E2E Disabled' }).click()
  await expect(page.getByRole('list', { name: 'What is deleted' })).toBeVisible()
  await page.getByRole('button', { name: /^(Delete|Confirm)$/ }).last().click()
  await expect(card(page, seed.TC_DISABLED_ID)).toHaveCount(0)
  const list = await (await page.request.get(`/api/users/${seed.TC_USER_ID}/tradecraft-resources`)).json()
  expect(list.map((r: { id: string }) => r.id)).not.toContain(seed.TC_DISABLED_ID)
})
