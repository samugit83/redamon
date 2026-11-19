import { test, expect, type Page } from '@playwright/test'
import { cleanupTradecraft, loginTradecraft, openChatDrawer, seedTradecraft, type TradecraftSeed } from './tradecraftFixtures'

/**
 * Tradecraft 2.0 in a project (T4.10, D-29): the project's Agent Skills & Tradecraft tab and its
 * accordion (turn one off, save, reopen), the chat drawer's window (a switch saved there shows in
 * the form, AC-30), the stale-save refusal when the drawer changed the project while the form was
 * open (AC-27), and the counter badge's numbers and their update (AC-29, AC-30). Synthetic account
 * and resources only (webapp/scripts/e2e-tradecraft-seed.mjs); no agent run, no site.
 * Run: cd testing/e2e && npx playwright test tradecraftProjects
 */

test.describe.configure({ mode: 'serial' })
test.setTimeout(120_000)

let seed: TradecraftSeed

test.beforeAll(() => { seed = seedTradecraft() })
test.afterAll(() => { cleanupTradecraft() })
test.beforeEach(async ({ page }) => {
  await loginTradecraft(page, seed)
  // Every resource on in the project before each test.
  const res = await page.request.put(`/api/projects/${seed.TC_PROJECT_ID}`, { data: { tradecraftOff: [] } })
  expect(res.ok(), await res.text()).toBeTruthy()
})

const PROJECT = () => `/api/projects/${seed.TC_PROJECT_ID}`
const offIds = async (page: Page): Promise<string[]> => (await (await page.request.get(PROJECT())).json()).tradecraftOff
const accordion = (page: Page) => page.getByTestId('tradecraft-accordion')

async function openProjectTab(page: Page) {
  await page.goto(`/projects/${seed.TC_PROJECT_ID}/settings`)
  await page.getByRole('button', { name: 'Agent Skills & Tradecraft' }).click({ timeout: 30_000 })
  await expect(accordion(page)).toBeVisible()
}

async function openDrawerWindow(page: Page) {
  await openChatDrawer(page, seed.TC_PROJECT_ID)
  await page.getByTitle('Agent settings').click()
  await page.getByRole('button', { name: 'Agent Skills & Tradecraft' }).click()
  await expect(page.getByRole('heading', { name: 'Agent Skills & Tradecraft' })).toBeVisible()
  await expect(accordion(page)).toBeVisible()
}

test('the accordion: turn one off, save, reopen (R-041 - R-043, R-064)', async ({ page }) => {
  await openProjectTab(page)
  await expect(page.getByTestId('tradecraft-active-count')).toHaveText('2 of 3 active in this project')
  await expect(page.getByRole('switch', { name: 'TC E2E Disabled in this project' })).toBeDisabled()
  await page.getByRole('switch', { name: 'TC E2E Blog in this project' }).click()
  await expect(page.getByTestId('tradecraft-active-count')).toHaveText('1 of 3 active in this project')
  await page.getByRole('button', { name: /Update Settings/ }).click()
  await expect.poll(() => offIds(page)).toEqual([seed.TC_BLOG_ID])
  await openProjectTab(page)
  await expect(page.getByRole('switch', { name: 'TC E2E Blog in this project' })).toHaveAttribute('aria-checked', 'false')
  await expect(page.getByRole('switch', { name: 'TC E2E Wiki in this project' })).toHaveAttribute('aria-checked', 'true')
})

test('drawer_switch: a switch saved in the drawer window shows in the project form (AC-30)', async ({ page }) => {
  await openDrawerWindow(page)
  const saved = page.waitForResponse(r => r.url().endsWith(PROJECT()) && r.request().method() === 'PUT' && r.ok())
  await page.getByRole('switch', { name: 'TC E2E Wiki in this project' }).click()
  await saved
  await expect.poll(() => offIds(page)).toEqual([seed.TC_WIKI_ID])
  // Its links open Global Settings in a new tab, so the chat stays open.
  await expect(accordion(page).getByRole('link', { name: 'Global Settings > Tradecraft' })).toHaveAttribute('target', '_blank')
  await openProjectTab(page)
  await expect(page.getByRole('switch', { name: 'TC E2E Wiki in this project' })).toHaveAttribute('aria-checked', 'false')
})

test('the counter: the numbers the agent will use, and their update when the drawer saves (AC-29, AC-30)', async ({ page }) => {
  await openChatDrawer(page, seed.TC_PROJECT_ID)
  const view = await (await page.request.get(`${PROJECT()}/tradecraft`)).json()
  const { builtIn, user, tradecraft } = view.counts
  const badge = page.getByRole('button', { name: /^Active in this project/ })
  await expect(badge).toHaveAccessibleName(
    `Active in this project: ${builtIn.active} built-in skills, ${user.active} user skills, ${tradecraft.active} tradecraft resources`)
  expect(tradecraft.active).toBe(2)
  await badge.click()
  await expect(page.getByRole('heading', { name: 'Agent Skills & Tradecraft' })).toBeVisible()
  await page.getByRole('switch', { name: 'TC E2E Blog in this project' }).click()
  await expect(badge).toHaveAccessibleName(/, 1 tradecraft resources$/, { timeout: 15_000 })
})

test('stale_save: the form is refused when the drawer changed the project meanwhile (AC-27)', async ({ page, browser }) => {
  await openProjectTab(page)
  // The drawer, in another window, saves first.
  const drawer = await browser.newPage()
  await loginTradecraft(drawer, seed)
  await openDrawerWindow(drawer)
  const saved = drawer.waitForResponse(r => r.url().endsWith(PROJECT()) && r.request().method() === 'PUT' && r.ok())
  await drawer.getByRole('switch', { name: 'TC E2E Wiki in this project' }).click()
  await saved
  await drawer.close()
  // The form read the project before that save: its own save is refused, and changes nothing.
  await page.getByRole('switch', { name: 'TC E2E Blog in this project' }).click()
  await page.getByRole('button', { name: /Update Settings/ }).click()
  await expect(page.getByText(/changed since you opened it|Someone else changed this project/)).toBeVisible({ timeout: 15_000 })
  expect(await offIds(page)).toEqual([seed.TC_WIKI_ID])
})
