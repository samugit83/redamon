import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * AI Navigator in a real browser against the running stack (plan §12): the launcher after sign-in,
 * dragging it and keeping its place across a reload, resizing the panel by its free edges, the panel's Intro and History, Escape, the
 * model gate on a first send with no model saved, and "Open the AI Agent" opening the AI Agent
 * drawer with nothing of the Navigator over it. None of it needs a model provider.
 *
 * Run: npx playwright test tests/navigator.spec.ts
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

let api: APIRequestContext
let projectId = ''
let previousModel = ''

async function open(page: Page, baseURL: string, path: string) {
  await signIn(page.context(), USER, baseURL)
  await page.context().addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({ version: '2026-03-28-v2', acceptedAt: new Date().toISOString() }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
  await page.goto(path)
}

const launcher = (page: Page) => page.getByTestId('navigator-launcher')
const panel = (page: Page) => page.getByRole('dialog', { name: 'AI Navigator' })

test.describe('AI Navigator', () => {
  test.beforeAll(async ({ playwright, baseURL }) => {
    api = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` } })
    const status = await api.get('/api/navigator/status')
    expect(status.ok(), await status.text()).toBeTruthy()
    expect((await status.json()).enabled).toBe(true)
    const settings = (await (await api.get(`/api/users/${USER}/settings`)).json()) as { featureModels?: Record<string, string> }
    previousModel = settings.featureModels?.navigator ?? ''
    const cleared = await api.put(`/api/users/${USER}/settings`, {
      data: { featureModels: { navigator: '' } }, headers: { 'Content-Type': 'application/json' },
    })
    expect(cleared.ok(), await cleared.text()).toBeTruthy()
    const project = await api.post('/api/projects', {
      data: { name: `Navigator e2e ${Date.now()}`, targetDomain: 'navigator-e2e.example', targetGuardrailEnabled: false, subdomainList: ['www'] },
      headers: { 'Content-Type': 'application/json' },
    })
    expect(project.ok(), await project.text()).toBeTruthy()
    projectId = ((await project.json()) as { id: string }).id
  })

  test.afterAll(async () => {
    if (!api) return
    if (projectId) await api.delete(`/api/projects/${projectId}`)
    await api.put(`/api/users/${USER}/settings`, {
      data: { featureModels: { navigator: previousModel } }, headers: { 'Content-Type': 'application/json' },
    })
    await api.dispose()
  })

  test('the launcher appears after sign-in; dragged, it keeps its place across a reload', async ({ page, baseURL }) => {
    await open(page, baseURL!, `/graph?project=${projectId}`)
    const btn = launcher(page)
    await expect(btn).toBeVisible()
    const before = (await btn.boundingBox())!
    await page.mouse.move(before.x + 24, before.y + 24)
    await page.mouse.down()
    await page.mouse.move(before.x - 176, before.y - 126, { steps: 8 })
    await page.mouse.up()
    await expect(panel(page)).toBeHidden()
    const moved = (await btn.boundingBox())!
    expect(Math.round(before.x - moved.x)).toBeGreaterThan(150)
    await page.reload()
    await expect(launcher(page)).toBeVisible()
    const after = (await launcher(page).boundingBox())!
    expect(Math.abs(after.x - moved.x)).toBeLessThan(3)
    expect(Math.abs(after.y - moved.y)).toBeLessThan(3)
    await launcher(page).focus()
    await page.keyboard.press('Alt+Home')
  })

  test('open and close; the Intro; the History empty state', async ({ page, baseURL }) => {
    await open(page, baseURL!, `/graph?project=${projectId}`)
    await launcher(page).click()
    await expect(panel(page)).toBeVisible()
    await expect(panel(page).getByTestId('navigator-intro')).toContainText('I only read.')
    await expect(panel(page).getByTestId('navigator-intro')).toContainText('I am not the RedAmon AI Agent.')
    await panel(page).getByRole('button', { name: 'History' }).click()
    await expect(panel(page).getByText('No conversations on this project yet.')).toBeVisible()
    await expect(panel(page).getByText(/Conversations are deleted after \d+ days? without activity/)).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(panel(page)).toBeHidden()
  })

  test('with no model saved, the first send opens the model picker', async ({ page, baseURL }) => {
    await open(page, baseURL!, `/graph?project=${projectId}`)
    await launcher(page).click()
    await panel(page).getByLabel('Message AI Navigator').fill('How do I schedule a weekly scan?')
    await panel(page).getByRole('button', { name: 'Send' }).click()
    const gate = page.getByRole('dialog').filter({ hasText: 'AI Navigator' }).filter({ hasNot: page.getByTestId('navigator-intro') })
    await expect(gate.last()).toBeVisible()
    await page.keyboard.press('Escape')
  })

  test('"Open the AI Agent" closes the panel and opens the AI Agent drawer, uncovered', async ({ page, baseURL }) => {
    await open(page, baseURL!, `/graph?project=${projectId}`)
    await launcher(page).click()
    await panel(page).getByRole('button', { name: 'Open the AI Agent →' }).click()
    await expect(panel(page)).toBeHidden()
    await expect(page).toHaveURL(new RegExp(`/graph\\?project=${projectId}$`))
    const drawer = page.locator('[class*="drawerOpen"]').first()
    await expect(drawer).toBeVisible()
    // The drawer registers as an obstacle once its open transition ends (and 450 ms after it
    // opens), and only then does the launcher step aside: wait for it to settle.
    await expect.poll(async () => {
      const d = (await drawer.boundingBox())!
      const l = (await launcher(page).boundingBox())!
      return l.x < d.x + d.width && l.x + l.width > d.x && l.y < d.y + d.height && l.y + l.height > d.y
    }, { timeout: 5_000 }).toBe(false)
  })
})

// No project and no settings change: the panel's size lives in the browser only.
test.describe('AI Navigator panel size', () => {
  // The sizes below are worked out for this window; Desktop Chrome's own is 1280 x 720.
  test.use({ viewport: { width: 1600, height: 1000 } })

  async function dragBy(page: Page, testId: string, dx: number, dy: number) {
    const h = (await page.getByTestId(testId).boundingBox())!
    await page.mouse.move(h.x + h.width / 2, h.y + h.height / 2)
    await page.mouse.down()
    await page.mouse.move(h.x + h.width / 2 + dx, h.y + h.height / 2 + dy, { steps: 10 })
    await page.mouse.up()
  }

  test('the free edges resize it, the size survives a reload, it stops at the window, and resets', async ({ page, baseURL }) => {
    await open(page, baseURL!, '/projects')
    await launcher(page).click()
    const start = (await panel(page).boundingBox())!
    expect(Math.round(start.width)).toBe(380)
    expect(Math.round(start.height)).toBe(560)
    // The launcher sits bottom right, so the panel's left and top edges are the free ones.
    await expect(page.getByTestId('navigator-resize-nw')).toBeAttached()
    await expect(page.getByTestId('navigator-resize-e')).toHaveCount(0)

    await dragBy(page, 'navigator-resize-w', -200, 0)
    await dragBy(page, 'navigator-resize-n', 0, -150)
    const grown = (await panel(page).boundingBox())!
    expect(Math.round(grown.width)).toBe(580)
    expect(Math.round(grown.height)).toBe(710)
    expect(Math.round(grown.x + grown.width)).toBe(Math.round(start.x + start.width))
    expect(Math.round(grown.y + grown.height)).toBe(Math.round(start.y + start.height))

    await page.reload()
    await launcher(page).click()
    const kept = (await panel(page).boundingBox())!
    expect(Math.round(kept.width)).toBe(580)
    expect(Math.round(kept.height)).toBe(710)

    await dragBy(page, 'navigator-resize-nw', -3000, -3000)
    const max = (await panel(page).boundingBox())!
    expect(Math.round(max.x)).toBe(8)
    expect(Math.round(max.y)).toBe(8)
    expect(Math.round(max.x + max.width)).toBe(Math.round(start.x + start.width))

    await panel(page).getByRole('button', { name: 'More' }).click()
    await panel(page).getByRole('menuitem', { name: 'Reset panel size' }).click()
    const reset = (await panel(page).boundingBox())!
    expect(Math.round(reset.width)).toBe(380)
    expect(Math.round(reset.height)).toBe(560)
  })
})
