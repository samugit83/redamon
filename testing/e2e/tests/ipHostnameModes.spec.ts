import { test, expect, type Page, type TestInfo } from '@playwright/test'
import { loginThroughUi } from './uiLogin'

/**
 * Hostnames on target IPs, in a real browser (04_ui_spec.md §7 Playwright, §8).
 *
 * - each mode's info modal opens from its card's info button without changing
 *   the mode, closes on Escape with focus back on the button (one screenshot per
 *   modal, attached to the run for the PR);
 * - the radio group moves with the arrow keys;
 * - Record + scan all cannot be saved until it is confirmed (the Save button is
 *   disabled with the reason under it); nothing is ever saved by this spec;
 * - every state of §8, at 1280, 768 and 390 px and inside the workflow node
 *   modal. The preview's states are served by the test (page.route on the
 *   preview route), so they render whatever the project's graph holds;
 * - with REDAMON_IP_LAB_PROJECT and REDAMON_IP_LAB_FOUND set (the hostname lab
 *   project and the names its last run recorded, from the recon JSON
 *   `ip_hostnames.summary.found`), the live preview's "of N" equals the lab's count.
 *
 * Needs the stack with a webapp image that contains the hostname-mode UI, and an
 * IP-mode project of the UI login user (REDAMON_IP_PROJECT). Signs in with the
 * repo .env UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD. Run:
 *   REDAMON_IP_PROJECT=<id> npx playwright test ipHostnameModes
 */

const PROJECT = process.env.REDAMON_IP_PROJECT || ''
const LAB_PROJECT = process.env.REDAMON_IP_LAB_PROJECT || ''
const LAB_FOUND = process.env.REDAMON_IP_LAB_FOUND || ''

const MODES = [
  { value: 'ip_only', label: 'IP only' },
  { value: 'record_only', label: 'Record hostnames' },
  { value: 'record_filter', label: 'Record + scan matching' },
  { value: 'scan_all', label: 'Record + scan all' },
] as const

const WIDTHS = [1280, 768, 390] as const

test.beforeEach(async ({ page, context }) => {
  test.skip(!PROJECT, 'REDAMON_IP_PROJECT (an IP-mode project of the UI login user) is not set')
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
  // Leaving the form with unsaved edits asks first; this spec never saves.
  page.on('dialog', d => void d.accept())
  await loginThroughUi(page)
})

async function shot(page: Page, info: TestInfo, name: string) {
  const path = info.outputPath(`${name}.png`)
  await page.screenshot({ path, fullPage: false })
  await info.attach(name, { path, contentType: 'image/png' })
}

/** The project settings on the Target tab, in the tab view. */
async function openTargetForm(page: Page, width = 1280) {
  await page.setViewportSize({ width, height: 900 })
  await page.goto(`/projects/${PROJECT}/settings`)
  await page.getByTitle('Tab view').click()
  const group = page.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
  await expect(group).toBeVisible()
  await group.scrollIntoViewIfNeeded()
  return group
}

const checkedValue = (page: Page) =>
  page.getByRole('radiogroup', { name: 'Hostnames on target IPs' }).locator('input[type="radio"]:checked')
    .getAttribute('value')

/** Answer the preview route with a body, or a status, for the next reads. */
async function servePreview(page: Page, answer: { status?: number; body?: unknown; hang?: boolean }) {
  await page.unroute('**/api/projects/*/ip-hostnames*')
  await page.route('**/api/projects/*/ip-hostnames*', async route => {
    if (answer.hang) return // never answered: the loading state stays on screen
    await route.fulfill({
      status: answer.status ?? 200,
      contentType: 'application/json',
      body: JSON.stringify(answer.body ?? { error: 'Failed', code: 'ServiceUnavailable' }),
    })
  })
}

const name = (n: string, result: string, reason = result) => ({
  name: n, ips: ['203.0.113.10'], sources: ['tlsx_san', 'ptr'], reason, last_seen: null, kind: 'recorded', result,
})

function previewBody(over: Record<string, unknown> = {}, found = 4) {
  const rows = [
    name('app.example.com', 'scanned', 'record_only'),
    name('blog.other.test', 'filter_no_match', 'record_only'),
    name('old.example.com', 'filter_excluded', 'record_only'),
    name('split.example.com', 'resolves_outside_targets'),
  ]
  return {
    mode: 'record_filter', evaluatedMode: 'record_filter', legacy: false, lastRunMode: 'record_only', hasRun: true,
    recorded: rows, scanned: [], evaluatedAt: '2026-11-10T10:00:00Z', nextCursor: found > 100 ? 'z' : null,
    totals: {
      found, recorded: found, scanned: 0, wouldScan: 1, matching: found,
      byReason: { scanned: 1, filter_no_match: 1, filter_excluded: 1, resolves_outside_targets: 1 },
      byIp: { '203.0.113.10': found },
    },
    ...over,
  }
}

test('each info modal opens from its card, leaves the mode alone, and returns focus on Escape', async ({ page }, info) => {
  const group = await openTargetForm(page)
  const before = await checkedValue(page)
  for (const m of MODES) {
    const button = page.getByRole('button', { name: `How '${m.label}' works` })
    await button.click()
    const dialog = page.getByRole('dialog', { name: `How '${m.label}' works` })
    await expect(dialog).toBeVisible()
    await expect(dialog.getByRole('img')).toHaveAttribute('aria-label', /.+/)
    await expect(dialog.getByRole('heading', { name: 'What RedAmon does' })).toBeVisible()
    await shot(page, info, `modal-${m.value}`)
    await dialog.getByRole('button', { name: 'Compare all four modes' }).click()
    await expect(dialog.getByRole('table')).toBeVisible()
    await shot(page, info, `modal-${m.value}-compare`)
    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
    await expect(button).toBeFocused()
    expect(await checkedValue(page)).toBe(before)
  }
  await expect(group).toBeVisible()
})

test('the arrow keys move the selection within the radio group', async ({ page }) => {
  const group = await openTargetForm(page)
  await group.getByRole('radio', { name: /IP only/ }).check()
  await group.getByRole('radio', { name: /IP only/ }).focus()
  await page.keyboard.press('ArrowDown')
  expect(await checkedValue(page)).toBe('record_only')
  await page.keyboard.press('ArrowDown')
  expect(await checkedValue(page)).toBe('record_filter')
  await page.keyboard.press('ArrowUp')
  expect(await checkedValue(page)).toBe('record_only')
})

test('Record + scan all cannot be saved until confirmed', async ({ page }, info) => {
  const group = await openTargetForm(page)
  const save = page.getByRole('button', { name: /Update Settings/ })
  const scanAll = group.getByRole('radio', { name: /Record \+ scan all/ })
  test.skip(await scanAll.isDisabled(), 'the project is a third-party engagement, where scan_all is refused (D-03)')
  await scanAll.check()
  await expect(save).toBeDisabled()
  await expect(page.locator('#project-save-blocked')).toContainText('scan_all needs ipHostnameScanAllConfirmed: true')
  await expect(page.getByText(/Every hostname found on your IPs will be scanned/)).toBeVisible()
  await shot(page, info, 'm1-unconfirmed')
  await page.getByLabel(/I confirm every site hosted on these IPs is in scope/).check()
  await expect(save).toBeEnabled()
  await expect(page.locator('#project-save-blocked')).toHaveCount(0)
})

for (const width of WIDTHS) {
  test(`cards, filters and preview at ${width} px`, async ({ page }, info) => {
    await servePreview(page, { body: previewBody() })
    const group = await openTargetForm(page, width)
    await shot(page, info, `${width}-cards`)
    await group.getByRole('radio', { name: /Record \+ scan matching/ }).check()
    await expect(page.getByLabel('Include (one per line)')).toBeVisible()
    await expect(page.getByTestId('ip-hostname-preview-count')).toHaveText('would scan 1 of 4')
    await page.getByTestId('ip-hostname-preview-count').scrollIntoViewIfNeeded()
    await shot(page, info, `${width}-filters-preview`)
    if (width < 768) {
      // Narrow: Seen on and Sources move into the row detail.
      await expect(page.locator('details').filter({ hasText: 'Details' }).first()).toBeVisible()
    }
    await page.getByRole('button', { name: "How 'Record + scan matching' works" }).click()
    await shot(page, info, `${width}-modal`)
  })
}

test('every preview state of §8', async ({ page }, info) => {
  const states: [string, { status?: number; body?: unknown; hang?: boolean }, RegExp][] = [
    ['loading', { hang: true }, /Loading names found last run/],
    ['error', { status: 500 }, /Couldn't load the names found last run\. The filters still apply at run time\./],
    ['not-found', { status: 404, body: { error: 'Not found' } }, /Couldn't find this project's names\. Reload the page\./],
    ['never-recorded', { body: previewBody({ recorded: [], lastRunMode: null }, 0) }, /No names recorded yet/],
    ['legacy', { body: previewBody({ recorded: [], legacy: true, lastRunMode: null }, 0) }, /predates hostname recording/],
    ['zero', { body: previewBody({ recorded: [], lastRunMode: 'record_only' }, 0) }, /No hostname was found on these IPs/],
    ['paged', { body: previewBody({}, 4312) }, /Showing 1-4 of 4,312/],
  ]
  const group = await openTargetForm(page)
  await group.getByRole('radio', { name: /Record \+ scan matching/ }).check()
  const include = page.getByLabel('Include (one per line)')
  let n = 0
  for (const [label, answer, text] of states) {
    await servePreview(page, answer)
    // A changed filter makes the preview ask again.
    await include.fill(`*.example.com\nstate${n++}.example.org`)
    await expect(page.getByText(text)).toBeVisible()
    await page.getByText(text).scrollIntoViewIfNeeded()
    await shot(page, info, `preview-${label}`)
  }
  await expect(page.getByRole('group', { name: 'Show names by result' })).toBeVisible()
})

test('the create form: the preview waits for a first scan', async ({ page }, info) => {
  // A new project opens on the workflow view with the target settings already open.
  await page.goto('/projects/new')
  await page.getByRole('button', { name: /IP \/ CIDR/ }).first().click()
  const group = page.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
  await group.getByRole('radio', { name: /Record \+ scan matching/ }).check()
  await expect(page.getByText('Available after the first scan in a recording mode.')).toBeVisible()
  await shot(page, info, 'preview-create')
})

test('inside the workflow node modal the narrow layouts apply', async ({ page }, info) => {
  await servePreview(page, { body: previewBody() })
  await page.setViewportSize({ width: 1600, height: 1000 })
  await page.goto(`/projects/${PROJECT}/settings`)
  await page.getByTitle('Workflow view').click()
  await page.locator('[class*="inputNode"]').first().click()
  const modal = page.getByRole('dialog')
  const group = modal.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
  await expect(group).toBeVisible()
  await group.getByRole('radio', { name: /Record \+ scan matching/ }).check()
  // Include and Exclude stack (one column) in the ~740 px the modal gives them.
  const inc = await modal.getByLabel('Include (one per line)').boundingBox()
  const exc = await modal.getByLabel('Exclude (one per line)').boundingBox()
  expect(exc!.y).toBeGreaterThan(inc!.y + inc!.height - 1)
  await shot(page, info, 'workflow-modal')
  // The info modal opens above it, and Escape closes only the info modal.
  await modal.getByRole('button', { name: "How 'Record + scan matching' works" }).click()
  await expect(page.getByRole('dialog', { name: "How 'Record + scan matching' works" })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog', { name: "How 'Record + scan matching' works" })).toHaveCount(0)
  await expect(group).toBeVisible()
})

test('lab: the live preview counts the names the lab run recorded', async ({ page }) => {
  test.skip(!LAB_PROJECT || !LAB_FOUND, 'REDAMON_IP_LAB_PROJECT and REDAMON_IP_LAB_FOUND are not set')
  await page.goto(`/projects/${LAB_PROJECT}/settings`)
  await page.getByTitle('Tab view').click()
  const group = page.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
  await group.getByRole('radio', { name: /Record \+ scan matching/ }).check()
  const include = page.getByLabel('Include (one per line)')
  if (!(await include.inputValue()).trim()) await include.fill('*.example.com')
  await expect(page.getByTestId('ip-hostname-preview-count')).toHaveText(new RegExp(` of ${Number(LAB_FOUND).toLocaleString('en-US')}$`))
})
