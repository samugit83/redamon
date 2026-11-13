import { test, expect, type Page } from '@playwright/test'
import { cleanupRbac, loginAs, readRbacSeed, seedRbac } from './rbacUsers'

/**
 * E2E-P4-01, P4-02, P4-04 (step 4.12; SH-09, SH-19, SH-20, SH-23, SH-27, UI-06, UI-07, DV-05): the share
 * dialog, driven in the browser. member_c owns rbac-PSHARED; viewer_tmp's seeded Read share is the one
 * these tests revoke, grant again and change (the next seed puts it back).
 *
 * - P4-01: member_c shares PSHARED with viewer_tmp as Viewer: the dialog confirms the person the server
 *   bound (name and email); viewer_tmp finds it under Shared with me with its owner and level.
 * - P4-02: an unknown email gets the route's own answer ("No account has this email."); then quick
 *   lookups hit the per-person ceiling of 20 a minute (429), and the dialog says so.
 * - P4-04: viewer_tmp changed to Analyst reads the captured traffic and the workspace; back to Viewer,
 *   both answer 403 naming the Raw data permission.
 *
 * Needs identity + permissions + RBAC_SHARING_ENABLED on and Root's policy enabled (skipped otherwise).
 * Run it alone, a minute after any other run that looked people up as member_c (the ceiling is per
 * person and per minute). Synthetic accounts only (rbac-*@e2e.local).
 * Run: cd testing/e2e && npx playwright test rbacShareDialog
 */

const PROJECT = 'rbac-PSHARED'
const TMP_NAME = 'RBAC Viewer Tmp'

test.describe.configure({ mode: 'serial' })

test.beforeAll(() => {
  seedRbac()
})

test.afterAll(() => {
  cleanupRbac()
})

async function skipUnlessSharing(page: Page): Promise<void> {
  const me = await (await page.request.get('/api/auth/me')).json()
  test.skip(me?.sharing?.enabled !== true, 'sharing is not in force (RBAC_SHARING_ENABLED and the instance policy)')
}

async function openShareDialog(page: Page) {
  await page.goto('/projects')
  await page.getByRole('button', { name: `Share ${PROJECT}` }).click()
  const dialog = page.getByRole('dialog', { name: `Share "${PROJECT}"` })
  await expect(dialog.getByRole('heading', { name: 'People with access' })).toBeVisible()
  return dialog
}

async function revokeIfListed(page: Page, dialog: ReturnType<Page['getByRole']>, name: string) {
  const row = dialog.getByRole('listitem', { name })
  await expect(dialog.getByText('Loading who has access...')).toHaveCount(0)
  if (await row.count() === 0) return
  await row.getByRole('button', { name: `Revoke access for ${name}` }).click()
  await page.getByRole('dialog', { name: 'Revoke access' }).getByRole('button', { name: 'Revoke' }).click()
  await expect(row).toHaveCount(0)
}

test('P4-01: the owner shares as Viewer; the dialog confirms the person; it is in their Shared with me', async ({ browser, baseURL }) => {
  const seed = readRbacSeed()
  const owner = await browser.newContext({ baseURL })
  const viewer = await browser.newContext({ baseURL })
  try {
    const page = await owner.newPage()
    await loginAs(page, 'MEMBER_C')
    await skipUnlessSharing(page)
    const dialog = await openShareDialog(page)
    await revokeIfListed(page, dialog, TMP_NAME)

    await dialog.getByLabel('Email', { exact: true }).fill(seed.VIEWER_TMP_EMAIL)
    await dialog.getByRole('radio', { name: /^Viewer/ }).check()
    await dialog.getByRole('button', { name: 'Share', exact: true }).click()
    const shared = dialog.getByRole('status', { name: 'Shared' })
    await expect(shared).toContainText(TMP_NAME)
    await expect(shared).toContainText(seed.VIEWER_TMP_EMAIL)
    await expect(shared).toContainText('Viewer (Read)')
    const row = dialog.getByRole('listitem', { name: TMP_NAME })
    await expect(row).toContainText('Viewer (Read)')
    await expect(row).toContainText('Granted by you')

    const theirs = await viewer.newPage()
    await loginAs(theirs, 'VIEWER_TMP')
    await theirs.goto('/projects')
    const section = theirs.getByRole('region', { name: 'Shared with me' })
    const card = section.locator('.card', { has: theirs.getByRole('heading', { name: PROJECT, level: 3 }) })
    await expect(card).toContainText(`Shared by RBAC Member C (${seed.MEMBER_C_EMAIL})`)
    await expect(card).toContainText('Read')
    await expect(card.getByRole('button', { name: `Leave ${PROJECT}` })).toBeVisible()
  } finally {
    await owner.close()
    await viewer.close()
  }
})

test('P4-02: an unknown email gets the route\'s answer; quick lookups are refused after 20', async ({ browser, baseURL }) => {
  const seed = readRbacSeed()
  const owner = await browser.newContext({ baseURL })
  try {
    const page = await owner.newPage()
    await loginAs(page, 'MEMBER_C')
    await skipUnlessSharing(page)
    const dialog = await openShareDialog(page)
    await dialog.getByLabel('Email', { exact: true }).fill('rbac-nobody-p4-02@e2e.local')
    await dialog.getByRole('button', { name: 'Share', exact: true }).click()
    await expect(dialog.getByRole('alert')).toContainText('No account has this email.')
    await expect(dialog.getByRole('status', { name: 'Shared' })).toHaveCount(0)

    // The route the dialog calls, as the dialog calls it (same-origin JSON), 25 times quickly.
    const statuses: number[] = []
    for (let i = 0; i < 25; i += 1) {
      const res = await page.request.post(`/api/projects/${seed.PSHARED_ID}/collaborators`, {
        headers: { Origin: new URL(baseURL!).origin, 'Content-Type': 'application/json' },
        data: { email: `rbac-nobody-p4-02-${i}@e2e.local`, access: 'read' },
      })
      statuses.push(res.status())
    }
    const first = statuses.indexOf(429)
    expect(first, statuses.join(',')).toBeGreaterThanOrEqual(0)
    expect(first, statuses.join(',')).toBeLessThan(20)
    expect(statuses.slice(0, first).every(s => s === 404), statuses.join(',')).toBe(true)
    expect(statuses.slice(first).every(s => s === 429), statuses.join(',')).toBe(true)

    await dialog.getByLabel('Email', { exact: true }).fill(seed.VIEWER_EMAIL)
    await dialog.getByRole('button', { name: 'Share', exact: true }).click()
    await expect(dialog.getByRole('alert')).toContainText('Too many people looked up')
  } finally {
    await owner.close()
  }
})

test('P4-04: Analyst reads traffic and the workspace; back to Viewer both answer 403', async ({ browser, baseURL }) => {
  const seed = readRbacSeed()
  const owner = await browser.newContext({ baseURL })
  const viewer = await browser.newContext({ baseURL })
  try {
    const page = await owner.newPage()
    await loginAs(page, 'MEMBER_C')
    await skipUnlessSharing(page)
    const theirs = await viewer.newPage()
    await loginAs(theirs, 'VIEWER_TMP')
    const traffic = () => theirs.request.get(`/api/traffic/${seed.PSHARED_ID}`)
    const workspace = () => theirs.request.get(`/api/agent/workspace/list?projectId=${seed.PSHARED_ID}&path=.`)

    const setPreset = async (preset: 'Viewer' | 'Analyst') => {
      const dialog = await openShareDialog(page)
      const row = dialog.getByRole('listitem', { name: TMP_NAME })
      await row.getByRole('button', { name: `Change access for ${TMP_NAME}` }).click()
      const form = dialog.getByRole('form', { name: `Change access for ${TMP_NAME}` })
      await form.getByRole('radio', { name: new RegExp(`^${preset}`) }).check()
      await form.getByRole('button', { name: 'Save' }).click()
      await expect(row).toContainText(preset === 'Analyst' ? 'Analyst (Read + Raw data & files)' : 'Viewer (Read)')
      await dialog.getByRole('button', { name: 'Close modal' }).click()
    }

    await setPreset('Analyst')
    const raw = await traffic()
    expect(raw.status()).toBe(200)
    expect(await raw.json()).toHaveProperty('rows')
    // The agent answers 200, or 404 for a project whose workspace was never written: never 403.
    expect((await workspace()).status()).not.toBe(403)

    await setPreset('Viewer')
    const denied = await traffic()
    expect(denied.status()).toBe(403)
    expect(await denied.json()).toMatchObject({ code: 'forbidden', permission: 'traffic:read' })
    const deniedFiles = await workspace()
    expect(deniedFiles.status()).toBe(403)
    expect(await deniedFiles.json()).toMatchObject({ code: 'forbidden', permission: 'workspace:read' })
  } finally {
    await owner.close()
    await viewer.close()
  }
})
