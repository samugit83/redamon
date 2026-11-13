import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { cleanupRbac, loginAs, readRbacSeed, seedRbac } from './rbacUsers'

/**
 * E2E-P5-01 (the grant half) and E2E-P5-02 (step 5.14; SH-05, SH-32, ID-25, UI-07): the share dialog grants
 * Read + Write, driven in the browser. member_c owns rbac-PSHARED; viewer_tmp's seeded Read share is the one
 * these tests change (the next seed puts it back).
 *
 * - P5-01: member_c changes viewer_tmp to Operator; before the owner allowed collaborators to spend the
 *   project's credentials the dialog asks that consent with the password, then saves; viewer_tmp's own
 *   access to PSHARED is Read + Write with Run scans and Use AI agent. (The run half of P5-01, viewer_tmp's
 *   partial recon and chat attributed in the feed, is checked by hand in the combined window.)
 * - P5-02: with Root's `membersMayGrantExploit` true, Red-teamer asks member_c's password (step-up) and is
 *   granted; with it false the dialog offers Exploitation & shells disabled with Root's reason and the route
 *   refuses it (409 `exploit_admins_only`), while taking it away still works.
 *
 * Needs identity + permissions + sharing + RBAC_SHARING_WRITE_ENABLED on and Root's policy enabled at write
 * (skipped otherwise). The spec flips `membersMayGrantExploit` in instance_settings by psql in the postgres
 * container and puts the stored policy back afterwards. Synthetic accounts only (rbac-*@e2e.local).
 * Run: cd testing/e2e && npx playwright test rbacShareWrite
 */

const REPO = join(__dirname, '..', '..', '..')
const PROJECT = 'rbac-PSHARED'
const TMP_NAME = 'RBAC Viewer Tmp'
const EXPLOIT_REFUSED = 'The instance sharing policy lets only administrators grant Exploitation & shells.'

test.describe.configure({ mode: 'serial' })

function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['compose', 'exec', '-T', 'postgres', 'sh', '-c', 'psql -X -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
    { cwd: REPO, input: sql, encoding: 'utf8' },
  ).trim()
}

let storedPolicy: string | null = null

function setMembersMayGrantExploit(on: boolean): void {
  psql(`UPDATE instance_settings SET sharing_policy = jsonb_set(coalesce(sharing_policy::jsonb, '{}'::jsonb), '{membersMayGrantExploit}', '${on}'::jsonb) WHERE id = 'instance';`)
}

test.beforeAll(() => {
  seedRbac()
  storedPolicy = psql("SELECT sharing_policy::text FROM instance_settings WHERE id = 'instance';")
})

test.afterAll(() => {
  if (storedPolicy !== null) {
    const literal = storedPolicy.replace(/'/g, "''")
    psql(`UPDATE instance_settings SET sharing_policy = '${literal}'::jsonb WHERE id = 'instance';`)
  }
  cleanupRbac()
})

async function skipUnlessWriteSharing(page: Page): Promise<void> {
  const me = await (await page.request.get('/api/auth/me')).json()
  test.skip(me?.sharing?.enabled !== true || me?.sharing?.maxLevel !== 'write',
    'write sharing is not in force (RBAC_SHARING_WRITE_ENABLED and the instance policy at write)')
}

/**
 * The webapp keeps Root's policy per process for RBAC_AUTHZ_CACHE_MS (6 s by default, sharingPolicy.ts), and
 * skipUnlessWriteSharing's /api/auth/me has just filled it: a dialog opened at once after a psql flip still offers
 * the old value. Wait, bounded, until the share list the dialog reads answers the value just set.
 */
async function waitForExploitGrantable(page: Page, projectId: string, grantable: boolean): Promise<void> {
  await expect.poll(async () => {
    const res = await page.request.get(`/api/projects/${projectId}/collaborators`)
    const body = res.ok() ? await res.json() : null
    return body?.grantable?.toggles?.exploit?.grantable === true
  }, { timeout: 20_000, intervals: [1_000] }).toBe(grantable)
}

async function openShareDialog(page: Page) {
  await page.goto('/projects')
  await page.getByRole('button', { name: `Share ${PROJECT}` }).click()
  const dialog = page.getByRole('dialog', { name: `Share "${PROJECT}"` })
  await expect(dialog.getByRole('heading', { name: 'People with access' })).toBeVisible()
  await expect(dialog.getByText('Loading who has access...')).toHaveCount(0)
  return dialog
}

/** Opens viewer_tmp's editor, picks the preset, saves; answers the password prompt when one opens. */
async function changePreset(page: Page, preset: string, password: string) {
  const dialog = await openShareDialog(page)
  const row = dialog.getByRole('listitem', { name: TMP_NAME })
  await row.getByRole('button', { name: `Change access for ${TMP_NAME}` }).click()
  const form = dialog.getByRole('form', { name: `Change access for ${TMP_NAME}` })
  await form.getByRole('radio', { name: new RegExp(`^${preset}`) }).check()
  await form.getByRole('button', { name: 'Save' }).click()
  const prompt = page.getByRole('dialog', { name: /Allow spending your credentials|Grant Exploitation & shells/ })
  await expect(form.or(prompt).first()).toBeVisible()
  if (await prompt.count()) {
    await prompt.getByLabel('Your password').fill(password)
    await prompt.getByRole('button', { name: /^(Allow and save|Save)$/ }).click()
    await expect(prompt).toHaveCount(0)
  }
  await expect(row).toContainText(`${preset} (`)
  return { dialog, row }
}

test('P5-01: Operator asks the owner\'s consent first; the collaborator then reaches Run scans and Use AI agent', async ({ browser, baseURL }) => {
  const seed = readRbacSeed()
  const owner = await browser.newContext({ baseURL })
  const collaborator = await browser.newContext({ baseURL })
  try {
    const page = await owner.newPage()
    await loginAs(page, 'MEMBER_C')
    await skipUnlessWriteSharing(page)
    const consentBefore = await (await page.request.get(`/api/projects/${seed.PSHARED_ID}/access-policy`)).json()
    const { dialog } = await changePreset(page, 'Operator', seed.RBAC_PASSWORD)
    await expect(dialog.getByRole('status', { name: 'Spending your credentials' })).toContainText('may spend')
    const consentAfter = await (await page.request.get(`/api/projects/${seed.PSHARED_ID}/access-policy`)).json()
    expect(consentAfter.ownerCredentialConsent).toBe(true)
    test.info().annotations.push({ type: 'consent', description: `before ${consentBefore.ownerCredentialConsent}, after true` })

    const theirs = await collaborator.newPage()
    await loginAs(theirs, 'VIEWER_TMP')
    const access = await (await theirs.request.get(`/api/projects/${seed.PSHARED_ID}/my-access`)).json()
    expect(access.myAccess ?? access).toMatchObject({ level: 'write', toggles: { runScans: true, useAgent: true, exploit: false } })
  } finally {
    await owner.close()
    await collaborator.close()
  }
})

test('P5-02: Red-teamer asks the password; with membersMayGrantExploit off it is refused by policy', async ({ browser, baseURL }) => {
  // Two policy-cache waits (up to 20 s and the closing 90 s poll) on top of the dialog work: above the default 60 s.
  test.setTimeout(180_000)
  const seed = readRbacSeed()
  const owner = await browser.newContext({ baseURL })
  try {
    const page = await owner.newPage()
    await loginAs(page, 'MEMBER_C')
    await skipUnlessWriteSharing(page)
    setMembersMayGrantExploit(true)
    await waitForExploitGrantable(page, seed.PSHARED_ID, true)
    const { row } = await changePreset(page, 'Red-teamer', seed.RBAC_PASSWORD)
    await expect(row).toContainText('Exploitation & shells')

    setMembersMayGrantExploit(false)
    const share = `/api/projects/${seed.PSHARED_ID}/collaborators/${seed.VIEWER_TMP_ID}`
    const headers = { Origin: new URL(baseURL!).origin, 'Content-Type': 'application/json' }
    // Taking it away is never blocked by the policy; granting it again is.
    expect((await page.request.patch(share, { headers, data: { exploit: false } })).status()).toBe(200)
    const refused = await page.request.patch(share, { headers, data: { exploit: true, stepUpPassword: seed.RBAC_PASSWORD } })
    expect(refused.status()).toBe(409)
    expect(await refused.json()).toMatchObject({ code: 'exploit_admins_only' })

    // The dialog reads the policy within RBAC_AUTHZ_CACHE_MS: Exploitation & shells disabled with Root's reason.
    await expect.poll(async () => {
      const dialog = await openShareDialog(page)
      const write = dialog.getByRole('group', { name: /Read \+ Write/ })
      const disabled = await write.getByRole('checkbox', { name: /^Exploitation & shells/ }).isDisabled()
      const said = await write.getByText(EXPLOIT_REFUSED).count()
      await dialog.getByRole('button', { name: 'Close modal' }).click()
      return disabled && said > 0
    }, { timeout: 90_000, intervals: [5_000] }).toBe(true)
  } finally {
    await owner.close()
  }
})
