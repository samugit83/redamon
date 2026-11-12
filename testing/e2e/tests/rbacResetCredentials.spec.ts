import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { test, expect } from '@playwright/test'
import { cleanupRbac, loginAs, readRbacSeed, seedRbac, skipFirstRunScreens } from './rbacUsers'

/**
 * E2E-P2-08 (step 2.10, ID-18, ID-19): an admin resets rbac-member-c's credentials with a reset
 * link and a reason while the member is signed in. The member's open session ends (the page
 * reloads to /login). The member opens the link, chooses a password and is signed in; the reset
 * notice ("RBAC Admin A ... Reason: ...") is shown once after that sign-in, never again at the
 * next one; the audit holds exactly one auth.login.after_reset row for the member.
 *
 * Needs RBAC_IDENTITY_ENABLED on in the webapp (skipped otherwise). Synthetic accounts only
 * (rbac-*@e2e.local): the seed makes them, the cleanup removes them with their audit rows.
 * Run: cd testing/e2e && npx playwright test rbacResetCredentials
 */

const PASSWORD = 'amber-orchard-compass-57'
const REASON = 'RBAC E2E P2-08: locked out'

/** Rows of `action` targeting `userId`, counted in the postgres container (SQL on stdin, ids from the seed). */
function auditCount(action: string, userId: string): number {
  if (!/^[A-Za-z0-9_-]+$/.test(userId)) throw new Error('unexpected fixture id')
  const out = execFileSync(
    'docker',
    ['compose', 'exec', '-T', 'postgres', 'sh', '-c', 'psql -X -q -t -A -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
    {
      cwd: join(__dirname, '..', '..', '..'),
      input: `select count(*) from audit_log where action = '${action}' and target_id = '${userId}';\n`,
      encoding: 'utf8',
    },
  )
  return Number(out.trim())
}

test.beforeAll(() => {
  seedRbac()
})

test.afterAll(() => {
  cleanupRbac()
})

test('P2-08: a reset link with a reason signs the member out; the notice is shown once after the link is used', async ({ browser, baseURL }) => {
  const admin = await browser.newContext({ baseURL })
  const member = await browser.newContext({ baseURL })
  const later = await browser.newContext({ baseURL })
  try {
    const seed = readRbacSeed()
    const memberPage = await member.newPage()
    await loginAs(memberPage, 'MEMBER_C')

    const adminPage = await admin.newPage()
    await loginAs(adminPage, 'ADMIN_A')
    const me = await (await adminPage.request.get('/api/auth/me')).json()
    test.skip(me?.rbac?.identity !== true, 'RBAC_IDENTITY_ENABLED is off: credentials resets do not exist')

    await adminPage.goto('/settings/users')
    await adminPage.getByRole('button', { name: 'Reset the credentials of RBAC Member C' }).click()
    const dialog = adminPage.getByRole('dialog', { name: 'Reset credentials - RBAC Member C' })
    await expect(dialog.getByRole('radio', { name: 'Send a reset link' })).toBeChecked()
    await dialog.getByLabel('Reason').fill(REASON)
    await dialog.getByRole('button', { name: 'Reset credentials' }).click()
    // A role and an exact name: getByLabel('Reset link') also matches the "Send a reset link" radio
    // (still shown while the request runs) and the "Copy the reset link" button.
    const link = await dialog.getByRole('textbox', { name: 'Reset link', exact: true }).inputValue()
    const path = new URL(link).pathname
    expect(path).toMatch(/^\/invite\/[A-Za-z0-9_-]{43}$/)
    await dialog.getByRole('button', { name: 'Done' }).click()

    // The member's open session ended: its cookie is refused and the page goes to /login.
    expect((await memberPage.request.get('/api/auth/me')).status()).toBe(401)
    await memberPage.reload()
    await expect(memberPage).toHaveURL(/\/login(\?|$)/, { timeout: 30_000 })

    // The member uses the link, chooses a password and is signed in; the notice comes once.
    await memberPage.goto(path)
    await expect(memberPage).toHaveURL(/\/invite$/)
    await expect(memberPage.getByRole('heading', { name: 'Choose a new password' })).toBeVisible()
    await memberPage.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await memberPage.getByLabel('Confirm password').fill(PASSWORD)
    await memberPage.getByRole('button', { name: 'Set password and sign in' }).click()
    await memberPage.getByRole('dialog', { name: 'Password set' }).getByRole('button', { name: 'OK' }).click()
    const notice = memberPage.getByRole('dialog', { name: 'Your password was reset' })
    await expect(notice).toContainText('rbac-admin-a@e2e.local')
    await expect(notice).toContainText(`Reason: ${REASON}`)
    await notice.getByRole('button', { name: 'OK' }).click()
    await expect(memberPage).toHaveURL(/\/graph/)
    expect(auditCount('auth.login.after_reset', seed.MEMBER_C_ID)).toBe(1)

    // The next sign-in shows no notice and records no address or browser.
    await skipFirstRunScreens(later)
    const again = await later.newPage()
    await again.goto('/login')
    await again.locator('#email').fill(seed.MEMBER_C_EMAIL)
    await again.locator('#password').fill(PASSWORD)
    await again.getByRole('button', { name: 'Sign In' }).click()
    await expect(again).toHaveURL(/\/graph/, { timeout: 30_000 })
    await expect(again.getByRole('dialog', { name: 'Your password was reset' })).toHaveCount(0)
    expect(auditCount('auth.login.after_reset', seed.MEMBER_C_ID)).toBe(1)
  } finally {
    await admin.close()
    await member.close()
    await later.close()
  }
})
