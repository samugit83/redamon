import { test, expect } from '@playwright/test'
import { cleanupRbac, loginAs, seedRbac, skipFirstRunScreens } from './rbacUsers'

/**
 * E2E-P2-06 (step 2.9, ID-14, ID-15): an admin invites a person and copies the link; the person
 * opens it in a browser of their own. The address becomes /invite (the token leaves it), the
 * password policy is shown, the password is set and the person is signed in as a member; the
 * same link opened again shows the invalid page; the link and the page send no referrer.
 *
 * Needs RBAC_IDENTITY_ENABLED on in the webapp (skipped otherwise). Synthetic accounts only
 * (rbac-*@e2e.local): the seed makes them, the cleanup removes them and the invited one.
 * Run: cd testing/e2e && npx playwright test rbacInvite
 */

const INVITEE = 'rbac-invitee-p2-06@e2e.local'
const PASSWORD = 'violet-harbour-lantern-42'

test.beforeAll(() => {
  seedRbac()
})

test.afterAll(() => {
  cleanupRbac()
})

test('P2-06: an admin invites, the person accepts the link in a browser of their own', async ({ browser, baseURL }) => {
  const admin = await browser.newContext({ baseURL })
  const invitee = await browser.newContext({ baseURL })
  const later = await browser.newContext({ baseURL })
  try {
    const adminPage = await admin.newPage()
    await loginAs(adminPage, 'ADMIN_A')
    const me = await (await adminPage.request.get('/api/auth/me')).json()
    test.skip(me?.rbac?.identity !== true, 'RBAC_IDENTITY_ENABLED is off: invite links do not exist')

    await adminPage.goto('/settings/users')
    await adminPage.getByRole('button', { name: 'Invite user' }).click()
    const dialog = adminPage.getByRole('dialog', { name: 'Invite user' })
    await dialog.getByLabel('Name').fill('RBAC Invitee')
    await dialog.getByLabel('Email').fill(INVITEE)
    await dialog.getByRole('button', { name: 'Create the invite link' }).click()
    // A role and an exact name: getByLabel('Invite link') also matches the "Copy the invite link" button.
    const link = await dialog.getByRole('textbox', { name: 'Invite link', exact: true }).inputValue()
    const path = new URL(link).pathname
    const token = path.split('/').pop()!
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    await dialog.getByRole('button', { name: 'Done' }).click()

    await skipFirstRunScreens(invitee)
    const page = await invitee.newPage()
    const landed = await page.goto(path)
    await expect(page).toHaveURL(/\/invite$/)
    expect(page.url()).not.toContain(token)
    const hop = await landed!.request().redirectedFrom()!.response()
    expect(hop!.status()).toBe(303)
    expect(hop!.headers()['referrer-policy']).toBe('no-referrer')
    expect(landed!.headers()['referrer-policy']).toBe('no-referrer')
    expect(landed!.headers()['content-security-policy']).toContain("default-src 'self'")

    await expect(page.getByText(/At least \d+ characters/)).toBeVisible()
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await page.getByLabel('Confirm password').fill(PASSWORD)
    await page.getByRole('button', { name: 'Set password and sign in' }).click()
    await page.getByRole('button', { name: 'OK' }).click()
    await expect(page).toHaveURL(/\/graph/)
    const signedIn = await (await page.request.get('/api/auth/me')).json()
    expect(signedIn.email).toBe(INVITEE)
    expect(signedIn.role).toBe('standard')

    await skipFirstRunScreens(later)
    const again = await later.newPage()
    await again.goto(path)
    await expect(again.getByText('This link is not valid or has expired')).toBeVisible()
    await expect(again.getByLabel('Password', { exact: true })).toHaveCount(0)
  } finally {
    await admin.close()
    await invitee.close()
    await later.close()
  }
})
