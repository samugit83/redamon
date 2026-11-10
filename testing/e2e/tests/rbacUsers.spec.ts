import { test, expect } from '@playwright/test'
import { cleanupRbac, loginAs, seedRbac, type RbacSeed } from './rbacUsers'

/**
 * The multi-user helper end to end: two seeded members signed in at the same time
 * through the real login form, one browser context each, and each sees only their
 * own project. Seeds its own synthetic accounts and removes them afterwards.
 */

let seed: RbacSeed

test.beforeAll(() => {
  seed = seedRbac()
})

test.afterAll(() => {
  cleanupRbac()
})

test('two members sign in side by side and each sees only their own project', async ({ browser, baseURL }) => {
  const contextA = await browser.newContext({ baseURL })
  const contextB = await browser.newContext({ baseURL })
  try {
    const pageA = await contextA.newPage()
    const pageB = await contextB.newPage()
    await loginAs(pageA, 'MEMBER_A')
    await loginAs(pageB, 'MEMBER_B')

    const meA = await (await pageA.request.get('/api/auth/me')).json()
    const meB = await (await pageB.request.get('/api/auth/me')).json()
    expect(meA.email).toBe(seed.MEMBER_A_EMAIL)
    expect(meB.email).toBe(seed.MEMBER_B_EMAIL)

    const listA = await (await pageA.request.get('/api/projects')).text()
    expect(listA).toContain(seed.PA_ID)
    expect(listA).not.toContain(seed.PB_ID)

    await pageB.goto('/projects')
    await expect(pageB.getByText('rbac-PB', { exact: true }).first()).toBeVisible()
    await expect(pageB.getByText('rbac-PA', { exact: true })).toHaveCount(0)
  } finally {
    await contextA.close()
    await contextB.close()
  }
})
