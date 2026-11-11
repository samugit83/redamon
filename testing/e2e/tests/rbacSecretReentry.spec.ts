import { test, expect } from '@playwright/test'
import { cleanupRbac, loginAs, seedRbac, type RbacSeed } from './rbacUsers'

/**
 * Step 1.6 done-when (HD-24): an admin editing their OWN provider's base URL without
 * typing the key again sees the re-entry message under the API key field, which takes
 * the focus, and nothing is saved. The rule holds for the account itself: a stolen
 * session cannot re-point a stored key it never saw. With the key typed again the save
 * asks for the admin's own password (ID-25), and only then re-points the provider.
 *
 * Seeds its own synthetic accounts and removes them afterwards (the provider goes with
 * its account). The key is a fake and both base URLs are closed local ports: nothing is
 * ever sent anywhere.
 */

let seed: RbacSeed

test.beforeAll(() => {
  seed = seedRbac()
})

test.afterAll(() => {
  cleanupRbac()
})

test('an admin re-pointing their own provider is asked for the key again', async ({ page }) => {
  await loginAs(page, 'ADMIN_A')
  const providers = `/api/users/${seed.ADMIN_A_ID}/llm-providers`
  const created = await page.request.post(providers, {
    data: {
      providerType: 'openai_compatible', name: 'rbac-reentry', modelIdentifier: 'rbac-model',
      baseUrl: 'http://127.0.0.1:9/v1', apiKey: 'rbac-fake-llm-key-0000000000000009',
    },
  })
  expect(created.status()).toBe(201)

  await page.goto('/settings?tab=providers')
  await page.locator('[class*="providerCard"]', { hasText: 'rbac-reentry' }).getByTitle('Edit').click()
  await page.getByPlaceholder('http://host.docker.internal:11434/v1').fill('http://127.0.0.2:9/v1')
  await page.getByRole('button', { name: 'Update Provider' }).click()

  // The hint under the field, not the error toast that says the same outside the page.
  await expect(page.getByRole('main').getByRole('alert').filter({ hasText: 'type the API key again' })).toBeVisible()
  await expect(page.getByLabel('API key')).toBeFocused()

  const stored = await (await page.request.get(providers)).json() as { name: string; baseUrl: string }[]
  expect(stored.find(p => p.name === 'rbac-reentry')?.baseUrl).toBe('http://127.0.0.1:9/v1')

  // Typed again, the same change asks for the password, and nothing moves before it.
  await page.getByLabel('API key').fill('rbac-fake-llm-key-0000000000000010')
  await page.getByRole('button', { name: 'Update Provider' }).click()
  const stepUp = page.getByRole('dialog').filter({ hasText: 'new address' })
  await expect(stepUp).toBeVisible()
  const pending = await (await page.request.get(providers)).json() as { name: string; baseUrl: string }[]
  expect(pending.find(p => p.name === 'rbac-reentry')?.baseUrl).toBe('http://127.0.0.1:9/v1')
  await stepUp.getByLabel('Your password').fill(seed.RBAC_PASSWORD)
  await stepUp.getByRole('button', { name: 'Save' }).click()
  await expect.poll(async () => {
    const rows = await (await page.request.get(providers)).json() as { name: string; baseUrl: string }[]
    return rows.find(p => p.name === 'rbac-reentry')?.baseUrl
  }).toBe('http://127.0.0.2:9/v1')
})
