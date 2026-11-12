import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { cleanupRbac, loginAs, seedRbac, type RbacSeed } from './rbacUsers'

/**
 * Step 1.10 done-when (HD-05, HD-06, UI-03): the tunnel is one listener for the whole
 * instance. The member holding the `tunnels` legacy grant still changes it from Global
 * Settings; a member without it sees the tunnel's status and who manages it, with no
 * controls; an admin keeps the controls. No browser session reads the credentials.
 *
 * With RBAC_IDENTITY_ENABLED on (step 2.4, OQ-R3 (a)) the tunnel is an instance setting:
 * the same people change it in the Tunneling section's own form (/api/admin/instance-settings),
 * and the account's settings row is no longer where it is stored. The spec reads which one
 * applies from the holder's settings (`sharedSettingsAt`). On the instance it changes the
 * instance's own tunnel, so it skips unless that tunnel is unconfigured (no ngrok token, no
 * chisel URL), and leaves it unconfigured again.
 *
 * Seeds its own synthetic accounts and removes them afterwards. The grant is set by SQL,
 * as the upgrade backfill records it. The chisel URL typed is a closed local port and
 * tunnels stay disabled, so the save pushes only the stop config the sandbox already
 * runs; the spec skips when a live tunnel is up, which that push would take down. The
 * URL is cleared again before the spec ends.
 */

const REPO = join(__dirname, '..', '..', '..')
const URL_PLACEHOLDER = 'e.g. http://your-vps.com:9090'
const MANAGED_TEXT = 'The tunnel is managed by an administrator.'
const FAKE_CHISEL = 'http://127.0.0.1:9'

let seed: RbacSeed

function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['compose', 'exec', '-T', 'postgres', 'sh', '-c', 'psql -X -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
    { cwd: REPO, input: sql, encoding: 'utf8' },
  )
}

test.beforeAll(() => {
  seed = seedRbac()
  const id = seed.MEMBER_A_ID
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error('unexpected seed id')
  psql(`UPDATE users SET legacy_grants = ARRAY['tunnels'] WHERE id = '${id}';`)
})

test.afterAll(() => {
  cleanupRbac()
})

const INSTANCE_SETTINGS = '/api/admin/instance-settings'

/** Whether the tunnel lives in the instance settings (the identity switch on), per the account's settings. */
async function tunnelAtInstance(page: Page, userId: string): Promise<boolean> {
  const res = await page.request.get(`/api/users/${userId}/settings`)
  return ((await res.json()) as { sharedSettingsAt?: string }).sharedSettingsAt === 'instance'
}

async function storedTunnel(page: Page, userId: string, atInstance: boolean): Promise<{ chiselServerUrl: string; ngrokAuthtoken: string }> {
  const res = await page.request.get(atInstance ? INSTANCE_SETTINGS : `/api/users/${userId}/settings`)
  const body = (await res.json()) as { chiselServerUrl?: string; ngrokAuthtoken?: string }
  return { chiselServerUrl: body.chiselServerUrl ?? '', ngrokAuthtoken: body.ngrokAuthtoken ?? '' }
}

async function saveChiselUrl(page: Page, value: string, atInstance: boolean): Promise<void> {
  await page.getByPlaceholder(URL_PLACEHOLDER).fill(value)
  await page.getByRole('button', { name: atInstance ? 'Save tunnel settings' : 'Save Settings' }).click()
  // "Saved, but not applied" when the sandbox is unreachable: the row is written either way.
  await expect(page.getByText(/Settings saved|Tunnel settings saved|Saved, but not applied/).first()).toBeVisible()
}

test('a legacy holder still changes the tunnel in the UI', async ({ page }) => {
  await loginAs(page, 'MEMBER_A')
  const status = await (await page.request.get('/api/agent/tunnel-status')).json() as Record<string, { active?: boolean }>
  test.skip(Object.values(status).some(s => s?.active), 'a live tunnel is up: a tunnel save would push the stop config')
  const atInstance = await tunnelAtInstance(page, seed.MEMBER_A_ID)
  if (atInstance) {
    const current = await storedTunnel(page, seed.MEMBER_A_ID, true)
    test.skip(current.chiselServerUrl !== '' || current.ngrokAuthtoken !== '', "the instance's tunnel is configured: the spec would replace it")
  }
  const chiselUrl = async () => (await storedTunnel(page, seed.MEMBER_A_ID, atInstance)).chiselServerUrl

  await page.goto('/settings?tab=keys')
  await expect(page.getByLabel('Enable tunnels')).toBeVisible()
  await expect(page.getByText(MANAGED_TEXT)).toHaveCount(0)

  await saveChiselUrl(page, FAKE_CHISEL, atInstance)
  await expect.poll(chiselUrl).toBe(FAKE_CHISEL)

  await saveChiselUrl(page, '', atInstance)
  await expect.poll(chiselUrl).toBe('')
})

test('a member without the grant sees the status and who manages it, and cannot read the credentials', async ({ page }) => {
  await loginAs(page, 'MEMBER_B')
  await page.goto('/settings?tab=keys')
  await expect(page.getByText(MANAGED_TEXT)).toBeVisible()
  await expect(page.getByText(/^(On \(.+\)|Off|Status unavailable)$/)).toBeVisible()
  await expect(page.getByPlaceholder(URL_PLACEHOLDER)).toHaveCount(0)
  await expect(page.getByLabel('Enable tunnels')).toHaveCount(0)
  expect((await page.request.get('/api/global/tunnel-config')).status()).toBe(404)
})

test('an admin keeps the tunnel controls', async ({ page }) => {
  await loginAs(page, 'ADMIN_A')
  await page.goto('/settings?tab=keys')
  await expect(page.getByPlaceholder(URL_PLACEHOLDER)).toBeVisible()
  await expect(page.getByText(MANAGED_TEXT)).toHaveCount(0)
  expect((await page.request.get('/api/global/tunnel-config')).status()).toBe(404)
})
