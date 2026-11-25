import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { test, expect, type Page } from '@playwright/test'
import { cleanupRbac, loginAs, seedRbac, type RbacSeed } from './rbacUsers'

/**
 * Step 1.10 done-when (HD-05, HD-06, UI-03), with each person's tunnel their own, running in their
 * own Kali sandbox (group 1): the member holding the `tunnels` legacy grant changes their tunnel
 * from Settings; a member without the Tunnels permission sees their own tunnel's state and the
 * per-person hint, with no controls; an admin keeps the controls. No browser session reads the
 * credentials. The tunnel is always stored in the person's own settings row, whatever the identity
 * switch (the instance settings never hold a tunnel any more).
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
// TunnelStatusReadOnly.tsx, per person, for someone without the Tunnels permission.
const OWN_TUNNEL_TEXT = 'Your own tunnel, in your own Kali sandbox. Turning one on needs the Tunnels permission; turning yours off does not.'
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
  // With RBAC_PERMISSIONS_ENABLED on, the first boot converts the column into override grants and
  // the column no longer counts: write what that conversion writes, as test_e2e_bola_live.sh does.
  psql(`INSERT INTO user_permission_overrides (user_id, permission, effect, expires_at, reason, granted_by_id)
        VALUES ('${id}', 'platform:tunnels', 'grant', (now() AT TIME ZONE 'UTC') + interval '90 days', 'kept from 7.7.x', 'system')
        ON CONFLICT (user_id, permission) DO NOTHING;`)
})

test.afterAll(() => {
  cleanupRbac()
})

/** The person's own stored tunnel, from their settings (the masked token reads non-empty when set). */
async function storedTunnel(page: Page, userId: string): Promise<{ chiselServerUrl: string; ngrokAuthtoken: string }> {
  const res = await page.request.get(`/api/users/${userId}/settings`)
  const body = (await res.json()) as { chiselServerUrl?: string; ngrokAuthtoken?: string }
  return { chiselServerUrl: body.chiselServerUrl ?? '', ngrokAuthtoken: body.ngrokAuthtoken ?? '' }
}

async function saveChiselUrl(page: Page, value: string): Promise<void> {
  await page.getByPlaceholder(URL_PLACEHOLDER).fill(value)
  await page.getByRole('button', { name: 'Save Settings' }).click()
  // "Saved, but not applied" when the sandbox is unreachable: the row is written either way.
  await expect(page.getByText(/Settings saved|Tunnel settings saved|Saved, but not applied/).first()).toBeVisible()
}

test('a legacy holder still changes the tunnel in the UI', async ({ page }) => {
  await loginAs(page, 'MEMBER_A')
  const status = await (await page.request.get('/api/agent/tunnel-status')).json() as Record<string, { active?: boolean }>
  test.skip(Object.values(status).some(s => s?.active), 'a live tunnel is up: a tunnel save would push the stop config')
  const chiselUrl = async () => (await storedTunnel(page, seed.MEMBER_A_ID)).chiselServerUrl

  await page.goto('/settings?tab=keys')
  await expect(page.getByLabel('Enable tunnels')).toBeVisible()
  await expect(page.getByText(MANAGED_TEXT)).toHaveCount(0)

  await saveChiselUrl(page, FAKE_CHISEL)
  await expect.poll(chiselUrl).toBe(FAKE_CHISEL)

  await saveChiselUrl(page, '')
  await expect.poll(chiselUrl).toBe('')
})

test('a member without the grant sees the status of their own tunnel, and cannot read the credentials', async ({ page }) => {
  await loginAs(page, 'MEMBER_B')
  const hint = await (await page.request.get(`/api/users/${seed.MEMBER_B_ID}/settings`)).json() as {
    tunnelScope?: string; tunnelsEnabled?: boolean
  }
  expect(hint.tunnelScope, "the member's tunnel is their own, in their own sandbox").toBe('own_sandbox')
  await page.goto('/settings?tab=keys')
  await expect(page.getByText(OWN_TUNNEL_TEXT)).toBeVisible()
  await expect(page.getByText(MANAGED_TEXT)).toHaveCount(0)
  const status = page.getByText(/^(On \(.+\)|Off|Status unavailable)$/)
  await expect(status).toBeVisible()
  await expect(page.getByPlaceholder(URL_PLACEHOLDER)).toHaveCount(0)
  await expect(page.getByLabel('Enable tunnels')).toHaveCount(0)
  // The one control is turning one's own tunnel off, offered only while a tunnel runs or the stored
  // setting reads on.
  if (hint.tunnelsEnabled !== true && !(await status.innerText()).startsWith('On')) {
    await expect(page.getByRole('button', { name: 'Turn my tunnel off' })).toHaveCount(0)
  }
  expect((await page.request.get('/api/global/tunnel-config')).status()).toBe(404)
})

test('an admin keeps the tunnel controls', async ({ page }) => {
  await loginAs(page, 'ADMIN_A')
  await page.goto('/settings?tab=keys')
  await expect(page.getByPlaceholder(URL_PLACEHOLDER)).toBeVisible()
  await expect(page.getByText(MANAGED_TEXT)).toHaveCount(0)
  expect((await page.request.get('/api/global/tunnel-config')).status()).toBe(404)
})
