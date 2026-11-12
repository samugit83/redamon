/**
 * The identity switch (RBAC_IDENTITY_ENABLED, Phase 2) off: everything behaves as after
 * Phase 1 (master plan §9.4, DV-30). Each Phase 2 step adds its part here.
 *
 * Step 2.1 adds columns and tables nobody reads yet, and an audit convention that is not
 * switched (it records the same people; it only stops recording them inconsistently):
 *   - the switch is off unless set;
 *   - the session and the principal keep today's shape and read no identity column;
 *   - no production code reads an identity table or column yet. A later step that adds a
 *     reader names it in IDENTITY_READERS, so every reader is reviewed against the switch;
 *   - the audit actor is the same with the switch off and on.
 *
 * Step 2.2 makes the principal read the identity columns and the login token carry the
 * session version. With the switch off:
 *   - the session version is still compared, the one identity check that runs whatever the
 *     switch (only the host commands bump it then: a host reset signs the account out);
 *   - the account's status decides nothing: no session ends because of it;
 *   - nothing is cached: every request reads the account, as after Phase 1;
 *   - a refused cookie is cleared and the browser lands on /login, because the deleted
 *     account of Phase 1 and the bumped version are refusals the switch does not gate.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/identity.flags.off.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import path from 'path'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

let authCookie: string | undefined
let actAsCookie: string | undefined
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && authCookie) return { value: authCookie }
      if (name === 'redamon-act-as' && actAsCookie) return { value: actAsCookie }
      return undefined
    },
    delete: (name: string) => { clearedCookies.push(name) },
  })),
}))
let clearedCookies: string[] = []

const anyAccount = async ({ where }: { where: { id: string } }): Promise<Record<string, unknown>> => ({
  id: where.id, email: `${where.id}@e2e.local`, role: where.id.startsWith('admin') ? 'admin' : 'standard',
  password: 'hash', createdAt: new Date(0), legacyGrants: [],
})
const findUnique = vi.fn(anyAccount)
vi.mock('@/lib/prisma', () => ({ default: { user: { findUnique: (a: { where: { id: string } }) => findUnique(a) } } }))

import { rbacFlags, setFlagsForTests } from './flags'
import { createToken, createActAsToken } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { auditActor } from '@/lib/auditActor'
import { clearPrincipalCacheForTests } from './principal'

const WEBAPP = path.resolve(__dirname, '../../..')

/** Production files allowed to read an identity table or column, each checking the switch where it must. */
const IDENTITY_READERS: string[] = [
  // The host commands (step 2.7) run whatever the switch: a host reset bumps the session
  // version (the one identity check the switch does not gate) and re-enables the account;
  // check-root / set-root and create-admin's first admin record Root, which takes effect
  // only with the switch on.
  'scripts/check-root.mjs',
  'scripts/create-admin.mjs',
  'scripts/reset-password.mjs',
  'scripts/set-root.mjs',
  // Login: the session version it signs (compared whatever the switch) and the last-login
  // time it writes whatever the switch; status / must-change are read for later steps.
  'src/app/api/auth/login/route.ts',
  'src/lib/authz/accountEmail.ts',
  // Reads every identity field of the account; the cache only with the switch on.
  'src/lib/authz/principal.ts',
  // Compares the session version whatever the switch, the status only with it on.
  'src/lib/session.ts',
]

const IDENTITY_NAMES = new RegExp(
  '\\b(instanceSettings|userInvite|sessionVersion|mustChangePassword|passwordOnHold|pendingNotices|lastLoginAt|' +
  'adminProfileId|instance_settings|user_invites|session_version|must_change_password|password_on_hold|' +
  'pending_notices|last_login_at|admin_profile_id)\\b',
)

function productionFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) {
      if (name === 'node_modules' || name === '__testing__' || name === '__fixtures__') continue
      productionFiles(full, out)
    } else if (/\.(ts|tsx|mjs|js)$/.test(name) && !/\.test\.(ts|tsx|mjs)$/.test(name)) {
      out.push(full)
    }
  }
  return out
}

beforeEach(() => {
  setFlagsForTests(null)
  authCookie = undefined
  actAsCookie = undefined
  clearedCookies = []
  findUnique.mockClear()
  clearPrincipalCacheForTests()
})
afterEach(() => setFlagsForTests(null))

describe('RBAC_IDENTITY_ENABLED off (step 2.1)', () => {
  test('the switch is off unless set', () => {
    vi.stubEnv('RBAC_IDENTITY_ENABLED', '')
    expect(rbacFlags().identity).toBe(false)
  })

  test('the session keeps its {userId, role} shape; the principal reads the identity columns (step 2.2)', async () => {
    authCookie = await createToken('member-1', 'standard')
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
    const select = (findUnique.mock.calls[0][0] as unknown as { select: Record<string, boolean> }).select
    expect(Object.keys(select).filter((k) => IDENTITY_NAMES.test(k)).sort())
      .toEqual(['adminProfileId', 'lastLoginAt', 'mustChangePassword', 'sessionVersion'])
  })

  test('no production code reads an identity table or column outside the named readers', () => {
    const files = [...productionFiles(path.join(WEBAPP, 'src')), ...productionFiles(path.join(WEBAPP, 'scripts'))]
    expect(files).toContain(path.join(WEBAPP, 'src/lib/session.ts'))
    expect(files).toContain(path.join(WEBAPP, 'scripts/backfill-rbac-legacy-grants.mjs'))
    const readers = files
      .filter((f) => IDENTITY_NAMES.test(readFileSync(f, 'utf8')))
      .map((f) => path.relative(WEBAPP, f))
      .sort()
    expect(readers).toEqual(IDENTITY_READERS)
  })

  test('the audit actor is the same with the switch off and on', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'member-1')
    setFlagsForTests({ identity: false })
    const off = await auditActor()
    setFlagsForTests({ identity: true })
    const on = await auditActor()
    expect(off).toEqual({ actorId: 'admin-1', onBehalfOfUserId: 'member-1', actorEmail: 'admin-1@e2e.local' })
    expect(on).toEqual(off)
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.2)', () => {
  afterEach(() => { findUnique.mockImplementation(anyAccount) })
  const account = (over: Record<string, unknown>) => async ({ where }: { where: { id: string } }) => ({
    id: where.id, email: `${where.id}@e2e.local`, role: 'standard', password: 'hash', createdAt: new Date(0),
    legacyGrants: [], status: 'active', sessionVersion: 0, ...over,
  })

  test('the session version is compared with the switch off too: a bumped account is signed out', async () => {
    setFlagsForTests({ identity: false })
    findUnique.mockImplementation(account({ sessionVersion: 1 }))
    authCookie = await createToken('member-1', 'standard', 0)
    expect(await getSession()).toBeNull()
    expect(clearedCookies).toEqual(['redamon-auth'])
    authCookie = await createToken('member-1', 'standard', 1)
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })

  test.each(['disabled', 'invited'])('with the switch off a %s status ends no session', async (status) => {
    setFlagsForTests({ identity: false })
    findUnique.mockImplementation(account({ status }))
    authCookie = await createToken('member-1', 'standard')
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
    expect(clearedCookies).toEqual([])
  })

  test('with the switch off every request reads the account: nothing is cached', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('member-1', 'standard')
    await getSession()
    await getSession()
    await getSession()
    expect(findUnique).toHaveBeenCalledTimes(3)
  })
})
