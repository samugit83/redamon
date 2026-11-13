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
 *   - a refused cookie is kept and /api/auth/me answers Phase 1's bare 401, so the browser is
 *     not sent to /login: clearing the cookie and the redirect belong to the switch (review of
 *     step 2.2). The cookie is dead anyway: a version only rises, a deleted id never returns.
 *
 * Step 2.3 adds disable, enable and "sign out everywhere". With the switch off:
 *   - disable, revoke-sessions and revoke-all answer 404 to everyone, as before they existed,
 *     and read nothing;
 *   - enable stays open to admins, so an account disabled while the switch was on can be
 *     restored (a member is refused, as on every admin route);
 *   - schedules and queued jobs start whatever their account's status: nothing is read.
 *
 * Step 2.4 moves the tunnel and the TrafficMind capture policy into the instance settings.
 * With the switch off:
 *   - /api/admin/instance-settings answers 404 to everyone, as before it existed;
 *   - the readers read no instance row (the user rows, as after Phase 1); the boot backfill
 *     still fills the row, so it is ready the day the switch goes on.
 *
 * Step 2.5 recognises one Root and protects it. With the switch off:
 *   - there is no Root: nothing reads the instance row for it, no route refuses
 *     `root_protected` (rootProtections.test.ts runs each route), an act-as cookie naming
 *     another admin acts as after Phase 1; the boot backfill still chooses the Root;
 *   - /api/auth/me carries no account type and no Root.
 *
 * Step 2.6 makes managing admins, the security policy and the Root transfer the confirmed Root's
 * powers. With the switch off:
 *   - nobody holds them and nothing reads the Root for them: every admin keeps the Phase 1
 *     rules (rootOnlyAdmins.test.ts runs each route with the switch off);
 *   - a role change raises no session version;
 *   - the Root transfer routes answer 404 to everyone, as before they existed, and read nothing.
 *
 * Step 2.8 makes the password policy configurable. With the switch off:
 *   - every new password meets Phase 1's policy (12 characters, 72 bytes): no instance minimum,
 *     no deny list, no email or repeated-character rule, and no instance row is read;
 *   - /api/auth/password-policy answers 404 to everyone and reads nothing (the forms keep
 *     Phase 1's floor and show no policy text);
 *   - no must-change: sign-in signs no `pwc` claim and reads no short-password setting, an
 *     admin's reset or a new account's password sets no flag and raises no version, the
 *     middleware lets a `pwc` cookie (minted while the switch was on) go anywhere, and the
 *     session helpers compare neither the claim nor the flag.
 *
 * Step 2.9 adds invite links and the public page that accepts them. With the switch off:
 *   - the admin invite routes (invite, resend, cancel) answer 404 to everyone and read nothing;
 *   - /invite, /invite/<token> and /api/invite/* are not public: signed out they get the sign-in
 *     redirect or 401 like any unknown path; signed in, the link and the API answer 404, read
 *     nothing and set no cookie, and the page does not exist.
 *
 * Step 2.10 adds credentials resets (a reset link or a temporary password, with a reason and a
 * notice to the person). With the switch off:
 *   - /api/users/[id]/reset-credentials answers 404 to everyone and reads nothing;
 *   - an admin setting someone else's password writes Phase 1's password alone: no reason asked,
 *     no notice, no version raised, no socket closed;
 *   - a sign-in answers no notice, marks none shown and writes no `auth.login.after_reset` row
 *     (login/route.resetNotice.test.ts), whatever notices a reset made while the switch was on.
 *
 * Step 2.11 adds the email change, the session lifetimes and the My account page. With the switch
 * off:
 *   - changing a sign-in email takes no password and writes Phase 1's `user.update` row, no notice
 *     (users/[id]/route.emailChange.test.ts);
 *   - every login token lives 7 days with `{sub, role, sv, iat, exp}` only (no `adm`, `idl`, `lat`),
 *     an act-as cookie 12 h, and no instance row is read for them (sessionLifetime.test.ts,
 *     login/route.lifetime.test.ts, act-as/route.test.ts);
 *   - the middleware ends no session for idleness and refreshes none, whatever claims a token
 *     minted while the switch was on carries (middleware.sessionIdle.test.ts);
 *   - /api/account/activity answers 404 to everyone and reads nothing, and the My account page is
 *     step 2.8's password form alone (account/page.myAccount.test.tsx).
 *
 * Step 2.12 makes the identity routes accept only same-origin JSON. Whatever the switch, like the
 * session-version comparison: it is a security fix of the Phase 1 routes (creating, editing and
 * deleting accounts, passwords, act-as, MCP tokens, the user settings) and of enable and the
 * legacy-grant review, which run with the switch off too; a page of this app sends the same
 * request as before, so only a request from another site or a non-JSON body is refused
 * (identitySameOrigin.test.ts and settings/sameOrigin.test.ts run each route with the switch off
 * and on). The Phase 2 routes answer 404 before it with the switch off. The Users page gains the
 * Status and Last login columns whatever the switch (the login records the time whatever it); with
 * it off the role column, the actions and the create form stay Phase 1's, and no must-change flag
 * is read or shown (users/route.test.ts, settings/users/page.columns.test.tsx).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/identity.flags.off.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import path from 'path'
import { NextRequest } from 'next/server'

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
  // Step 2.4: fills the instance settings row whatever the switch (the data is ready the day
  // it goes on); with the switch off nothing reads that row.
  'scripts/backfill-rbac-instance-settings.mjs',
  // Step 2.5: chooses the automatic Root whatever the switch (ready the day it goes on);
  // with the switch off no Root power or protection reads it.
  'scripts/backfill-rbac-root.mjs',
  // The host commands (step 2.7) run whatever the switch: a host reset bumps the session
  // version (the one identity check the switch does not gate) and re-enables the account;
  // check-root / set-root and create-admin's first admin record Root, which takes effect
  // only with the switch on.
  'scripts/check-root.mjs',
  'scripts/create-admin.mjs',
  // Step 3.8: the live-matrix fixture seed gives its synthetic rbac-* admin the User manager profile
  // whatever the switch; the profile counts only with the switches on, as for any admin.
  'scripts/e2e-rbac-seed.mjs',
  // Step 2.8: the instance password minimum, read by the host scripts only with the switch on.
  'scripts/lib/passwordRules.mjs',
  // Step 2.13: the upgrade preview reads the Root and whether an admin saved the instance row,
  // read-only, for its report alone; the switch changes only the lines printed, never the exit
  // status (both sections are `affects: false`).
  'scripts/rbac-upgrade-preview.mjs',
  'scripts/reset-password.mjs',
  'scripts/set-root.mjs',
  // Step 6.2: the admin console's users directory and detail show the last sign-in and a password
  // that must change; they sit under /admin, which does not exist with the governance switch off
  // (it needs this switch), and their API answers 404 then (governance.flags.off.test.ts).
  'src/app/admin/users/[id]/page.tsx',
  'src/app/admin/users/page.tsx',
  // Login: the session version it signs (compared whatever the switch) and the last-login
  // time it writes whatever the switch; status and must-change (pwc) only with the switch on.
  'src/app/api/auth/login/route.ts',
  // Step 2.8: an admin's reset flags the account and raises its version, an own change clears
  // the flag, only with the switch on; off, the Phase 1 write of the password alone.
  'src/app/api/users/[id]/password/route.ts',
  // Step 2.10: reads the account's status and last sign-in after a 404 with the switch off.
  'src/app/api/users/[id]/reset-credentials/route.ts',
  // Step 2.6: a role change raises the session version only with the switch on (its
  // identity path); off, the Phase 1 path writes the role alone.
  'src/app/api/users/[id]/route.ts',
  // Step 2.8: a new account with a temporary password is flagged only with the switch on. Step
  // 2.12: the list carries the last sign-in whatever the switch, the must-change flag only with it on.
  'src/app/api/users/route.ts',
  // Step 2.12: the Users page shows the last sign-in whatever the switch, a password that must
  // change only with it on; the hook only types the list's fields.
  'src/app/settings/users/page.tsx',
  // Step 3.13: the permission panel reads and sends an admin's profile through the permissions
  // API, which answers 404 with the permissions switch off (the page shows the panel only with it on).
  'src/components/admin/permissionModel.ts',
  'src/hooks/useUsers.ts',
  // Step 2.11: My activity reads the account's notices, reached only through a route that answers
  // 404 with the switch off.
  'src/lib/authz/accountActivity.ts',
  'src/lib/authz/accountEmail.ts',
  // Step 2.10: the reset notices, written by a reset and handed over at a sign-in, both only with
  // the switch on.
  'src/lib/authz/accountNotices.ts',
  // Disable, enable, revoke sessions (step 2.3): reached only through routes that answer 404
  // with the switch off, except enable, which stays open to restore an account disabled
  // while the switch was on.
  'src/lib/authz/accountStatus.ts',
  // Step 3.14: the impersonation settings and the admin's session version an act-as token carries,
  // read only with the permissions switch on, which needs this switch.
  'src/lib/authz/actAs.ts',
  // Step 6.6: audit retention reads the instance's retention and the legacy-grant holders only in the
  // expiry sweep's governance part, which needs this switch (governance.flags.off.test.ts).
  'src/lib/authz/auditRetention.ts',
  // Step 3.4: reads an admin's profile and the instance default set only with the permissions
  // switch on, which needs this switch; off, the account type's default (no Root, nothing read).
  'src/lib/authz/capabilities.ts',
  // Step 6.10: device sessions store the session version a sign-in had (a row below the account's
  // reads as ended), written and read only with the governance switch on, which needs this switch
  // (governance.flags.off.test.ts).
  'src/lib/authz/deviceSessionAdmin.ts',
  'src/lib/authz/deviceSessions.ts',
  // Step 4.15: the expiry sweep removes expired links only with the switch on (off, it reads none).
  'src/lib/authz/expirySweep.ts',
  // Step 2.9: invite and reset links, reached only through routes that answer 404 with the
  // switch off.
  'src/lib/authz/invites.ts',
  // Step 2.8: flags a short password at sign-in, reached only with the switch on.
  'src/lib/authz/mustChange.ts',
  // Step 2.8: reads no column; it names the 403 code `must_change_password`, which the
  // middleware answers only with the switch on.
  'src/lib/authz/mustChangeGate.ts',
  // Step 2.8: the instance password minimum and the sign-in prompt, read only with the switch on.
  'src/lib/authz/passwordPolicyInForce.ts',
  // Step 3.11: an admin's profile, read by the permission routes and the admins:manage gate, all
  // reached only with the permissions switch on, which needs this switch.
  'src/lib/authz/permissionAdmin.ts',
  // Step 3.11: an admin's profile and the instance default set (the instance row), written and read
  // only through routes that answer 404 with the permissions switch off.
  'src/lib/authz/permissionSetAdmin.ts',
  // Reads every identity field of the account; the cache only with the switch on.
  'src/lib/authz/principal.ts',
  // Step 2.10: credentials resets, reached only with the switch on (the reset route answers 404
  // without it; the password route takes its Phase 1 path).
  'src/lib/authz/resetCredentials.ts',
  // Step 2.5: the Root, read only with the switch on (off: no Root, nothing read).
  'src/lib/authz/root.ts',
  // Step 2.6: the Root transfer, reached only through routes that answer 404 with the switch off.
  'src/lib/authz/rootTransfer.ts',
  // Step 2.11: the session lifetimes, read only with the switch on (off: Phase 1's 7 days and 12 h).
  'src/lib/authz/sessionLifetime.ts',
  // Step 4.2: the instance sharing policy, read only with the sharing switch on, which needs this
  // switch (sharing.flags.off.test.ts).
  'src/lib/authz/sharingPolicy.ts',
  // Step 6.2: the admin users directory reads each account's status, must-change flag, last sign-in
  // and profile, reached only through routes that answer 404 with the governance switch off, which
  // needs this switch (governance.flags.off.test.ts).
  'src/lib/authz/userDirectory.ts',
  // Step 3.11: an admin's profile and the session version a removal raises, reached only through
  // a route that answers 404 with the permissions switch off.
  'src/lib/authz/userPermissionAdmin.ts',
  // Step 6.11: the instance LLM providers' policy (`byoLlmForbidden`) on the instance row and its audit
  // target, read and written only with the governance switch on, which needs this switch
  // (governance.flags.off.test.ts: the agent list and every provider route).
  'src/lib/instanceProviders/admin.ts',
  'src/lib/instanceProviders/store.ts',
  // Compares the session version whatever the switch, the status only with it on.
  'src/lib/session.ts',
  // Step 2.4: the tunnel and capture readers read the instance settings row only with the
  // switch on; off, they read the user rows as before.
  'src/lib/sharedInstanceSettings.ts',
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
    // Signed out, but the cookie stays, as a deleted account's did after Phase 1.
    expect(clearedCookies).toEqual([])
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

describe('RBAC_IDENTITY_ENABLED off (step 2.3)', () => {
  const post = (url: string) => new NextRequest(`http://redamon.test${url}`, {
    method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: '{}',
  })
  const params = { params: Promise.resolve({ id: 'member-2' }) }

  test.each([
    ['admin', 'admin-1', 'admin'],
    ['member', 'member-1', 'standard'],
    ['nobody', null, null],
  ])('disable, revoke-sessions and revoke-all answer 404 to %s and read nothing', async (_who, id, role) => {
    setFlagsForTests({ identity: false })
    authCookie = id && role ? await createToken(id, role) : undefined
    const { POST: disable } = await import('@/app/api/users/[id]/disable/route')
    const { POST: revokeSessions } = await import('@/app/api/users/[id]/revoke-sessions/route')
    const { POST: revokeAll } = await import('@/app/api/auth/sessions/revoke-all/route')
    for (const res of [
      await disable(post('/api/users/member-2/disable'), params),
      await revokeSessions(post('/api/users/member-2/revoke-sessions'), params),
      await revokeAll(post('/api/auth/sessions/revoke-all')),
    ]) {
      expect(res.status).toBe(404)
    }
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('enable stays open: the route answers (a member is refused as on every admin route)', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('member-1', 'standard')
    const { POST: enable } = await import('@/app/api/users/[id]/enable/route')
    const res = await enable(post('/api/users/member-2/enable'), params)
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:disable' })
  })

  test('a deferred scan is judged on nothing: no account is read', async () => {
    setFlagsForTests({ identity: false })
    const { inactiveScanAccount } = await import('./scanActor')
    expect(await inactiveScanAccount({ actorUserId: 'member-1', projectId: 'p1' })).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.4)', () => {
  // The Prisma double has no instanceSettings table: a read of it would throw (a 500 here).
  test('the instance settings route answers 404 to an admin and reads nothing', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('admin-1', 'admin')
    const { GET, PUT } = await import('@/app/api/admin/instance-settings/route')
    const url = 'http://redamon.test/api/admin/instance-settings'
    const headers = { host: 'redamon.test', 'content-type': 'application/json' }
    expect((await GET(new NextRequest(url, { headers }))).status).toBe(404)
    expect((await PUT(new NextRequest(url, { method: 'PUT', headers, body: '{"tunnelsEnabled":true}' }))).status).toBe(404)
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('the shared settings readers read no instance row', async () => {
    setFlagsForTests({ identity: false })
    const { instanceSettingsInForce } = await import('@/lib/sharedInstanceSettings')
    expect(await instanceSettingsInForce()).toBeNull()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.5)', () => {
  // The Prisma double has no instanceSettings table: a read of it would throw.
  test('there is no Root and nothing reads the instance row for one', async () => {
    setFlagsForTests({ identity: false })
    const { loadInstanceRoot, isRootAccount } = await import('./root')
    expect(await loadInstanceRoot()).toBeNull()
    expect(await loadInstanceRoot({ fresh: true })).toBeNull()
    expect(await isRootAccount('admin-1', { fresh: true })).toBe(false)
  })

  test('an act-as cookie naming another admin acts as after Phase 1', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'admin-2')
    const { getEffectiveUser } = await import('@/lib/session')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-2' })
  })

  test('no route answers root_protected: the protection reads nothing and refuses nothing', async () => {
    setFlagsForTests({ identity: false })
    const { rootProtectedRefusal } = await import('./rootProtection')
    const request = new NextRequest('http://redamon.test/api/x', { method: 'POST' })
    for (const attempted of ['edit', 'role_change', 'delete', 'reset_password', 'disable', 'enable', 'revoke_sessions', 'act_as'] as const) {
      expect(await rootProtectedRefusal(request, { userId: 'admin-1', role: 'admin' }, 'admin-2', attempted)).toBeNull()
    }
    expect(await rootProtectedRefusal(request, { userId: 'admin-1', role: 'admin' }, 'admin-1', 'role_change', { self: true })).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.6)', () => {
  // The Prisma double has no instanceSettings table: a read of it would throw.
  test("no Root power is held or looked up: the gates answer Phase 1's way and read nothing", async () => {
    setFlagsForTests({ identity: false })
    const { rootStanding, adminTargetGate } = await import('./rootPowers')
    expect(await rootStanding('admin-1')).toBe('none')
    const request = new NextRequest('http://redamon.test/api/x', { method: 'POST' })
    expect(await adminTargetGate(request, { userId: 'admin-1', role: 'admin' }, 'admin-2', undefined, 'x'))
      .toEqual({ adminTarget: false })
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('the Root transfer routes answer 404 to everyone and read nothing', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('admin-1', 'admin')
    const { GET, POST: offer } = await import('@/app/api/root/transfer/route')
    const { POST: accept } = await import('@/app/api/root/transfer/accept/route')
    const { POST: cancel } = await import('@/app/api/root/transfer/cancel/route')
    const post = (body: unknown) => new NextRequest('http://redamon.test/api/root/transfer', {
      method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    for (const res of [
      await GET(new NextRequest('http://redamon.test/api/root/transfer')),
      await offer(post({ targetUserId: 'admin-2', stepUpPassword: 'x' })),
      await accept(post({ stepUpPassword: 'x' })),
      await cancel(post({})),
    ]) expect(res.status).toBe(404)
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.8)', () => {
  // The Prisma double has no instanceSettings table: a read of it would throw.
  test("the policy in force is Phase 1's and no instance row is read", async () => {
    setFlagsForTests({ identity: false })
    const { passwordPolicyInForce } = await import('./passwordPolicyInForce')
    expect(await passwordPolicyInForce()).toEqual({ minLength: 12, rules: false, askChangeIfShort: false })
    const { validateNewPassword } = await import('./passwordPolicy')
    expect(validateNewPassword('password1234', await passwordPolicyInForce())).toEqual({ ok: true })
  })

  test('the password policy route answers 404 to everyone and reads nothing', async () => {
    setFlagsForTests({ identity: false })
    authCookie = await createToken('member-1', 'standard')
    const { GET } = await import('@/app/api/auth/password-policy/route')
    expect((await GET()).status).toBe(404)
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.8): no must-change', () => {
  test('a pwc cookie goes anywhere through the middleware', async () => {
    setFlagsForTests({ identity: false })
    const { middleware } = await import('@/middleware')
    const cookie = await createToken('member-1', 'standard', 0, { pwc: true })
    for (const path of ['/graph', '/api/projects']) {
      const res = await middleware(new NextRequest(`http://redamon.test${path}`, { headers: { cookie: `redamon-auth=${cookie}` } }))
      expect(res.status, path).toBe(200)
      expect(res.headers.get('location'), path).toBeNull()
    }
  })

  test('the session helpers compare neither the claim nor the flag', async () => {
    setFlagsForTests({ identity: false })
    findUnique.mockImplementation(async ({ where }: { where: { id: string } }) => ({
      id: where.id, email: `${where.id}@e2e.local`, role: 'standard', password: 'hash', createdAt: new Date(0),
      legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: true,
    }))
    authCookie = await createToken('member-1', 'standard', 0)
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
    authCookie = await createToken('member-1', 'standard', 0, { pwc: true })
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
    expect(clearedCookies).toEqual([])
    findUnique.mockImplementation(anyAccount)
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.9)', () => {
  test('the admin invite routes answer 404 to an admin, a member and nobody, and read nothing', async () => {
    setFlagsForTests({ identity: false })
    const { POST: invite } = await import('@/app/api/users/invite/route')
    const { POST: resend } = await import('@/app/api/users/[id]/invite/resend/route')
    const { POST: cancel } = await import('@/app/api/users/[id]/invite/cancel/route')
    const post = () => new NextRequest('http://redamon.test/api/users/invite', {
      method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Nina', email: 'nina@e2e.local' }),
    })
    const params = { params: Promise.resolve({ id: 'member-2' }) }
    for (const cookie of [await createToken('admin-1', 'admin'), await createToken('member-1', 'standard'), undefined]) {
      authCookie = cookie
      expect((await invite(post())).status).toBe(404)
      expect((await resend(post(), params)).status).toBe(404)
      expect((await cancel(post(), params)).status).toBe(404)
    }
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.9): no public invite page', () => {
  test('the invite paths are like any unknown path at the middleware', async () => {
    setFlagsForTests({ identity: false })
    const { middleware } = await import('@/middleware')
    for (const path of ['/invite', '/invite/some-token']) {
      const res = await middleware(new NextRequest(`http://redamon.test${path}`))
      expect(res.headers.get('location'), path).toBe('http://redamon.test/login')
      expect(res.headers.get('content-security-policy'), path).toBeNull()
    }
    for (const path of ['/api/invite/state', '/api/invite/accept']) {
      expect((await middleware(new NextRequest(`http://redamon.test${path}`))).status, path).toBe(401)
    }
  })

  test('signed in, the link and the invite API answer 404, read nothing and set no cookie', async () => {
    setFlagsForTests({ identity: false })
    const { GET: link } = await import('@/app/invite/[token]/route')
    const { GET: state } = await import('@/app/api/invite/state/route')
    const { POST: accept } = await import('@/app/api/invite/accept/route')
    const { signInviteCookie } = await import('./invites')
    const cookie = `redamon-auth=${await createToken('member-1', 'standard')}; redamon-invite=${await signInviteCookie('invite-1')}`
    const get = (path: string) => new NextRequest(`http://redamon.test${path}`, { headers: { cookie } })
    const responses = [
      await link(get('/invite/some-token'), { params: Promise.resolve({ token: 'some-token' }) }),
      await state(get('/api/invite/state')),
      await accept(new NextRequest('http://redamon.test/api/invite/accept', {
        method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ password: 'x'.repeat(20) }),
      })),
    ]
    for (const res of responses) {
      expect(res.status).toBe(404)
      expect(res.headers.getSetCookie()).toEqual([])
    }
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.10)', () => {
  test('reset-credentials answers 404 to an admin, a member and nobody, and reads nothing', async () => {
    setFlagsForTests({ identity: false })
    const { POST: resetCredentials } = await import('@/app/api/users/[id]/reset-credentials/route')
    const post = () => new NextRequest('http://redamon.test/api/users/member-2/reset-credentials', {
      method: 'POST', headers: { host: 'redamon.test', 'content-type': 'application/json' },
      body: JSON.stringify({ mode: 'link', reason: 'x' }),
    })
    const params = { params: Promise.resolve({ id: 'member-2' }) }
    for (const cookie of [await createToken('admin-1', 'admin'), await createToken('member-1', 'standard'), undefined]) {
      authCookie = cookie
      expect((await resetCredentials(post(), params)).status).toBe(404)
    }
    expect(findUnique).not.toHaveBeenCalled()
  })
})

describe('RBAC_IDENTITY_ENABLED off (step 2.11)', () => {
  test('a sign-in token is Phase 1\'s: 7 days, {sub, role, sv, iat, exp}, nothing read', async () => {
    setFlagsForTests({ identity: false })
    const { decodeJwt } = await import('jose')
    const { issueLoginToken, actAsLifetimeSeconds } = await import('./sessionLifetime')
    for (const role of ['admin', 'standard']) {
      const { token, maxAge } = await issueLoginToken({ id: `${role}-1`, role, sessionVersion: 0 }, { pwc: true })
      const claims = decodeJwt(token)
      expect(Object.keys(claims).sort()).toEqual(['exp', 'iat', 'role', 'sub', 'sv'])
      expect(claims.exp! - claims.iat!).toBe(7 * 24 * 3600)
      expect(maxAge).toBe(7 * 24 * 3600)
    }
    expect(await actAsLifetimeSeconds()).toBe(12 * 3600)
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('My activity answers 404 to a member, an admin and nobody, and reads nothing', async () => {
    setFlagsForTests({ identity: false })
    const { GET: activity } = await import('@/app/api/account/activity/route')
    for (const cookie of [await createToken('admin-1', 'admin'), await createToken('member-1', 'standard'), undefined]) {
      authCookie = cookie
      expect((await activity()).status).toBe(404)
    }
    expect(findUnique).not.toHaveBeenCalled()
  })
})
