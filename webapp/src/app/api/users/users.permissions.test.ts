/**
 * The user routes ask the policy (can(), through authz/adminPermission.ts), not the account type:
 * with RBAC_PERMISSIONS_ENABLED on an admin whose profile lacks the permission is refused 403
 * naming it (list `users:read`, create `users:create`, edit and roles `users:edit`, delete
 * `users:delete`, another account's password `users:reset_credentials`, another account's LLM
 * providers `users:read`), and an `admins:manage` holder edits, demotes, promotes and deletes an
 * admin over a strict subset of its own admin side, with its own password (hierarchy.ts, D-02),
 * where Phase 2 let only the confirmed Root. With the switch off every admin answers as before.
 *
 * Real routes, session helpers, tokens, bcrypt, step-up and the last-admin guard; the database is
 * the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})
vi.mock('@/lib/projectTeardown', () => ({
  teardownProject: async () => { throw new Error('the accounts here own no project') },
}))
// The case-insensitive address check is raw SQL the in-memory database does not answer.
vi.mock('@/lib/authz/accountEmail', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/accountEmail')>()),
  emailTakenByAnother: async () => false,
}))

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { builtinSet, FULL_ADMIN_PROFILE_ID } from '@/lib/authz/builtinSets'
import { __resetThrottle } from '@/lib/loginThrottle'
import { GET as listUsers, POST as createUser } from './route'
import { GET as readUser, PUT as editUser, DELETE as deleteUser } from './[id]/route'
import { PUT as setPassword } from './[id]/password/route'

const db = () => h.db as AccountDb
const ROOT = 'root-1'
const ACCOUNTS = [ROOT, 'admin-full', 'admin-m', 'admin-s', 'admin-um', 'admin-po', 'admin-low', 'member-1', 'member-2']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))
const MANAGER = [...builtinSet(FULL_ADMIN_PROFILE_ID)!.permissions, 'admins:manage']

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

async function answer(res: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', email: 'root@e2e.local', password: HASH[ROOT] },
    { id: 'admin-full', role: 'admin', email: 'full@e2e.local', password: HASH['admin-full'] },
    { id: 'admin-m', role: 'admin', email: 'm@e2e.local', password: HASH['admin-m'], adminProfileId: 'set-manager' },
    { id: 'admin-s', role: 'admin', email: 's@e2e.local', password: HASH['admin-s'], adminProfileId: 'set-manager' },
    { id: 'admin-um', role: 'admin', email: 'um@e2e.local', password: HASH['admin-um'], adminProfileId: 'builtin:user-manager' },
    { id: 'admin-po', role: 'admin', email: 'po@e2e.local', password: HASH['admin-po'], adminProfileId: 'builtin:platform-operator' },
    { id: 'admin-low', role: 'admin', email: 'low@e2e.local', password: HASH['admin-low'], adminProfileId: 'builtin:security-auditor' },
    { id: 'member-1', email: 'm1@e2e.local', password: HASH['member-1'] },
    { id: 'member-2', email: 'm2@e2e.local', password: HASH['member-2'], adminProfileId: 'builtin:security-auditor' },
  ])
  db().seedSet({ id: 'set-manager', kind: 'admin', name: 'Manager', permissions: MANAGER })
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
})

afterEach(() => {
  setFlagsForTests(null)
})

describe('each user route asks its permission (permissions switch on)', () => {
  test('a Platform operator lists only itself and reads no other account (users:read)', async () => {
    await as('admin-po')
    const rows = await (await listUsers(req('GET'))).json() as Array<{ id: string }>
    expect(rows.map((r) => r.id)).toEqual(['admin-po'])
    expect(await answer(await readUser(req('GET'), params('member-1'))))
      .toMatchObject({ status: 403, body: { code: 'forbidden', permission: 'users:read' } })
  })

  test('a User manager lists every account', async () => {
    await as('admin-um')
    const rows = await (await listUsers(req('GET'))).json() as Array<{ id: string }>
    expect(rows).toHaveLength(ACCOUNTS.length)
  })

  test('a Platform operator cannot create, edit, delete or set a password (403 naming each permission)', async () => {
    await as('admin-po')
    expect(await answer(await createUser(req('POST', { name: 'n', email: 'n@e2e.local' }))))
      .toMatchObject({ status: 403, body: { permission: 'users:create' } })
    expect(await answer(await editUser(req('PUT', { name: 'x' }), params('member-1'))))
      .toMatchObject({ status: 403, body: { permission: 'users:edit' } })
    expect(await answer(await deleteUser(req('DELETE'), params('member-1'))))
      .toMatchObject({ status: 403, body: { permission: 'users:delete' } })
    expect(await answer(await setPassword(req('PUT', { newPassword: 'a-long-enough-password-1', reason: 'r' }), params('member-1'))))
      .toMatchObject({ status: 403, body: { permission: 'users:reset_credentials' } })
    expect(db().account('member-1')!.name).not.toBe('x')
    expect(db().audit()).toEqual([])
  })

  test('a Platform operator still edits its own name, and cannot change its own role (users:edit)', async () => {
    await as('admin-po')
    expect((await editUser(req('PUT', { name: 'Po' }), params('admin-po'))).status).toBe(200)
    expect(await answer(await editUser(req('PUT', { role: 'standard' }), params('admin-po'))))
      .toMatchObject({ status: 403, body: { permission: 'users:edit' } })
    expect(db().account('admin-po')!.role).toBe('admin')
  })

  test('a User manager edits a member and creates one; a Security auditor neither', async () => {
    await as('admin-um')
    expect((await editUser(req('PUT', { name: 'Renamed' }), params('member-1'))).status).toBe(200)
    expect((await createUser(req('POST', { name: 'n', email: 'n@e2e.local' }))).status).toBe(201)
    await as('admin-low')
    expect((await editUser(req('PUT', { name: 'Again' }), params('member-1'))).status).toBe(403)
    expect(db().account('member-1')!.name).toBe('Renamed')
  })

  test('a member never holds a user administration permission, whatever is stored', async () => {
    await as('member-2')
    expect((await editUser(req('PUT', { name: 'x' }), params('member-1'))).status).toBe(403)
    const rows = await (await listUsers(req('GET'))).json() as Array<{ id: string }>
    expect(rows.map((r) => r.id)).toEqual(['member-2'])
  })
})

describe('admins:manage over a strict subset (D-02) on the account routes', () => {
  test('edits and demotes a Full admin with its own password, and the rows name it', async () => {
    await as('admin-m')
    expect((await answer(await editUser(req('PUT', { name: 'Fa' }), params('admin-full')))).body.code).toBe('step_up_required')
    expect((await answer(await editUser(req('PUT', { name: 'Fa', stepUpPassword: pw(ROOT) }), params('admin-full')))).body.code)
      .toBe('step_up_failed')
    expect((await editUser(req('PUT', { name: 'Fa', stepUpPassword: pw('admin-m') }), params('admin-full'))).status).toBe(200)
    expect(db().account('admin-full')!.name).toBe('Fa')
    const sv = Number(db().account('admin-full')!.sessionVersion)
    expect((await editUser(req('PUT', { role: 'standard', stepUpPassword: pw('admin-m') }), params('admin-full'))).status).toBe(200)
    expect(db().account('admin-full')!.role).toBe('standard')
    expect(db().account('admin-full')!.sessionVersion).toBe(sv + 1)
    expect(db().audit().map((a) => [a.action, a.actorId])).toEqual([
      ['user.update', 'admin-m'], ['user.role_changed', 'admin-m'],
    ])
  })

  test('promotes a member whose profile would sit inside its own', async () => {
    await as('admin-m')
    expect((await editUser(req('PUT', { role: 'admin', stepUpPassword: pw('admin-m') }), params('member-1'))).status).toBe(200)
    expect(db().account('member-1')!.role).toBe('admin')
  })

  test('deletes a Full admin with its own password', async () => {
    await as('admin-m')
    expect((await answer(await deleteUser(req('DELETE', {}), params('admin-full')))).body.code).toBe('step_up_required')
    expect((await deleteUser(req('DELETE', { stepUpPassword: pw('admin-m') }), params('admin-full'))).status).toBe(200)
    expect(db().account('admin-full')).toBeFalsy()
  })

  test('equal profiles cannot manage each other: 403 not_a_subset before any password', async () => {
    await as('admin-m')
    expect((await answer(await editUser(req('PUT', { name: 'x', stepUpPassword: 'wrong' }), params('admin-s')))).body.code).toBe('not_a_subset')
    expect((await answer(await deleteUser(req('DELETE', { stepUpPassword: 'wrong' }), params('admin-s')))).body.code).toBe('not_a_subset')
    expect(db().account('admin-s')).toBeTruthy()
  })

  test('a Full admin (no admins:manage) keeps Phase 2\'s root_only for another admin and a promotion', async () => {
    await as('admin-full')
    for (const res of [
      await editUser(req('PUT', { name: 'x', stepUpPassword: pw('admin-full') }), params('admin-m')),
      await editUser(req('PUT', { role: 'admin', stepUpPassword: pw('admin-full') }), params('member-1')),
      await deleteUser(req('DELETE', { stepUpPassword: pw('admin-full') }), params('admin-m')),
    ]) expect(await answer(res)).toMatchObject({ status: 403, body: { code: 'root_only' } })
    expect(db().account('member-1')!.role).toBe('standard')
  })

  test('nobody manages Root', async () => {
    await as('admin-m')
    expect((await answer(await editUser(req('PUT', { name: 'x', stepUpPassword: pw('admin-m') }), params(ROOT)))).body.code).toBe('root_protected')
  })

  test('Root keeps its path, with its own password', async () => {
    await as(ROOT)
    expect((await editUser(req('PUT', { name: 'Em', stepUpPassword: pw(ROOT) }), params('admin-m'))).status).toBe(200)
  })
})

describe('with the permissions switch off: every admin answers as before', () => {
  test('a Platform operator profile on record changes nothing: the admin lists, edits and creates', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-po')
    expect(await (await listUsers(req('GET'))).json()).toHaveLength(ACCOUNTS.length)
    expect((await editUser(req('PUT', { name: 'Renamed' }), params('member-1'))).status).toBe(200)
    expect((await createUser(req('POST', { name: 'n', email: 'n@e2e.local' }))).status).toBe(201)
    await as('member-1')
    expect((await editUser(req('PUT', { name: 'x' }), params('member-2'))).status).toBe(403)
  })

  test('another admin stays the confirmed Root\'s, admins:manage on record or not', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-m')
    expect((await answer(await editUser(req('PUT', { name: 'x', stepUpPassword: pw('admin-m') }), params('admin-full')))).body.code).toBe('root_only')
  })
})
