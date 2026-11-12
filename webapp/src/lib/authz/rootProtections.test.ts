/**
 * Root is protected (step 2.5, ID-04, ID-06, ID-10; feature document §4.4): with the identity
 * switch on, no other account demotes, edits, disables, enables, deletes, resets the password
 * of, signs out or acts as Root. Each attempt answers 403 `root_protected`, changes nothing
 * and writes a `rbac.root_protected_refused` row. The refusal comes right after the target is
 * known, before any step-up, teardown or write; Root is read fresh for it. Root itself keeps
 * today's answers (its self-deletion is the 400 every account gets) and keeps the admin role
 * until it transfers Root. An unconfirmed Root has every protection. With the switch off the
 * routes answer exactly as after Phase 1 and the instance row is never read.
 *
 * Real session helpers, tokens and step-up; the database is the in-memory accountDb
 * (transactions roll back); the agent and the project teardown are doubles that must not run.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/rootProtections.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})
vi.mock('@/lib/projectTeardown', () => ({
  teardownProject: async () => { throw new Error('a refused deletion must tear nothing down') },
}))
// The case-insensitive address check is raw SQL the in-memory database does not answer; no
// address here is taken.
vi.mock('@/lib/authz/accountEmail', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/accountEmail')>()),
  emailTakenByAnother: async () => false,
}))

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests, loadInstanceRoot } from './root'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getEffectiveUser } from '@/lib/session'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { PUT as resetPassword } from '@/app/api/users/[id]/password/route'
import { POST as disableUser } from '@/app/api/users/[id]/disable/route'
import { POST as enableUser } from '@/app/api/users/[id]/enable/route'
import { POST as revokeUserSessions } from '@/app/api/users/[id]/revoke-sessions/route'
import { POST as startActAs } from '@/app/api/auth/act-as/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const REFUSED = 'rbac.root_protected_refused'

/** The audit row reads the act-as cookie from the request, the session helpers from next/headers: both carry it. */
function req(method: string, body?: unknown): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json' }
  if (h.jar.actAs) headers.cookie = `redamon-act-as=${h.jar.actAs}`
  return new NextRequest('http://redamon.test/api/x', {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

type Attempt = { name: string; attempted: string; call: () => Promise<Response>; unchanged: () => void }

/** Every action on Root, as `admin-2` (or whoever is signed in) would send it; none carries a step-up password. */
const ATTEMPTS: Attempt[] = [
  {
    name: 'demote', attempted: 'role_change',
    call: () => editUser(req('PUT', { role: 'standard' }), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)!.role).toBe('admin'),
  },
  {
    name: 'edit the name or the sign-in address', attempted: 'edit',
    call: () => editUser(req('PUT', { name: 'Taken over', email: 'attacker@e2e.local' }), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)).toMatchObject({ name: 'Root', email: 'root@e2e.local' }),
  },
  {
    name: 'delete', attempted: 'delete',
    call: () => deleteUser(req('DELETE', {}), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)).toBeDefined(),
  },
  {
    name: 'reset the password', attempted: 'reset_password',
    call: () => resetPassword(req('PUT', { newPassword: 'a-brand-new-password-0001' }), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)!.password).toBe('$2a$12$hash-of-root-1'),
  },
  {
    name: 'disable', attempted: 'disable',
    call: () => disableUser(req('POST', {}), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)).toMatchObject({ status: 'active', password: '$2a$12$hash-of-root-1' }),
  },
  {
    name: 'enable', attempted: 'enable',
    call: () => enableUser(req('POST', {}), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)!.status).toBe('active'),
  },
  {
    name: 'sign out everywhere', attempted: 'revoke_sessions',
    call: () => revokeUserSessions(req('POST', {}), params(ROOT)),
    unchanged: () => expect(db().account(ROOT)!.sessionVersion).toBe(0),
  },
  {
    name: 'act as', attempted: 'act_as',
    call: () => startActAs(req('POST', { targetUserId: ROOT })),
    unchanged: () => undefined,
  },
]

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local' },
    { id: 'admin-2', role: 'admin', email: 'adm2@e2e.local' },
    { id: 'member-1' },
  ])
  db().seedToken({ id: 'tok-root', userId: ROOT })
  // The automatic choice of the boot backfill: unconfirmed.
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => { throw new Error('a refused action must not reach the agent') })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

async function expectRefused(a: Attempt, actor: string, onBehalfOf?: string) {
  const res = await a.call()
  expect(res.status).toBe(403)
  const body = await res.json()
  expect(body.code).toBe('root_protected')
  expect(body.error).toMatch(/Root/)
  expect(res.headers.get('set-cookie') ?? '').not.toContain('redamon-act-as=ey')
  a.unchanged()
  expect(db().account(ROOT)).toMatchObject({ role: 'admin', status: 'active', sessionVersion: 0 })
  expect(db().tokens().find((t) => t.id === 'tok-root')!.revokedAt).toBeNull()
  const rows = db().audit()
  expect(rows).toHaveLength(1)
  expect(rows[0]).toMatchObject({
    action: REFUSED, actorId: actor, targetType: 'user', targetId: ROOT, source: 'api',
    after: { attempted: a.attempted, ...(onBehalfOf ? { actingAsUserId: onBehalfOf } : {}) },
  })
  if (onBehalfOf) expect(rows[0].onBehalfOfUserId).toBe(onBehalfOf)
  else expect(rows[0]).not.toHaveProperty('onBehalfOfUserId')
  expect(fetchMock).not.toHaveBeenCalled()
}

describe('an admin acting on Root: refused with root_protected, before any step-up', () => {
  for (const a of ATTEMPTS) {
    test(`${a.name}: admin actor`, async () => {
      await signIn('admin-2')
      await expectRefused(a, 'admin-2')
    })
    test(`${a.name}: an admin acting as a member`, async () => {
      await signIn('admin-2', 'member-1')
      await expectRefused(a, 'admin-2', 'member-1')
    })
  }

  test('confirmed or unconfirmed, Root has the protections (an unconfirmed Root lacks only the Root-only powers)', async () => {
    expect(await loadInstanceRoot()).toMatchObject({ userId: ROOT, confirmed: false })
    await signIn('admin-2')
    expect((await ATTEMPTS[0].call()).status).toBe(403)
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date() })
    expect((await ATTEMPTS[0].call()).status).toBe(403)
    expect(db().audit()).toHaveLength(2)
  })

  test('Root is read fresh: a Root recorded after this process cached "no Root" is protected at once', async () => {
    db().seedInstance(null)
    expect(await loadInstanceRoot()).toBeNull()
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })
    await signIn('admin-2')
    const res = await startActAs(req('POST', { targetUserId: ROOT }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_protected')
  })

  test('a failed refusal row does not let the action through', async () => {
    db().failAudit(REFUSED)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-2')
    const res = await deleteUser(req('DELETE', {}), params(ROOT))
    expect(res.status).toBe(403)
    expect(db().account(ROOT)).toBeDefined()
  })

  test('a member gets the answer it always got (no Root lookup, no row)', async () => {
    await signIn('member-1')
    expect((await editUser(req('PUT', { role: 'standard' }), params(ROOT))).status).toBe(403)
    expect((await resetPassword(req('PUT', { newPassword: 'a-brand-new-password-0001' }), params(ROOT))).status).toBe(403)
    expect(db().audit()).toEqual([])
  })
})

describe('Root on its own account', () => {
  test('root self-delete 400 as for everyone', async () => {
    await signIn(ROOT)
    const res = await deleteUser(req('DELETE', {}), params(ROOT))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'Cannot delete your own account' })
    expect(db().audit()).toEqual([])
  })

  test('Root keeps the admin role until it transfers Root: its own demotion is refused', async () => {
    await signIn(ROOT)
    const res = await editUser(req('PUT', { role: 'standard' }), params(ROOT))
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.code).toBe('root_protected')
    expect(body.error).toMatch(/transfer Root/i)
    expect(db().account(ROOT)!.role).toBe('admin')
    expect(db().audit()).toMatchObject([{ action: REFUSED, actorId: ROOT, targetId: ROOT, after: { attempted: 'role_change' } }])
  })

  test('Root edits its own name as anyone does', async () => {
    await signIn(ROOT)
    const res = await editUser(req('PUT', { name: 'Root Renamed' }), params(ROOT))
    expect(res.status).toBe(200)
    expect(db().account(ROOT)!.name).toBe('Root Renamed')
  })
})

describe('only the account the row names, while it is an admin, is Root', () => {
  // Step 2.6 (PE-08, by design): acting as an admin became the confirmed Root's power, so
  // with no Root the answer is root_only instead of Phase 1's step-up; still no protection.
  test('a Root id that names no account protects nobody: no root_protected, no refusal row', async () => {
    db().seedInstance({ rootUserId: 'gone', rootAssignedBy: 'automatic' })
    await signIn('admin-2')
    const res = await startActAs(req('POST', { targetUserId: ROOT }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_only')
    expect(db().audit()).toEqual([])
  })

  test('the last-admin guard counts Root: another admin may demote itself while Root remains', async () => {
    await signIn('admin-2')
    const res = await editUser(req('PUT', { role: 'standard' }), params('admin-2'))
    expect(res.status).toBe(200)
    expect(db().account('admin-2')!.role).toBe('standard')
  })

  test('a member target is no Root: an admin disables it as before', async () => {
    fetchMock.mockImplementation(async (url: string) => new Response(
      JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 0 } : { stopped: 0 }), { status: 200 }))
    await signIn('admin-2')
    const res = await disableUser(req('POST', {}), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().account('member-1')!.status).toBe('disabled')
  })
})

describe('an act-as cookie naming Root (minted before Root was protected) acts for nobody', () => {
  test('switch on: the admin is its own effective user', async () => {
    await signIn('admin-2', ROOT)
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-2' })
  })

  test('switch on: a cookie naming another admin, not Root, still works', async () => {
    db().seedUsers([{ id: 'admin-3', role: 'admin' }])
    await signIn('admin-2', 'admin-3')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-3' })
  })

  test('switch off: Phase 1, the cookie acts', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-2', ROOT)
    expect(await getEffectiveUser()).toEqual({ userId: ROOT })
  })
})

describe('switch off: Phase 1 answers, the instance row never read', () => {
  const PHASE1: Record<string, { status: number; code?: string }> = {
    demote: { status: 403, code: 'step_up_required' },
    'edit the name or the sign-in address': { status: 200 },
    delete: { status: 403, code: 'step_up_required' },
    'reset the password': { status: 403, code: 'step_up_required' },
    disable: { status: 404 },
    enable: { status: 403, code: 'step_up_required' },
    'sign out everywhere': { status: 404 },
    'act as': { status: 403, code: 'step_up_required' },
  }
  for (const a of ATTEMPTS) {
    test(`${a.name}: ${PHASE1[a.name].status}${PHASE1[a.name].code ? ` ${PHASE1[a.name].code}` : ''}`, async () => {
      setFlagsForTests({ identity: false })
      const read = vi.spyOn(db().instanceSettings, 'findUnique')
      await signIn('admin-2')
      const res = await a.call()
      expect(res.status).toBe(PHASE1[a.name].status)
      if (PHASE1[a.name].code) expect((await res.json()).code).toBe(PHASE1[a.name].code)
      expect(read).not.toHaveBeenCalled()
      expect(db().audit().filter((r) => r.action === REFUSED)).toEqual([])
    })
  }
})
