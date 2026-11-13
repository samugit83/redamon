/**
 * An account's device sessions on the admin console (step 6.10, GV-17): GET /api/users/[id]/sessions
 * lists them and DELETE /api/users/[id]/sessions/[sid] signs one browser out, for whoever may sign the
 * account out (users:revoke_sessions; on another admin the confirmed Root with Root's password, or an
 * admins:manage holder over a strict subset); nobody acts on Root's; the own account is My account's.
 * Admin revoke audited (`user.session_revoked`, by the admin, target the account); the account's other
 * browsers stay signed in. With RBAC_GOVERNANCE_ENABLED off both answer 404 and read nothing (DV-30).
 *
 * Real routes, session helpers, capability resolution and Root protections; the database is the
 * in-memory accountDb, the agent a fetch double.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/users/[id]/sessions/route.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'h'.repeat(64))
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

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearDeviceSessionCacheForTests } from '@/lib/authz/deviceSessions'
import { getSession } from '@/lib/session'
import { GET } from './route'
import { DELETE } from './[sid]/route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-13T12:00:00Z')
const LATER = new Date(T0.getTime() + 24 * 3600_000)
const GOVERNANCE = { identity: true, permissions: true, governance: true }
const ROOT_PASSWORD = 'root-step-up-pass'
const fetchMock = vi.fn()

const as = async (userId: string) => {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}
const device = (id: string, userId: string, over: Record<string, unknown> = {}) => db().seedSession({
  id, userId, sessionVersion: Number(db().account(userId)?.sessionVersion ?? 0), expiresAt: LATER, createdAt: T0,
  ip: '192.0.2.10', userAgent: 'Mozilla/5.0 (Macintosh) Safari/605.1.15', ...over,
})
function req(method: string, opts: { body?: unknown; origin?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test' }
  if (opts.origin) headers.origin = opts.origin
  if (opts.body !== undefined) headers['content-type'] = 'application/json'
  return new NextRequest('http://redamon.test/api/users/x/sessions', {
    method, headers, ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  })
}
const list = (id: string) => GET(req('GET'), { params: Promise.resolve({ id }) })
const revoke = (id: string, sid: string, opts: { body?: unknown; origin?: string } = {}) =>
  DELETE(req('DELETE', opts), { params: Promise.resolve({ id, sid }) })
async function answer(res: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}
const revokedRows = () => db().audit().filter((a) => a.action === 'user.session_revoked')
async function signedIn(userId: string, sid: string): Promise<boolean> {
  const before = h.jar.auth
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0), { sid })
  const session = await getSession()
  h.jar.auth = before
  return session !== null
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', password: bcrypt.hashSync(ROOT_PASSWORD, 4) },
    { id: 'admin-1', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-audit', role: 'admin', adminProfileId: 'builtin:security-auditor' },
    { id: 'member-1' },
    { id: 'member-2' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  device('m1-laptop', 'member-1')
  device('m1-phone', 'member-1', { lastSeenAt: new Date(T0.getTime() - 60_000) })
  device('m2-laptop', 'member-2')
  device('um-laptop', 'admin-um')
  device('root-laptop', 'root-1')
  setFlagsForTests(GOVERNANCE)
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  clearDeviceSessionCacheForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 1, stopped_runs: 0, by_kind: {} }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('GET /api/users/[id]/sessions', () => {
  test('a Full admin lists a member\'s sessions; none is current, no other account\'s row', async () => {
    await as('admin-1')
    const { status, body } = await answer(await list('member-1'))
    expect(status).toBe(200)
    const sessions = body.sessions as Array<Record<string, unknown>>
    expect(sessions.map((s) => [s.id, s.state, s.current])).toEqual([['m1-laptop', 'active', false], ['m1-phone', 'active', false]])
  })

  test('the User manager lists too (it holds users:revoke_sessions); the Security auditor does not', async () => {
    await as('admin-um')
    expect((await list('member-1')).status).toBe(200)
    await as('admin-audit')
    expect(await answer(await list('member-1'))).toEqual({
      status: 403, body: expect.objectContaining({ code: 'forbidden', permission: 'users:revoke_sessions' }),
    })
  })

  test('a member: 403 naming users:revoke_sessions', async () => {
    await as('member-2')
    expect(await answer(await list('member-1'))).toMatchObject({ status: 403, body: { code: 'forbidden', permission: 'users:revoke_sessions' } })
  })

  test('another admin\'s: Root\'s to read (a Full admin gets root_only); nobody reads Root\'s', async () => {
    await as('admin-1')
    expect(await answer(await list('admin-um'))).toMatchObject({ status: 403, body: { code: 'root_only' } })
    expect(await answer(await list('root-1'))).toMatchObject({ status: 403, body: { code: 'root_protected' } })
    await as('root-1')
    expect(await answer(await list('admin-um'))).toMatchObject({ status: 200, body: { sessions: [expect.objectContaining({ id: 'um-laptop' })] } })
  })

  test('the own account: 400 own_account (My account lists it); a missing account: 404', async () => {
    await as('admin-1')
    expect(await answer(await list('admin-1'))).toMatchObject({ status: 400, body: { code: 'own_account' } })
    expect(await answer(await list('nobody'))).toMatchObject({ status: 404, body: { code: 'user_not_found' } })
  })
})

describe('DELETE /api/users/[id]/sessions/[sid]', () => {
  test('admin revoke audited: by the admin, target the account; that browser refused, the other goes on', async () => {
    await as('admin-1')
    const { status, body } = await answer(await revoke('member-1', 'm1-phone'))
    expect(status).toBe(200)
    expect(body).toEqual({ id: 'm1-phone', changed: true, state: 'revoked', agent: { sockets: { closed: 1 } } })
    expect(revokedRows()).toEqual([expect.objectContaining({
      actorId: 'admin-1', action: 'user.session_revoked', targetType: 'user', targetId: 'member-1',
      after: { sessionId: 'm1-phone', by: 'admin' },
    })])
    expect(db().sessions().find((s) => s.id === 'm1-phone')).toMatchObject({ revokedAt: T0, revokedById: 'admin-1', endedBy: 'admin' })
    expect(await signedIn('member-1', 'm1-phone')).toBe(false)
    expect(await signedIn('member-1', 'm1-laptop')).toBe(true)
  })

  test('the admin and the member revoking the same session at once: one audit row', async () => {
    await as('admin-1')
    const first = revoke('member-1', 'm1-phone')
    const second = revoke('member-1', 'm1-phone')
    const bodies = await Promise.all([first, second].map(async (p) => (await answer(await p)).body))
    expect(bodies.map((b) => b.changed).sort()).toEqual([false, true])
    expect(revokedRows()).toHaveLength(1)
  })

  test('without users:revoke_sessions: 403, nothing changed', async () => {
    for (const who of ['admin-audit', 'member-2']) {
      await as(who)
      expect(await answer(await revoke('member-1', 'm1-phone'))).toMatchObject({ status: 403, body: { permission: 'users:revoke_sessions' } })
    }
    expect(db().sessions().find((s) => s.id === 'm1-phone')?.revokedAt).toBeNull()
  })

  test('another admin\'s session: a Full admin gets root_only; Root needs its password and then revokes', async () => {
    await as('admin-1')
    expect(await answer(await revoke('admin-um', 'um-laptop'))).toMatchObject({ status: 403, body: { code: 'root_only' } })
    await as('root-1')
    expect(await answer(await revoke('admin-um', 'um-laptop'))).toMatchObject({ status: 403, body: { code: 'step_up_required' } })
    expect(await answer(await revoke('admin-um', 'um-laptop', { body: { stepUpPassword: 'wrong-pass' } })))
      .toMatchObject({ status: 403, body: { code: 'step_up_failed' } })
    expect(db().sessions().find((s) => s.id === 'um-laptop')?.revokedAt).toBeNull()
    const ok = await answer(await revoke('admin-um', 'um-laptop', { body: { stepUpPassword: ROOT_PASSWORD } }))
    expect(ok).toMatchObject({ status: 200, body: { changed: true } })
    expect(revokedRows()).toEqual([expect.objectContaining({ actorId: 'root-1', targetId: 'admin-um' })])
  })

  test('Root\'s session: 403 root_protected, audited as an attempt, nothing changed', async () => {
    await as('admin-1')
    expect(await answer(await revoke('root-1', 'root-laptop'))).toMatchObject({ status: 403, body: { code: 'root_protected' } })
    expect(db().audit().filter((a) => a.action === 'rbac.root_protected_refused')).toEqual([
      expect.objectContaining({ actorId: 'admin-1', targetId: 'root-1', after: { attempted: 'revoke_sessions' } }),
    ])
    expect(db().sessions().find((s) => s.id === 'root-laptop')?.revokedAt).toBeNull()
  })

  test('the own account: 400 own_account; another account\'s session id, a missing or malformed one: 404', async () => {
    await as('admin-1')
    expect(await answer(await revoke('admin-1', 'm1-phone'))).toMatchObject({ status: 400, body: { code: 'own_account' } })
    for (const sid of ['m2-laptop', 'nope', 'a/b']) {
      expect(await answer(await revoke('member-1', sid))).toMatchObject({ status: 404, body: { code: 'session_not_found' } })
    }
    expect(db().sessions().every((s) => s.revokedAt === null)).toBe(true)
    expect(revokedRows()).toEqual([])
  })

  test('another origin: refused before anything is changed', async () => {
    await as('admin-1')
    expect((await revoke('member-1', 'm1-phone', { origin: 'https://evil.example' })).status).toBe(403)
    expect(db().sessions().find((s) => s.id === 'm1-phone')?.revokedAt).toBeNull()
  })

  test('a demotion applies at once: the next revoke reads the admin fresh', async () => {
    await as('admin-1')
    await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:security-auditor' } })
    expect((await revoke('member-1', 'm1-phone')).status).toBe(403)
  })
})

describe('switch off (DV-30)', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('%s: both routes answer 404 and read nothing', async (_name, flags) => {
    setFlagsForTests(flags)
    await as('admin-1')
    const reads = [vi.spyOn(db().user, 'findUnique'), vi.spyOn(db().userSession, 'findMany'), vi.spyOn(db().userSession, 'findFirst')]
    expect((await list('member-1')).status).toBe(404)
    expect((await revoke('member-1', 'm1-phone')).status).toBe(404)
    for (const read of reads) expect(read).not.toHaveBeenCalled()
  })
})
