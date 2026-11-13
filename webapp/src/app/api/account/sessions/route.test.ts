/**
 * My account → Sessions (step 6.10, GV-17, UI-09): GET /api/account/sessions lists the signed-in
 * account's device sessions, DELETE /api/account/sessions/[sid] signs one browser out. Revoking one
 * leaves the others; the revoked browser is refused at its next request; the revoke is audited
 * (`user.session_revoked`, the session id and never its address or browser) and closes the sockets
 * the account opened; a second revoke, or two at once, change nothing more (one audit row); revoking
 * the browser asking is a sign-out (cookies cleared, its impersonation ended `logout`). The agent down
 * never undoes a revoke (`[rbac] socket-close failed`); a failed audit row does (fail closed). With
 * RBAC_GOVERNANCE_ENABLED off both routes answer 404 and read nothing (DV-30).
 *
 * Real routes, session helpers and act-as log; the database is the in-memory accountDb, the agent a
 * fetch double.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/account/sessions/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'g'.repeat(64))
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

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearDeviceSessionCacheForTests } from '@/lib/authz/deviceSessions'
import { startImpersonation } from '@/lib/authz/actAs'
import { getSession } from '@/lib/session'
import { GET } from './route'
import { DELETE } from './[sid]/route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-13T12:00:00Z')
const LATER = new Date(T0.getTime() + 24 * 3600_000)
const GOVERNANCE = { identity: true, permissions: true, governance: true }
const fetchMock = vi.fn()

const cookieFor = async (userId: string, sid?: string) => {
  const row = db().account(userId)!
  return createToken(userId, String(row.role), Number(row.sessionVersion ?? 0), sid ? { sid } : {})
}
const device = (id: string, userId: string, over: Record<string, unknown> = {}) => db().seedSession({
  id, userId, sessionVersion: Number(db().account(userId)?.sessionVersion ?? 0), expiresAt: LATER, createdAt: T0,
  ip: '198.51.100.4', userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0', ...over,
})
function req(method: string, opts: { origin?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test' }
  if (opts.origin) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/account/sessions', { method, headers })
}
const revoke = (sid: string, opts: { origin?: string; cookie?: string } = {}) =>
  DELETE(req('DELETE', opts), { params: Promise.resolve({ sid }) })
async function body(res: Response): Promise<Record<string, unknown>> {
  return await res.json().catch(() => ({})) as Record<string, unknown>
}
const closes = () => fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/ws/close'))
  .map(([, init]) => JSON.parse(String((init as RequestInit).body)))
const revokedRows = () => db().audit().filter((a) => a.action === 'user.session_revoked')
/** Whether the browser holding `sid` is still signed in, as its next request would find. */
async function signedIn(userId: string, sid: string): Promise<boolean> {
  const before = h.jar.auth
  h.jar.auth = await cookieFor(userId, sid)
  const session = await getSession()
  h.jar.auth = before
  return session !== null
}

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'root-1', role: 'admin' }, { id: 'admin-1', role: 'admin' }, { id: 'member-1' }, { id: 'member-2' }])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  device('sess-a', 'member-1')
  device('sess-b', 'member-1', { lastSeenAt: new Date(T0.getTime() - 60_000), createdAt: new Date(T0.getTime() - 3600_000) })
  device('sess-x', 'member-2')
  setFlagsForTests(GOVERNANCE)
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  clearDeviceSessionCacheForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 2, stopped_runs: 0, by_kind: {} }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('GET /api/account/sessions', () => {
  test('the account\'s own sessions, this browser first and marked current; never another account\'s', async () => {
    device('sess-old', 'member-1', { revokedAt: T0, endedBy: 'sign_out', lastSeenAt: new Date(T0.getTime() - 7200_000) })
    h.jar.auth = await cookieFor('member-1', 'sess-b')
    const res = await GET()
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const { sessions } = await body(res) as { sessions: Array<Record<string, unknown>> }
    expect(sessions.map((s) => [s.id, s.state, s.current])).toEqual([
      ['sess-b', 'active', true], ['sess-a', 'active', false], ['sess-old', 'signed_out', false],
    ])
    expect(sessions[0]).toEqual({
      id: 'sess-b', createdAt: new Date(T0.getTime() - 3600_000).toISOString(), lastSeenAt: new Date(T0.getTime() - 60_000).toISOString(),
      expiresAt: LATER.toISOString(), ip: '198.51.100.4', ipTrusted: false, userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0',
      state: 'active', revokedAt: null, current: true,
    })
  })

  test('a token without sid lists every session, none current', async () => {
    h.jar.auth = await cookieFor('member-1')
    const { sessions } = await body(await GET()) as { sessions: Array<Record<string, unknown>> }
    expect(sessions.map((s) => s.current)).toEqual([false, false])
  })

  test('signed out: 401', async () => {
    expect((await GET()).status).toBe(401)
  })
})

describe('DELETE /api/account/sessions/[sid]', () => {
  test('revoke one leaves the others: that browser is refused at its next request, this one goes on', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const res = await revoke('sess-b')
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ id: 'sess-b', changed: true, state: 'revoked', agent: { sockets: { closed: 2 } } })
    expect(res.headers.getSetCookie()).toEqual([])
    expect(await signedIn('member-1', 'sess-b')).toBe(false)
    expect(await signedIn('member-1', 'sess-a')).toBe(true)
    expect(db().sessions().find((s) => s.id === 'sess-b')).toMatchObject({ revokedAt: T0, revokedById: 'member-1', endedBy: 'self' })
  })

  test('audited user.session_revoked with the session id, never its address or browser', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    await revoke('sess-b')
    expect(revokedRows()).toEqual([expect.objectContaining({
      actorId: 'member-1', action: 'user.session_revoked', targetType: 'user', targetId: 'member-1',
      after: { sessionId: 'sess-b', by: 'self' },
    })])
    expect(JSON.stringify(db().audit())).not.toMatch(/198\.51\.100\.4|Chrome/)
  })

  test('its sockets close: the ones the account opened itself (scope access), every kind', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    await revoke('sess-b')
    expect(closes()).toEqual([{ user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'access' }])
  })

  test('double revoke: the second changes nothing, writes no row and closes nothing', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    await revoke('sess-b')
    const again = await revoke('sess-b')
    expect(again.status).toBe(200)
    expect(await body(again)).toEqual({ id: 'sess-b', changed: false, state: 'revoked' })
    expect(revokedRows()).toHaveLength(1)
    expect(closes()).toHaveLength(1)
  })

  test('two revokes at once: one changes it, one audit row', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const answers = await Promise.all([revoke('sess-b'), revoke('sess-b')].map(async (p) => body(await p)))
    expect(answers.map((a) => a.changed).sort()).toEqual([false, true])
    expect(revokedRows()).toHaveLength(1)
  })

  test('revoke of the current session is a sign-out: both cookies cleared, its next request refused', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const res = await revoke('sess-a')
    expect(res.status).toBe(200)
    expect(await body(res)).toMatchObject({ id: 'sess-a', changed: true, state: 'revoked' })
    const cleared = res.headers.getSetCookie()
    expect(cleared.some((c) => c.startsWith('redamon-auth=;') && /Max-Age=0/.test(c))).toBe(true)
    expect(cleared.some((c) => c.startsWith('redamon-act-as=;') && /Max-Age=0/.test(c))).toBe(true)
    expect(revokedRows()[0].after).toEqual({ sessionId: 'sess-a', by: 'self', current: true })
    expect(await signedIn('member-1', 'sess-a')).toBe(false)
    expect(await signedIn('member-1', 'sess-b')).toBe(true)
  })

  test('an admin revoking the browser it acts from: the impersonation ends as at sign-out', async () => {
    device('sess-adm', 'admin-1')
    const actAs = await startImpersonation({
      admin: { id: 'admin-1', sessionVersion: 0 }, targetUserId: 'member-1', seconds: 3600, reason: 'ticket 9',
      durationMinutes: 60, presentedToken: null, deviceSessionId: 'sess-adm',
    })
    h.jar = { auth: await cookieFor('admin-1', 'sess-adm'), actAs }
    const res = await revoke('sess-adm', { cookie: `redamon-act-as=${actAs}` })
    expect(res.status).toBe(200)
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([expect.objectContaining({ adminId: 'admin-1', endedBy: 'logout' })])
    // The real signed-in account revoked its own session, recorded as acting as the member.
    expect(revokedRows()[0]).toMatchObject({ actorId: 'admin-1', targetId: 'admin-1' })
  })

  test('the agent unreachable: the revoke still lands and logs [rbac] socket-close failed', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock.mockImplementation(async () => { throw new TypeError('fetch failed') })
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const res = await revoke('sess-b')
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ id: 'sess-b', changed: true, state: 'revoked', agent: { sockets: { error: 'agent_unreachable' } } })
    expect(error).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] socket-close failed user=member-1 .*agent_unreachable/))
    expect(await signedIn('member-1', 'sess-b')).toBe(false)
  })

  test('the audit row cannot be written: 500, the session stays live (fail closed)', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    db().failAudit('user.session_revoked')
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const res = await revoke('sess-b')
    expect(res.status).toBe(500)
    expect(db().sessions().find((s) => s.id === 'sess-b')?.revokedAt).toBeNull()
    expect(await signedIn('member-1', 'sess-b')).toBe(true)
    expect(closes()).toEqual([])
  })

  test('a session already ended by sign out everywhere, or expired: nothing changes, no row', async () => {
    device('sess-v', 'member-1', { sessionVersion: -1 })
    device('sess-e', 'member-1', { expiresAt: T0 })
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    expect(await body(await revoke('sess-v'))).toEqual({ id: 'sess-v', changed: false, state: 'ended' })
    expect(await body(await revoke('sess-e'))).toEqual({ id: 'sess-e', changed: false, state: 'expired' })
    expect(revokedRows()).toEqual([])
  })

  test('another account\'s session, a missing one or a malformed id: 404 session_not_found, nothing changed', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    for (const sid of ['sess-x', 'sess-404', '../sess-x']) {
      const res = await revoke(sid)
      expect(res.status).toBe(404)
      expect(await body(res)).toMatchObject({ code: 'session_not_found' })
    }
    expect(db().sessions().find((s) => s.id === 'sess-x')?.revokedAt).toBeNull()
    expect(revokedRows()).toEqual([])
  })

  test('another origin: refused, nothing changed', async () => {
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const res = await revoke('sess-b', { origin: 'https://evil.example' })
    expect(res.status).toBe(403)
    expect(db().sessions().find((s) => s.id === 'sess-b')?.revokedAt).toBeNull()
  })

  test('signed out, or a refused browser: 401', async () => {
    expect((await revoke('sess-b')).status).toBe(401)
    h.jar.auth = await cookieFor('member-1', 'sess-b')
    await db().userSession.updateMany({ where: { id: 'sess-b' }, data: { revokedAt: T0 } })
    expect((await revoke('sess-a')).status).toBe(401)
  })
})

describe('switch off (DV-30)', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('%s: both routes answer 404, reading neither the session nor a device session', async (_name, flags) => {
    setFlagsForTests(flags)
    h.jar.auth = await cookieFor('member-1', 'sess-a')
    const reads = [vi.spyOn(db().user, 'findUnique'), vi.spyOn(db().userSession, 'findMany'), vi.spyOn(db().userSession, 'findFirst')]
    expect((await GET()).status).toBe(404)
    expect((await revoke('sess-b')).status).toBe(404)
    for (const read of reads) expect(read).not.toHaveBeenCalled()
    expect(db().sessions().find((s) => s.id === 'sess-b')?.revokedAt).toBeNull()
  })
})
