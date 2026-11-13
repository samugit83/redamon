/**
 * getSession and device sessions (step 6.10, GV-17). With RBAC_GOVERNANCE_ENABLED on, a login token
 * naming a device session (`sid`) is accepted only while that row is live: a revoked or unknown row
 * refuses it (cookie cleared, so the browser goes to /login), a token without `sid` stays valid. An
 * impersonation started from a device session acts only beside that browser's login, so revoking the
 * device ends it there for good (end row `invalidated`, act-as cookie cleared) and it never resumes
 * after the next sign-in. With the switch off nothing of this is read or checked (DV-30).
 *
 * Real session helpers, act-as log and capability resolution; the database is the in-memory accountDb.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/session.deviceSessions.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'e'.repeat(64))

const h = vi.hoisted(() => ({
  db: null as unknown,
  jar: {} as { auth?: string; actAs?: string },
  deleted: [] as string[],
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: (name: string) => { h.deleted.push(name) },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('./authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import type { AccountDb } from './authz/__testing__/accountDb'
import { createToken } from './auth'
import { setFlagsForTests } from './authz/flags'
import { setNowForTests } from './authz/clock'
import { clearPrincipalCacheForTests } from './authz/principal'
import { clearInstanceRootCacheForTests } from './authz/root'
import { clearCapabilityCachesForTests } from './authz/capabilities'
import { clearDeviceSessionCacheForTests, sessionDeviceId } from './authz/deviceSessions'
import { startImpersonation } from './authz/actAs'
import { getAuthzIdentity, getSession } from './session'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-13T12:00:00Z')
const LATER = new Date(T0.getTime() + 24 * 3600_000)
const GOVERNANCE = { identity: true, permissions: true, governance: true }

const login = async (userId: string, sid?: string) => {
  const row = db().account(userId)!
  return createToken(userId, String(row.role), Number(row.sessionVersion ?? 0), sid ? { sid } : {})
}
const device = (id: string, userId: string, over: Record<string, unknown> = {}) =>
  db().seedSession({ id, userId, sessionVersion: Number(db().account(userId)?.sessionVersion ?? 0), expiresAt: LATER, createdAt: T0, ...over })

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'root-1', role: 'admin' }, { id: 'admin-1', role: 'admin' }, { id: 'member-1' }])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests(GOVERNANCE)
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  clearDeviceSessionCacheForTests()
  h.jar = {}
  h.deleted = []
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('revoked sid refused', () => {
  test('a live device session signs in, and the session object names it', async () => {
    device('sess-a', 'member-1')
    h.jar.auth = await login('member-1', 'sess-a')
    const session = await getSession()
    expect(session).toEqual({ userId: 'member-1', role: 'standard' })
    expect(sessionDeviceId(session!)).toBe('sess-a')
    expect(h.deleted).toEqual([])
  })

  test('a revoked one is refused and its cookie cleared; the account\'s other browser goes on', async () => {
    device('sess-a', 'member-1', { revokedAt: T0, endedBy: 'admin' })
    device('sess-b', 'member-1')
    h.jar.auth = await login('member-1', 'sess-a')
    expect(await getSession()).toBeNull()
    expect(h.deleted).toEqual(['redamon-auth'])
    h.jar.auth = await login('member-1', 'sess-b')
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })

  test('a row that is gone, or another account\'s, is refused', async () => {
    device('sess-other', 'admin-1')
    for (const sid of ['sess-404', 'sess-other']) {
      h.jar.auth = await login('member-1', sid)
      expect(await getSession()).toBeNull()
    }
  })

  test('old token without sid valid (signed before the switch, the Playwright helper\'s)', async () => {
    h.jar.auth = await login('member-1')
    const session = await getSession()
    expect(session).toEqual({ userId: 'member-1', role: 'standard' })
    expect(sessionDeviceId(session!)).toBeNull()
  })

  test('the session version still decides first: a live row under an old version is refused', async () => {
    device('sess-a', 'member-1')
    h.jar.auth = await login('member-1', 'sess-a')
    await db().user.update({ where: { id: 'member-1' }, data: { sessionVersion: { increment: 1 } } })
    clearPrincipalCacheForTests()
    expect(await getSession()).toBeNull()
  })

  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('switch off (%s): a revoked sid is ignored and no device session is read', async (_name, flags) => {
    setFlagsForTests(flags)
    device('sess-a', 'member-1', { revokedAt: T0 })
    const reads = vi.spyOn(db().userSession, 'findUnique')
    h.jar.auth = await login('member-1', 'sess-a')
    const session = await getSession()
    expect(session).toEqual({ userId: 'member-1', role: 'standard' })
    expect(sessionDeviceId(session!)).toBeNull()
    expect(reads).not.toHaveBeenCalled()
  })
})

describe('the act-as chain follows the device session', () => {
  async function actAsFrom(sid: string | null): Promise<string> {
    return startImpersonation({
      admin: { id: 'admin-1', sessionVersion: 0 }, targetUserId: 'member-1', seconds: 3600, reason: 'ticket 7',
      durationMinutes: 60, presentedToken: null, deviceSessionId: sid,
    })
  }
  const ends = () => db().actAs().filter((r) => r.event === 'end')

  test('started from this browser: the admin acts as the member here', async () => {
    device('sess-l', 'admin-1')
    h.jar = { auth: await login('admin-1', 'sess-l'), actAs: await actAsFrom('sess-l') }
    const identity = await getAuthzIdentity()
    expect(identity?.actingAs?.id).toBe('member-1')
    expect(ends()).toEqual([])
  })

  test('the same act-as cookie beside another login of the admin ends (invalidated) and is cleared', async () => {
    device('sess-l', 'admin-1')
    device('sess-p', 'admin-1')
    h.jar = { auth: await login('admin-1', 'sess-p'), actAs: await actAsFrom('sess-l') }
    const identity = await getAuthzIdentity()
    expect(identity?.session.userId).toBe('admin-1')
    expect(identity?.actingAs).toBeNull()
    expect(ends()).toEqual([expect.objectContaining({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'invalidated' })])
    expect(h.deleted).toContain('redamon-act-as')
  })

  test('the device revoked: its next request is refused, the impersonation ends there and both cookies are cleared', async () => {
    device('sess-l', 'admin-1', { revokedAt: T0, endedBy: 'self' })
    h.jar = { auth: await login('admin-1', 'sess-l'), actAs: await actAsFrom('sess-l') }
    expect(await getSession()).toBeNull()
    expect(ends()).toEqual([expect.objectContaining({ endedBy: 'invalidated' })])
    expect(h.deleted.sort()).toEqual(['redamon-act-as', 'redamon-auth'])
  })

  test('signing in again on that browser never resumes it, even if the old act-as cookie stayed', async () => {
    device('sess-l', 'admin-1', { revokedAt: T0, endedBy: 'self' })
    device('sess-l2', 'admin-1')
    const stale = await actAsFrom('sess-l')
    h.jar = { auth: await login('admin-1', 'sess-l2'), actAs: stale }
    expect((await getAuthzIdentity())?.actingAs).toBeNull()
  })

  test('a failed end row at the refusal is logged; the refusal stands', async () => {
    device('sess-l', 'admin-1', { revokedAt: T0 })
    h.jar = { auth: await login('admin-1', 'sess-l'), actAs: await actAsFrom('sess-l') }
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db().actAsAudit, 'create').mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    expect(await getSession()).toBeNull()
    expect(error).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] act-as end not recorded at a revoked device session code=/))
  })

  test('switch off: an act-as token naming a device session acts beside any login of the admin', async () => {
    device('sess-l', 'admin-1')
    const token = await actAsFrom('sess-l')
    setFlagsForTests({ identity: true, permissions: true })
    h.jar = { auth: await login('admin-1'), actAs: token }
    expect((await getAuthzIdentity())?.actingAs?.id).toBe('member-1')
  })

  test('an act-as token from before device sessions (no sid) keeps acting beside a device login', async () => {
    device('sess-l', 'admin-1')
    h.jar = { auth: await login('admin-1', 'sess-l'), actAs: await actAsFrom(null) }
    expect((await getAuthzIdentity())?.actingAs?.id).toBe('member-1')
  })
})
