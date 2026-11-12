/**
 * A saved act-as cookie replayed after its impersonation ended acts as nobody (step 3.14 review,
 * finding 1; IM-05, IM-11). With RBAC_PERMISSIONS_ENABLED on the token names its start row (`jti`)
 * and acts only while that row is the latest of its admin and account in the act-as log: a Stop, a
 * sign-out, a new act-as (of anyone, the same account included) write the end, so every copy of the
 * cookie stops at once, with no start row, reason, step-up or notice of its own. The previous
 * impersonation's end and the new one's start are written together or not at all, so a failed start
 * leaves the log and the old cookie agreeing. A replay writes nothing and ends nothing.
 *
 * Real routes, session helpers, tokens and step-up; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string }, cleared: 0 }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: (name: string) => {
      if (name !== 'redamon-act-as') return
      h.cleared++
      h.jar.actAs = undefined
    },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import bcrypt from 'bcryptjs'
import { SignJWT } from 'jose'
import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getEffectiveUser } from '@/lib/session'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { POST as logout } from '../logout/route'
import { POST, DELETE } from './route'

const db = () => h.db as AccountDb
const PASSWORD = 'admin-one-passphrase'

function req(path: string, method: 'POST' | 'DELETE', body?: unknown): NextRequest {
  return new NextRequest(`http://redamon.test${path}`, {
    method,
    headers: {
      host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json',
      ...(h.jar.actAs ? { cookie: `redamon-act-as=${h.jar.actAs}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}

async function signIn(userId = 'admin-1') {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

/** What the next request reads (the caches another copy keeps are not this test's subject). */
function nextRequest() {
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
}

/** Acts as `targetUserId` the way the dialog does; returns the cookie the browser was given. */
async function actAs(targetUserId: string): Promise<{ status: number; token: string | null }> {
  const res = await POST(req('/api/auth/act-as', 'POST', { targetUserId, reason: 'ticket #42', durationMinutes: 30, stepUpPassword: PASSWORD }))
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as=')) ?? null
  const token = line ? line.slice('redamon-act-as='.length).split(';')[0] || null : null
  if (res.status === 200) h.jar.actAs = token ?? undefined
  return { status: res.status, token }
}

/** Who the next request runs as when the browser sends `token` (a saved copy, replayed). */
async function replay(token: string | null): Promise<string | undefined> {
  nextRequest()
  h.jar.actAs = token ?? undefined
  return (await getEffectiveUser())?.userId
}

const rows = () => db().actAs()
const ends = () => rows().filter((r) => r.event === 'end')

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', password: bcrypt.hashSync(PASSWORD, 4), sessionVersion: 1 },
    { id: 'member-1', name: 'Marco' },
    { id: 'member-2', name: 'Giulia' },
  ])
  db().seedInstance({
    rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: false, adminSessionTtlHours: 12,
  })
  setFlagsForTests({ identity: true, permissions: true })
  nextRequest()
  __resetThrottle()
  h.jar = {}
  h.cleared = 0
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('a saved cookie replayed after the impersonation ended acts as nobody', () => {
  test('after Stop: the replay runs as the admin, writes nothing, and is cleared', async () => {
    await signIn()
    const saved = (await actAs('member-1')).token
    expect(await replay(saved)).toBe('member-1')
    expect((await DELETE(req('/api/auth/act-as', 'DELETE'))).status).toBe(200)
    const logged = rows().length
    expect(await replay(saved)).toBe('admin-1')
    expect(rows()).toHaveLength(logged)
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'stopped' })])
    expect(h.cleared).toBe(1)
  })

  test('after sign-out and a new sign-in (the session version does not move)', async () => {
    await signIn()
    const saved = (await actAs('member-1')).token
    expect((await logout(req('/api/auth/logout', 'POST'))).status).toBe(200)
    expect(db().account('admin-1')!.sessionVersion).toBe(1)
    await signIn()
    expect(await replay(saved)).toBe('admin-1')
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'logout' })])
  })

  test('after a new act-as of someone else: the old cookie is refused, the new one acts', async () => {
    await signIn()
    const first = (await actAs('member-1')).token
    const second = (await actAs('member-2')).token
    expect(await replay(first)).toBe('admin-1')
    expect(await replay(second)).toBe('member-2')
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'stopped' })])
  })

  test('after a new act-as of the same account: only the newest cookie acts, and the replay ends nothing', async () => {
    await signIn()
    const first = (await actAs('member-1')).token
    const second = (await actAs('member-1')).token
    expect(first).not.toEqual(second)
    expect(await replay(first)).toBe('admin-1')
    expect(await replay(second)).toBe('member-1')
    expect(rows().map((r) => r.event)).toEqual(['start', 'end', 'start'])
  })

  test('an impersonation of the same account open in another browser ends when a new one starts', async () => {
    await signIn()
    const otherBrowser = (await actAs('member-1')).token
    h.jar.actAs = undefined
    const thisBrowser = (await actAs('member-1')).token
    expect(await replay(otherBrowser)).toBe('admin-1')
    expect(await replay(thisBrowser)).toBe('member-1')
    expect(ends()).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'stopped' })])
  })

  test('a Stop sent with a stale copy leaves the current impersonation running', async () => {
    await signIn()
    const first = (await actAs('member-1')).token
    const second = (await actAs('member-1')).token
    h.jar.actAs = first ?? undefined
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(await replay(second)).toBe('member-1')
    expect(ends()).toHaveLength(1)
  })
})

describe('a failed start: the end and the start are written together or not at all', () => {
  test('the new start fails: 500, no end row for the previous, which still acts (log and cookie agree)', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn()
    const saved = (await actAs('member-1')).token
    const create = db().actAsAudit.create
    vi.spyOn(db().actAsAudit, 'create').mockImplementation(async (a: { data: Record<string, unknown> }) => {
      if (a.data.event === 'start') throw Object.assign(new Error('gone'), { code: 'P1001' })
      return create(a)
    })
    const r = await actAs('member-2')
    expect(r.status).toBe(500)
    expect(r.token).toBeNull()
    expect(ends()).toEqual([])
    expect(rows().filter((x) => x.targetUserId === 'member-2')).toEqual([])
    vi.mocked(db().actAsAudit.create).mockRestore()
    expect(await replay(saved)).toBe('member-1')
  })
})

describe('fail closed', () => {
  test('a token signed under the rule whose start row is not in the log acts as nobody', async () => {
    await signIn()
    const forged = await new SignJWT({ sub: 'admin-1', act: 'member-1', asv: 1, jti: 'no-such-start' })
      .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('30m')
      .sign(new TextEncoder().encode('f'.repeat(64)))
    expect(await replay(forged)).toBe('admin-1')
    expect(rows()).toEqual([])
  })

  test('the log cannot be read: the request fails, it never runs as the account', async () => {
    await signIn()
    const saved = (await actAs('member-1')).token
    vi.spyOn(db().actAsAudit, 'findFirst').mockRejectedValue(Object.assign(new Error('down'), { code: 'P1001' }))
    nextRequest()
    h.jar.actAs = saved ?? undefined
    await expect(getEffectiveUser()).rejects.toThrow()
  })

  test('a request that acts reads the log once (DV-25)', async () => {
    await signIn()
    const saved = (await actAs('member-1')).token
    nextRequest()
    const reads = vi.spyOn(db().actAsAudit, 'findFirst')
    h.jar.actAs = saved ?? undefined
    expect((await getEffectiveUser())?.userId).toBe('member-1')
    expect(reads).toHaveBeenCalledTimes(1)
  })
})

describe('switch off: Phase 2 behaviour', () => {
  test('a cookie replayed after Stop still acts until its own expiry, as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await signIn()
    const res = await POST(req('/api/auth/act-as', 'POST', { targetUserId: 'member-1' }))
    const saved = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as='))!.slice('redamon-act-as='.length).split(';')[0]
    h.jar.actAs = saved
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(await replay(saved)).toBe('member-1')
  })
})
