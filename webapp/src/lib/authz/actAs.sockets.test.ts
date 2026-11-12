/**
 * An agent connection ends with the impersonation it was opened under (step 3.14 review, finding 2;
 * IM-11, DV-21): the agent checks a WebSocket ticket only when the socket opens, so when an
 * impersonation ends (Stop, a new act-as, sign-out, its time limit noticed, the admin's session
 * version or users:impersonate gone) the webapp asks the agent to close what that admin opened acting
 * as that account (`scope: 'act_as'`): the account's own sockets and runs, the admin's own and other
 * admins' stay. The close never fails the end, which is already written. A replayed copy of an ended
 * cookie ends nothing and closes nothing. Switch off: Phase 2 (nothing closed).
 *
 * Real routes, session helpers and tokens; the database is the in-memory accountDb; the agent's
 * POST /ws/close is the closeAgentSockets double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: (name: string) => { if (name === 'redamon-act-as') h.jar.actAs = undefined },
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  return { default: db, prisma: db }
})
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn() }))

import bcrypt from 'bcryptjs'
import { SignJWT } from 'jose'
import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { closeAgentSockets } from '@/lib/agentSockets'
import { createToken } from '@/lib/auth'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getEffectiveUser } from '@/lib/session'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { POST as logout } from '@/app/api/auth/logout/route'
import { POST, DELETE } from '@/app/api/auth/act-as/route'

const db = () => h.db as AccountDb
const close = vi.mocked(closeAgentSockets)
const PASSWORD = 'admin-one-passphrase'
const ALL_SOCKETS = ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']
const pairClose = (userId: string, actorId = 'admin-1') => ({ userId, actorId, kinds: ALL_SOCKETS, scope: 'act_as' })

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

function nextRequest() {
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
}

async function signIn(userId = 'admin-1') {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

async function actAs(targetUserId: string): Promise<string> {
  const res = await POST(req('/api/auth/act-as', 'POST', { targetUserId, reason: 'ticket #42', durationMinutes: 30, stepUpPassword: PASSWORD }))
  expect(res.status).toBe(200)
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as='))!
  h.jar.actAs = line.slice('redamon-act-as='.length).split(';')[0]
  return h.jar.actAs
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', password: bcrypt.hashSync(PASSWORD, 4) },
    { id: 'member-1' },
    { id: 'member-2' },
  ])
  db().seedInstance({
    rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    impersonationMaxMinutes: 720, impersonationNotifyTarget: false, adminSessionTtlHours: 12,
  })
  setFlagsForTests({ identity: true, permissions: true })
  nextRequest()
  __resetThrottle()
  h.jar = {}
  close.mockReset()
  close.mockResolvedValue({ ok: true, closed: 1, stoppedRuns: 0 })
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the sockets of the impersonation that ended close, and only those', () => {
  test('Stop closes what the admin opened acting as the account', async () => {
    await signIn()
    await actAs('member-1')
    expect(close).not.toHaveBeenCalled()
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })

  test('a new act-as closes the previous impersonation\'s sockets, not the new one\'s', async () => {
    await signIn()
    await actAs('member-1')
    await actAs('member-2')
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })

  test('sign-out closes them', async () => {
    await signIn()
    await actAs('member-1')
    await logout(req('/api/auth/logout', 'POST'))
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })

  test('its time limit, noticed on a request, closes them', async () => {
    await signIn()
    await actAs('member-1')
    setNowForTests(() => new Date(Date.now() + 31 * 60_000))
    // The browser still sends the cookie (its clock is behind): the token itself has expired.
    const startId = db().actAs().at(-1)!.id as string
    const iat = Math.floor(Date.now() / 1000) - 3600
    h.jar.actAs = await new SignJWT({ sub: 'admin-1', act: 'member-1', asv: 0, jti: startId }).setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(iat).setExpirationTime(iat + 1800).sign(new TextEncoder().encode('a'.repeat(64)))
    nextRequest()
    expect((await getEffectiveUser())?.userId).toBe('admin-1')
    expect(db().actAs().at(-1)).toMatchObject({ event: 'end', endedBy: 'expired' })
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })

  test('its time limit settled from the log at the next Stop closes them', async () => {
    db().seedActAs({ id: 'old-start', adminId: 'admin-1', targetUserId: 'member-2', event: 'start', createdAt: new Date('2026-11-12T09:00:00Z'), durationMinutes: 30 })
    setNowForTests(() => new Date('2026-11-12T09:31:00Z'))
    await signIn()
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(close.mock.calls).toEqual([[pairClose('member-2')]])
  })

  test('the admin losing users:impersonate (invalidated) closes them on the next request', async () => {
    await signIn()
    await actAs('member-1')
    await db().user.update({ where: { id: 'admin-1' }, data: { adminProfileId: 'builtin:user-manager' } })
    nextRequest()
    expect((await getEffectiveUser())?.userId).toBe('admin-1')
    expect(db().actAs().at(-1)).toMatchObject({ event: 'end', endedBy: 'invalidated' })
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })

  test('a replayed copy of an ended cookie closes nothing', async () => {
    await signIn()
    const saved = await actAs('member-1')
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    close.mockClear()
    h.jar.actAs = saved
    nextRequest()
    expect((await getEffectiveUser())?.userId).toBe('admin-1')
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(close).not.toHaveBeenCalled()
  })

  test('the agent unreachable: the Stop still ends it (the close logs its own failure)', async () => {
    close.mockResolvedValue({ ok: false, reason: 'agent_unreachable' })
    await signIn()
    await actAs('member-1')
    const res = await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(res.status).toBe(200)
    expect(db().actAs().at(-1)).toMatchObject({ event: 'end', endedBy: 'stopped' })
    expect(close).toHaveBeenCalledTimes(1)
  })

  test('the end row could not be written: the impersonation ends on the request and its sockets still close', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn()
    await actAs('member-1')
    await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    nextRequest()
    vi.spyOn(db(), '$transaction').mockRejectedValue(Object.assign(new Error('x'), { code: 'P1001' }))
    expect((await getEffectiveUser())?.userId).toBe('admin-1')
    expect(close.mock.calls).toEqual([[pairClose('member-1')]])
  })
})

describe('switch off: Phase 2 behaviour', () => {
  test('Stop closes nothing', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await signIn()
    const res = await POST(req('/api/auth/act-as', 'POST', { targetUserId: 'member-1' }))
    h.jar.actAs = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as='))!.slice('redamon-act-as='.length).split(';')[0]
    await DELETE(req('/api/auth/act-as', 'DELETE'))
    expect(close).not.toHaveBeenCalled()
  })
})
