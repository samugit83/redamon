/**
 * Every end of an admin's sessions also ends the impersonations it holds, with their end row (step
 * 3.14 review, finding 3; IM-11, AU-03): "sign out everywhere", the Root transfer (both accounts),
 * an admin disabled, signed out by Root, or deleted. Those paths clear or kill the act-as cookie
 * without passing through the request check that writes `invalidated`, and a disabled or deleted
 * admin never sends it again, so the impersonation would stay open in the log until its time ran
 * out. Now each open one ends `invalidated` (`expired` when its time had already run out), once; the
 * sockets close with the account's (`scope: 'account'`), a deleted admin's per impersonation. A log
 * that cannot be written never fails the revoke (logged). Switch off: no act-as row (Phase 2).
 *
 * Real routes and session helpers; the database is the in-memory accountDb; the agent is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

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
  teardownProject: async () => { throw new Error('the accounts here own no project') },
}))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import type { AccountDb } from './__testing__/accountDb'
import { closeAgentSockets } from '@/lib/agentSockets'
import { createActAsToken, createToken } from '@/lib/auth'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getEffectiveUser } from '@/lib/session'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { disableAccount, revokeSessions } from './accountStatus'
import { POST as revokeAll } from '@/app/api/auth/sessions/revoke-all/route'
import { POST as offerRoot } from '@/app/api/root/transfer/route'
import { POST as acceptRoot } from '@/app/api/root/transfer/accept/route'
import { DELETE as deleteUser } from '@/app/api/users/[id]/route'

const db = () => h.db as AccountDb
const close = vi.mocked(closeAgentSockets)
const fetchMock = vi.fn()
const ROOT = 'root-1'
const PW: Record<string, string> = { [ROOT]: 'root-own-passphrase-0001', 'admin-2': 'admin-two-passphrase-0002' }
const HASH = Object.fromEntries(Object.entries(PW).map(([id, pw]) => [id, bcrypt.hashSync(pw, 4)]))
const ROOT_SESSION = { userId: ROOT, role: 'admin' }

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method,
    headers: {
      host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json',
      ...(h.jar.actAs ? { cookie: `redamon-act-as=${h.jar.actAs}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

function nextRequest() {
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
}

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar = { auth: await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0)) }
}

/** An impersonation of `target` by `admin` that started a minute ago (`minutes` long); its cookie. */
async function acting(admin: string, target: string, minutes = 60, startedAgoMs = 60_000): Promise<string> {
  const id = `start-${admin}-${target}`
  db().seedActAs({ id, adminId: admin, targetUserId: target, event: 'start', createdAt: new Date(Date.now() - startedAgoMs), durationMinutes: minutes })
  return createActAsToken(admin, target, 3600, { asv: Number(db().account(admin)!.sessionVersion ?? 0), jti: id })
}

const endsOf = (adminId: string) => db().actAs().filter((r) => r.adminId === adminId && r.event === 'end')

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, role: 'admin', password: HASH[ROOT] },
    { id: 'admin-2', role: 'admin', password: HASH['admin-2'] },
    { id: 'admin-3', role: 'admin' },
    { id: 'member-1' },
    { id: 'member-2' },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-01T00:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  nextRequest()
  __resetThrottle()
  h.jar = {}
  close.mockClear()
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response('{"stopped":0}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('an admin\'s sessions end: the impersonations it holds end with them', () => {
  test('sign out everywhere: `invalidated`, once; the saved cookie acts as nobody after signing in again', async () => {
    const saved = await acting('admin-2', 'member-1')
    await signIn('admin-2')
    h.jar.actAs = saved
    expect((await revokeAll(req('POST', {}))).status).toBe(200)
    expect(endsOf('admin-2')).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'invalidated' })])
    await signIn('admin-2')
    h.jar.actAs = saved
    nextRequest()
    expect((await getEffectiveUser())?.userId).toBe('admin-2')
    expect(endsOf('admin-2')).toHaveLength(1)
  })

  test('sign out everywhere ends the impersonations of other browsers too', async () => {
    await acting('admin-2', 'member-1')
    await acting('admin-2', 'member-2')
    await signIn('admin-2')
    await revokeAll(req('POST', {}))
    expect(endsOf('admin-2').map((r) => [r.targetUserId, r.endedBy]).sort())
      .toEqual([['member-1', 'invalidated'], ['member-2', 'invalidated']])
  })

  test('the Root transfer: both accounts\' impersonations end', async () => {
    await acting(ROOT, 'member-1')
    await acting('admin-2', 'member-2')
    await signIn(ROOT)
    expect((await offerRoot(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }))).status).toBe(200)
    await signIn('admin-2')
    expect((await acceptRoot(req('POST', { stepUpPassword: PW['admin-2'] }))).status).toBe(200)
    expect(endsOf(ROOT)).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'invalidated' })])
    expect(endsOf('admin-2')).toEqual([expect.objectContaining({ targetUserId: 'member-2', endedBy: 'invalidated' })])
  })

  test('an admin disabled by Root: its impersonation ends; the sockets close with the account\'s', async () => {
    await acting('admin-2', 'member-1')
    expect((await disableAccount(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect(endsOf('admin-2')).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'invalidated' })])
    expect(close.mock.calls).toEqual([[expect.objectContaining({ userId: 'admin-2', scope: 'account' })]])
  })

  test('an admin signed out by Root: its impersonation ends', async () => {
    await acting('admin-2', 'member-1')
    expect((await revokeSessions(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect(endsOf('admin-2')).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'invalidated' })])
  })

  test('an admin deleted by Root: its impersonation ends and what it opened acting closes', async () => {
    await acting('admin-3', 'member-1')
    await signIn(ROOT)
    const res = await deleteUser(req('DELETE', { stepUpPassword: PW[ROOT] }), params('admin-3'))
    expect(res.status).toBe(200)
    expect(db().account('admin-3')).toBeUndefined()
    expect(endsOf('admin-3')).toEqual([expect.objectContaining({ targetUserId: 'member-1', endedBy: 'invalidated' })])
    expect(close.mock.calls).toEqual([[{ userId: 'member-1', actorId: 'admin-3', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'act_as' }]])
  })

  test('an impersonation whose time had already run out ends `expired`', async () => {
    await acting('admin-2', 'member-1', 30, 31 * 60_000)
    await revokeSessions(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })
    expect(endsOf('admin-2')).toEqual([expect.objectContaining({ endedBy: 'expired' })])
  })

  test('one already ended is left as it is; a member holds none', async () => {
    await acting('admin-2', 'member-1')
    db().seedActAs({ adminId: 'admin-2', targetUserId: 'member-1', event: 'end', createdAt: new Date(), endedBy: 'stopped' })
    await revokeSessions(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })
    await revokeSessions(req('POST', {}), ROOT_SESSION, 'member-2')
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([expect.objectContaining({ endedBy: 'stopped' })])
  })

  test('the act-as log cannot be written: the revoke still succeeds (logged)', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await acting('admin-2', 'member-1')
    vi.spyOn(db().actAsAudit, 'findMany').mockRejectedValue(Object.assign(new Error('down'), { code: 'P1001' }))
    expect((await revokeSessions(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })).status).toBe(200)
    expect(err.mock.calls.some(([l]) => String(l) === '[rbac] act-as end not recorded admin=admin-2 ended-by=invalidated code=P1001')).toBe(true)
  })
})

describe('switch off: Phase 2 behaviour', () => {
  test('sign out everywhere and an admin disabled write no act-as row', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await acting('admin-2', 'member-1')
    await signIn('admin-2')
    await revokeAll(req('POST', {}))
    await disableAccount(req('POST', {}), ROOT_SESSION, 'admin-2', { adminTarget: true })
    expect(db().actAs().filter((r) => r.event === 'end')).toEqual([])
  })
})
