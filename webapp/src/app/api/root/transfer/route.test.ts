/**
 * Root transfer (step 2.6, ID-07, ID-05, ID-25; feature document §4.4): the confirmed Root offers
 * Root to an admin with its own password (POST /api/root/transfer); the offer lasts 24 hours; the
 * admin accepts with its own password (POST /api/root/transfer/accept) or declines, and Root may
 * cancel (POST /api/root/transfer/cancel). Accepting moves Root, confirmed, `rootAssignedBy:
 * transfer`, raises both accounts' session versions (both sign in again; this browser's cookies
 * are cleared) and writes `root.transfer`, all in one transaction under the Root lock the boot and
 * the host take; the old Root stays a Full admin. GET tells Root and the recipient about a pending
 * offer, nobody else. With the identity switch off the routes do not exist.
 *
 * Real session helpers, tokens, bcrypt and step-up; the database is the in-memory accountDb
 * (transactions roll back, one at a time); the agent is a fetch double; the clock is injected.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/root/transfer/route.test.ts
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

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { ROOT_LOCK, clearInstanceRootCacheForTests, loadInstanceRoot } from '@/lib/authz/root'
import { setNowForTests } from '@/lib/authz/clock'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getSession } from '@/lib/session'
import { GET, POST as offer } from './route'
import { POST as accept } from './accept/route'
import { POST as cancel } from './cancel/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const ROOT = 'root-1'
const PW: Record<string, string> = { [ROOT]: 'root-own-passphrase-0001', 'admin-2': 'admin-two-passphrase-0002' }
const HASH = Object.fromEntries(Object.entries(PW).map(([id, pw]) => [id, bcrypt.hashSync(pw, 4)]))
const T0 = new Date('2026-11-12T10:00:00.000Z')
const DAY = 24 * 60 * 60 * 1000

function req(method: string, body?: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://redamon.test/api/root/transfer', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  })
}

async function signIn(userId: string) {
  const row = db().account(userId)!
  h.jar = { auth: await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0)) }
}

async function codeOf(res: Response): Promise<string | undefined> {
  return (await res.clone().json().catch(() => ({}))).code
}

const instance = () => db().instance()!
const actions = () => db().audit().map((r) => r.action)

/** Root offers Root to admin-2 (the happy path's first half). */
async function offered() {
  await signIn(ROOT)
  const res = await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }))
  expect(res.status).toBe(200)
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local', password: HASH[ROOT] },
    { id: 'admin-2', name: 'Pia', role: 'admin', email: 'adm2@e2e.local', password: HASH['admin-2'] },
    { id: 'admin-3', name: 'Ines', role: 'admin', email: 'adm3@e2e.local' },
    { id: 'admin-off', role: 'admin', status: 'disabled', password: '', passwordOnHold: '$2a$12$held' },
    { id: 'admin-nopw', role: 'admin', password: '' },
    { id: 'member-1', name: 'Marco', email: 'mem1@e2e.local' },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-01T00:00:00Z') })
  setFlagsForTests({ identity: true })
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string) => new Response(
    JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 1 } : { stopped: 0 }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('offering Root', () => {
  test('needs step-up: no password, or a wrong one, offers nothing', async () => {
    await signIn(ROOT)
    expect(await codeOf(await offer(req('POST', { targetUserId: 'admin-2' })))).toBe('step_up_required')
    expect(await codeOf(await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: 'wrong' })))).toBe('step_up_failed')
    expect(instance().pendingRootTransferTo).toBeNull()
    expect(db().audit()).toEqual([])
  })

  test('with its password: the offer lasts 24 hours and is audited in the same transaction', async () => {
    await signIn(ROOT)
    const res = await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ offered: true, toUserId: 'admin-2', expiresAt: new Date(T0.getTime() + DAY).toISOString() })
    expect(instance()).toMatchObject({ pendingRootTransferTo: 'admin-2', pendingRootTransferExpires: new Date(T0.getTime() + DAY), rootUserId: ROOT })
    expect(db().audit()).toMatchObject([{
      action: 'root.transfer_offered', actorId: ROOT, targetType: 'user', targetId: 'admin-2', source: 'api',
      after: { toUserId: 'admin-2', expiresAt: new Date(T0.getTime() + DAY).toISOString() },
    }])
    expect(JSON.stringify(db().audit())).not.toContain(PW[ROOT])
    expect(db().rawValues.map((v) => v[0])).toContain(ROOT_LOCK)
  })

  test('a new offer replaces the one pending', async () => {
    await offered()
    db().seedUsers([{ id: 'admin-5', role: 'admin', password: HASH['admin-2'] }])
    const res = await offer(req('POST', { targetUserId: 'admin-5', stepUpPassword: PW[ROOT] }))
    expect(res.status).toBe(200)
    expect(instance().pendingRootTransferTo).toBe('admin-5')
    expect(db().audit()[1]).toMatchObject({ action: 'root.transfer_offered', before: { toUserId: 'admin-2' } })
  })

  test.each([
    ['a member', 'member-1', 400, 'target_not_admin'],
    ['a disabled admin', 'admin-off', 400, 'target_cannot_sign_in'],
    ['a passwordless admin', 'admin-nopw', 400, 'target_cannot_sign_in'],
    ['Root itself', ROOT, 400, 'own_account'],
    ['nobody', 'rbac-no-such-account', 404, 'user_not_found'],
  ])('target must be an admin who can sign in: %s is refused before any password check', async (_n, target, status, code) => {
    await signIn(ROOT)
    const res = await offer(req('POST', { targetUserId: target, stepUpPassword: 'wrong' }))
    expect(res.status).toBe(status)
    expect(await codeOf(res)).toBe(code)
    // A 400/404, not step_up_failed: the target is checked before the password.
    expect(instance().pendingRootTransferTo).toBeNull()
  })

  test('a missing target is refused', async () => {
    await signIn(ROOT)
    expect(await codeOf(await offer(req('POST', { stepUpPassword: PW[ROOT] })))).toBe('target_required')
  })

  test('an admin, or an unconfirmed Root, cannot offer Root', async () => {
    await signIn('admin-2')
    const res = await offer(req('POST', { targetUserId: 'admin-3', stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(403)
    expect(await codeOf(res)).toBe('root_only')
    db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })
    await signIn(ROOT)
    const unconfirmed = await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }))
    expect(await codeOf(unconfirmed)).toBe('root_only')
    expect((await unconfirmed.json()).error).toMatch(/set-root/)
    expect(instance().pendingRootTransferTo).toBeNull()
  })

  test('a member is refused with the permission named', async () => {
    await signIn('member-1')
    const res = await offer(req('POST', { targetUserId: 'admin-2' }))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'root:transfer' })
  })

  test('cross-origin refused; not JSON 415; no session 401', async () => {
    await signIn(ROOT)
    expect((await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }, { origin: 'http://evil.test' }))).status).toBe(403)
    expect((await offer(req('POST', 'targetUserId=admin-2', { 'content-type': 'text/plain' }))).status).toBe(415)
    h.jar = {}
    expect((await offer(req('POST', { targetUserId: 'admin-2' }))).status).toBe(401)
    expect(instance().pendingRootTransferTo).toBeNull()
  })

  test('audit failure: no offer', async () => {
    db().failAudit('root.transfer_offered')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn(ROOT)
    expect((await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] }))).status).toBe(500)
    expect(instance().pendingRootTransferTo).toBeNull()
  })
})

describe('accepting', () => {
  test('accept moves Root and bumps both', async () => {
    await offered()
    const rootCookie = h.jar.auth!
    const before = await loadInstanceRoot()
    expect(before?.userId).toBe(ROOT)

    await signIn('admin-2')
    const pia = h.jar.auth!
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ transferred: true, rootUserId: 'admin-2', previousRootUserId: ROOT })
    expect(instance()).toMatchObject({
      rootUserId: 'admin-2', rootConfirmedAt: T0, rootAssignedBy: 'transfer',
      pendingRootTransferTo: null, pendingRootTransferExpires: null,
    })
    expect(db().account('admin-2')).toMatchObject({ role: 'admin', sessionVersion: 1 })
    expect(db().account(ROOT)).toMatchObject({ role: 'admin', sessionVersion: 1, adminProfileId: null })
    expect(db().audit().filter((r) => r.action === 'root.transfer')).toMatchObject([{
      actorId: 'admin-2', targetType: 'user', targetId: 'admin-2',
      before: { rootUserId: ROOT }, after: { rootUserId: 'admin-2', previousRootUserId: ROOT, rootAssignedBy: 'transfer' },
    }])
    expect(db().rawValues.map((v) => v[0]).filter((k) => k === ROOT_LOCK).length).toBeGreaterThanOrEqual(2)

    // This process sees the new Root at once (the cache was dropped).
    expect(await loadInstanceRoot()).toMatchObject({ userId: 'admin-2', confirmed: true, assignedBy: 'transfer' })
    // This browser signs in again: both cookies are cleared on the answer.
    const cleared = res.headers.getSetCookie().join('\n')
    expect(cleared).toMatch(/redamon-auth=;/)
    expect(cleared).toMatch(/redamon-act-as=;/)
    // Both accounts' old cookies sign nobody in.
    clearPrincipalCacheForTests()
    for (const cookie of [rootCookie, pia]) {
      h.jar = { auth: cookie }
      expect(await getSession()).toBeNull()
    }
    // Their open sockets close (scope account), each account's.
    const closes = fetchMock.mock.calls.filter((c) => String(c[0]).endsWith('/ws/close')).map((c) => JSON.parse(String(c[1].body)))
    expect(closes.map((b) => b.user_id).sort()).toEqual(['admin-2', ROOT])
    expect(closes.every((b) => b.scope === 'account')).toBe(true)
  })

  test('the new Root holds the powers, the old one does not', async () => {
    await offered()
    await signIn('admin-2')
    await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    await signIn(ROOT)
    expect(await codeOf(await offer(req('POST', { targetUserId: 'admin-3', stepUpPassword: PW[ROOT] })))).toBe('root_only')
    await signIn('admin-2')
    expect((await offer(req('POST', { targetUserId: ROOT, stepUpPassword: PW['admin-2'] }))).status).toBe(200)
  })

  test('needs step-up: the recipient proves its own password', async () => {
    await offered()
    await signIn('admin-2')
    expect(await codeOf(await accept(req('POST', {})))).toBe('step_up_required')
    expect(await codeOf(await accept(req('POST', { stepUpPassword: PW[ROOT] })))).toBe('step_up_failed')
    expect(instance().rootUserId).toBe(ROOT)
  })

  test('expired offer refused', async () => {
    await offered()
    setNowForTests(() => new Date(T0.getTime() + DAY + 1))
    await signIn('admin-2')
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(409)
    expect(await codeOf(res)).toBe('transfer_expired')
    expect(instance().rootUserId).toBe(ROOT)
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
  })

  test('no offer for this account: 409, before any password check', async () => {
    await offered()
    await signIn('admin-3')
    const res = await accept(req('POST', { stepUpPassword: 'wrong' }))
    expect(res.status).toBe(409)
    expect(await codeOf(res)).toBe('no_transfer_offer')
    expect(instance()).toMatchObject({ rootUserId: ROOT, pendingRootTransferTo: 'admin-2' })
  })

  test('two accepts → one transfer', async () => {
    await offered()
    await signIn('admin-2')
    const [a, b] = await Promise.all([
      accept(req('POST', { stepUpPassword: PW['admin-2'] })),
      accept(req('POST', { stepUpPassword: PW['admin-2'] })),
    ])
    // The second finds no offer left (409), or its cookie already ended by the first (403).
    const statuses = [a.status, b.status].sort()
    expect(statuses[0]).toBe(200)
    expect([403, 409]).toContain(statuses[1])
    expect(actions().filter((x) => x === 'root.transfer')).toHaveLength(1)
    expect(db().account('admin-2')!.sessionVersion).toBe(1)
    expect(db().account(ROOT)!.sessionVersion).toBe(1)
  })

  test('the offer withdrawn between the check and the write: 409, nothing moved, nobody signed out', async () => {
    await offered()
    await signIn('admin-2')
    const original = db().$transaction
    const cancelledFirst = async (fn: Parameters<AccountDb['$transaction']>[0]) => {
      await db().instanceSettings.update({ where: { id: 'instance' }, data: { pendingRootTransferTo: null, pendingRootTransferExpires: null } })
      return original(fn)
    }
    vi.spyOn(db(), '$transaction').mockImplementationOnce(cancelledFirst as never)
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(409)
    expect(await codeOf(res)).toBe('no_transfer_offer')
    expect(instance().rootUserId).toBe(ROOT)
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
    expect(actions()).not.toContain('root.transfer')
  })

  test('the recipient lost the admin role meanwhile: refused, Root unchanged', async () => {
    await offered()
    await signIn('admin-2')
    const pia = h.jar.auth!
    await db().user.update({ where: { id: 'admin-2' }, data: { role: 'standard' } })
    clearPrincipalCacheForTests()
    h.jar = { auth: pia }
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(403)
    expect(instance().rootUserId).toBe(ROOT)
  })

  test('the host moved Root meanwhile (set-root clears the offer): nothing to accept', async () => {
    await offered()
    db().seedInstance({ rootUserId: 'admin-3', rootAssignedBy: 'host', rootConfirmedAt: T0 })
    await signIn('admin-2')
    expect(await codeOf(await accept(req('POST', { stepUpPassword: PW['admin-2'] })))).toBe('no_transfer_offer')
    expect(instance().rootUserId).toBe('admin-3')
  })

  test('audit failure: Root stays, nobody is signed out', async () => {
    await offered()
    db().failAudit('root.transfer')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-2')
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(500)
    expect(instance()).toMatchObject({ rootUserId: ROOT, pendingRootTransferTo: 'admin-2' })
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
    expect(db().account(ROOT)!.sessionVersion).toBe(0)
    expect(res.headers.getSetCookie().join('\n')).not.toMatch(/redamon-auth=;/)
  })

  test('the agent unreachable: Root moved anyway, the failure reported', async () => {
    await offered()
    fetchMock.mockImplementation(async () => { throw new TypeError('fetch failed') })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-2')
    const res = await accept(req('POST', { stepUpPassword: PW['admin-2'] }))
    expect(res.status).toBe(200)
    expect(instance().rootUserId).toBe('admin-2')
    expect((await res.json()).agent).toMatchObject({ recipient: { sockets: { error: expect.any(String) } } })
  })
})

describe('declining and cancelling', () => {
  test('decline and cancel audited', async () => {
    await offered()
    await signIn('admin-2')
    const declined = await cancel(req('POST', {}))
    expect(declined.status).toBe(200)
    expect(await declined.json()).toEqual({ withdrawn: true, by: 'recipient' })
    expect(instance()).toMatchObject({ rootUserId: ROOT, pendingRootTransferTo: null, pendingRootTransferExpires: null })
    expect(db().audit()[1]).toMatchObject({ action: 'root.transfer_declined', actorId: 'admin-2', targetId: 'admin-2', before: { toUserId: 'admin-2' } })

    await offered()
    const cancelled = await cancel(req('POST', {}))
    expect(await cancelled.json()).toEqual({ withdrawn: true, by: 'root' })
    expect(instance().pendingRootTransferTo).toBeNull()
    expect(db().audit()[3]).toMatchObject({ action: 'root.transfer_cancelled', actorId: ROOT, targetId: 'admin-2', before: { toUserId: 'admin-2' } })
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
  })

  test('cancelling twice changes nothing the second time', async () => {
    await offered()
    expect((await (await cancel(req('POST', {}))).json()).withdrawn).toBe(true)
    const again = await cancel(req('POST', {}))
    expect(again.status).toBe(200)
    expect(await again.json()).toEqual({ withdrawn: false })
    expect(actions().filter((a) => a === 'root.transfer_cancelled')).toHaveLength(1)
  })

  test('another admin has nothing to withdraw', async () => {
    await offered()
    await signIn('admin-3')
    expect(await codeOf(await cancel(req('POST', {})))).toBe('no_transfer_offer')
    expect(instance().pendingRootTransferTo).toBe('admin-2')
  })

  test('a cancelled offer can no longer be accepted', async () => {
    await offered()
    await cancel(req('POST', {}))
    await signIn('admin-2')
    expect(await codeOf(await accept(req('POST', { stepUpPassword: PW['admin-2'] })))).toBe('no_transfer_offer')
  })
})

describe('GET: who learns about a pending offer', () => {
  test('Root and the recipient; nobody else; an expired one is no offer', async () => {
    await offered()
    const expiresAt = new Date(T0.getTime() + DAY).toISOString()
    expect(await (await GET(req('GET'))).json()).toEqual({
      offer: { toUserId: 'admin-2', toEmail: 'adm2@e2e.local', fromEmail: 'root@e2e.local', expiresAt, forYou: false },
    })
    await signIn('admin-2')
    expect((await (await GET(req('GET'))).json()).offer).toMatchObject({ forYou: true, fromEmail: 'root@e2e.local' })
    await signIn('admin-3')
    expect(await (await GET(req('GET'))).json()).toEqual({ offer: null })
    await signIn('admin-2')
    setNowForTests(() => new Date(T0.getTime() + DAY + 1))
    expect(await (await GET(req('GET'))).json()).toEqual({ offer: null })
  })

  test('a member is refused', async () => {
    await signIn('member-1')
    expect((await GET(req('GET'))).status).toBe(403)
  })
})

describe('switch off: the routes do not exist', () => {
  test('404 before any check, nothing read', async () => {
    setFlagsForTests({ identity: false })
    const read = vi.spyOn(db().instanceSettings, 'findUnique')
    await signIn(ROOT)
    for (const res of [
      await GET(req('GET')),
      await offer(req('POST', { targetUserId: 'admin-2', stepUpPassword: PW[ROOT] })),
      await accept(req('POST', { stepUpPassword: PW[ROOT] })),
      await cancel(req('POST', {})),
    ]) expect(res.status).toBe(404)
    expect(read).not.toHaveBeenCalled()
  })
})
