/**
 * POST /api/users/[id]/reset-credentials (step 2.10, ID-18, ID-19, PE-12 behaviour, DV-11): an
 * admin resets a member's credentials, the confirmed Root an admin's (with its own password),
 * nobody Root's. Either a reset link (the password is emptied, so the account signs in only
 * through the link) or a temporary password the person must change. Both raise the session
 * version (every login cookie ends), revoke the MCP tokens, cancel the account's open links and
 * leave a notice for the person, with `user.credentials_reset`, in one transaction; then the
 * account's sockets close. A reset is takeover-equivalent, so it is visible: an account that has
 * signed in before needs a reason, which the person reads in the notice.
 *
 * Real session helpers, tokens, bcrypt and step-up; the database is the in-memory accountDb; the
 * agent is a fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'
import { createHash } from 'node:crypto'

vi.stubEnv('AUTH_SECRET', 'r'.repeat(64))
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
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { setNowForTests } from '@/lib/authz/clock'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getSession } from '@/lib/session'
import { resetCredentials } from '@/lib/authz/resetCredentials'
import { POST } from './route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const NOW = new Date('2026-11-12T12:00:00Z')
const PW = { root: 'root-own-passphrase-0001', admin: 'admin-own-passphrase-0001' }
const TEMP = 'Temporary-orchid-paddle-42'

function req(body: unknown = {}, opts: { origin?: string; contentType?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/users/x/reset-credentials', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const cookieOf = async (userId: string) => {
  const a = db().account(userId)!
  return createToken(userId, String(a.role), Number(a.sessionVersion ?? 0))
}
async function signIn(userId: string) {
  h.jar = { auth: await cookieOf(userId) }
}
const tokenOf = (link: string) => link.split('/invite/')[1]
const sha256 = (t: string) => createHash('sha256').update(t).digest('hex')

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', name: 'Rita', role: 'admin', email: 'rita@e2e.local', password: bcrypt.hashSync(PW.root, 4) },
    { id: 'admin-1', name: 'Laura', role: 'admin', email: 'laura@e2e.local', password: bcrypt.hashSync(PW.admin, 4) },
    { id: 'admin-2', name: 'Ines', role: 'admin' },
    { id: 'member-1', name: 'Marco' },
    { id: 'member-2', name: 'Pia' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-01T00:00:00Z'), publicBaseUrl: 'https://redamon.example.com', resetTtlHours: 4 })
  db().seedToken({ id: 'tok-1', userId: 'member-1' })
  db().seedToken({ id: 'tok-2', userId: 'member-2' })
  setFlagsForTests({ identity: true })
  setNowForTests(() => NOW)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
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

describe('link mode', () => {
  test('link mode empties the password and returns a link', async () => {
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('member-1'))
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    const body = await res.json()
    expect(body).toEqual({
      id: 'member-1', mode: 'link', link: expect.stringMatching(/^https:\/\/redamon\.example\.com\/invite\/[A-Za-z0-9_-]{43}$/),
      expiresAt: '2026-11-12T16:00:00.000Z', localhostWarning: false, tokensRevoked: 1, agent: { sockets: { closed: 2 } },
    })
    expect(db().account('member-1')).toMatchObject({ password: '', status: 'active', mustChangePassword: false, sessionVersion: 1 })
    // The link is stored only as the hash of its token, made by this admin.
    expect(db().invites()).toEqual([expect.objectContaining({
      userId: 'member-1', kind: 'reset', tokenHash: sha256(tokenOf(body.link)), createdById: 'admin-1', usedAt: null, cancelledAt: null,
    })])
  })

  test('the account no longer signs in with its old password (passwordless until the link is used)', async () => {
    db().seedUsers([{ id: 'member-3', password: bcrypt.hashSync('old-password-of-m3', 4) }])
    await signIn('admin-1')
    await POST(req({ mode: 'link' }), params('member-3'))
    expect(db().account('member-3')!.password).toBe('')
  })
})

describe('temporary mode', () => {
  test('temporary mode sets must-change', async () => {
    await signIn('admin-1')
    const res = await POST(req({ mode: 'temporary', temporaryPassword: TEMP }), params('member-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      id: 'member-1', mode: 'temporary', mustChangePassword: true, tokensRevoked: 1, agent: { sockets: { closed: 2 } },
    })
    const account = db().account('member-1')!
    expect(account).toMatchObject({ status: 'active', mustChangePassword: true, sessionVersion: 1 })
    expect(bcrypt.compareSync(TEMP, String(account.password))).toBe(true)
    expect(db().invites()).toEqual([])
  })

  test('the temporary password meets the policy in force, judged on the account\'s address', async () => {
    await signIn('admin-1')
    for (const [temporaryPassword, code] of [['short', 'password_too_short'], ['password1234', 'password_common'], ['member-1@e2e.local', 'password_is_email']]) {
      const res = await POST(req({ mode: 'temporary', temporaryPassword }), params('member-1'))
      expect(res.status, temporaryPassword).toBe(400)
      expect((await res.json()).code).toBe(code)
    }
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(db().audit()).toEqual([])
  })

  test('a disabled account takes a temporary password and stays disabled; a link needs an active one', async () => {
    db().seedUsers([{ id: 'member-3', status: 'disabled', password: '', passwordOnHold: '$2a$12$held' }])
    await signIn('admin-1')
    const link = await POST(req({ mode: 'link' }), params('member-3'))
    expect(link.status).toBe(409)
    expect(await link.json()).toMatchObject({ code: 'not_active' })
    const temp = await POST(req({ mode: 'temporary', temporaryPassword: TEMP }), params('member-3'))
    expect(temp.status).toBe(200)
    expect(db().account('member-3')).toMatchObject({ status: 'disabled', passwordOnHold: '$2a$12$held', mustChangePassword: true, sessionVersion: 1 })
  })
})

describe('both modes', () => {
  test.each(['link', 'temporary'] as const)('sv bumped and tokens revoked (%s)', async (mode) => {
    const old = await cookieOf('member-1')
    await signIn('admin-1')
    const res = await POST(req(mode === 'link' ? { mode } : { mode, temporaryPassword: TEMP }), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().tokens().map((t) => [t.id, t.revokedAt instanceof Date])).toEqual([['tok-1', true], ['tok-2', false]])
    h.jar = { auth: old }
    expect(await getSession()).toBeNull()
  })

  test.each(['link', 'temporary'] as const)("the account's open links are cancelled (%s)", async (mode) => {
    db().seedInvite({ id: 'old-reset', userId: 'member-1', kind: 'reset', tokenHash: 'h1', expiresAt: new Date('2026-11-12T13:00:00Z') })
    db().seedInvite({ id: 'other', userId: 'member-2', kind: 'reset', tokenHash: 'h2', expiresAt: new Date('2026-11-12T13:00:00Z') })
    await signIn('admin-1')
    await POST(req(mode === 'link' ? { mode } : { mode, temporaryPassword: TEMP }), params('member-1'))
    const byId = Object.fromEntries(db().invites().map((v) => [v.id, v]))
    expect(byId['old-reset'].cancelledAt).toEqual(NOW)
    expect(byId.other.cancelledAt).toBeNull()
    expect(db().audit()[0].after).toMatchObject({ cancelledLinks: 1 })
  })

  test('the reset, the notice and its audit row commit together; no token, link or hash in the row', async () => {
    db().seedUsers([{ id: 'member-3', lastLoginAt: new Date('2026-11-10T08:00:00Z') }])
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link', reason: '  Locked out after a holiday  ' }), params('member-3'))
    const { link } = await res.json()
    expect(db().transactions).toBe(1)
    const [row] = db().audit()
    expect(row).toMatchObject({
      actorId: 'admin-1', action: 'user.credentials_reset', targetType: 'user', targetId: 'member-3', source: 'api',
      after: {
        mode: 'link', mustChangePassword: false, sessionVersion: 1, revokedMcpTokens: 0, cancelledLinks: 0,
        reason: 'Locked out after a holiday', expiresAt: '2026-11-12T16:00:00.000Z',
      },
    })
    const text = JSON.stringify(row)
    for (const secret of [link, tokenOf(link), sha256(tokenOf(link)), '$2a$']) expect(text).not.toContain(secret)
    expect(db().invites()[0].reason).toBe('Locked out after a holiday')
  })

  test('a notice joins the account\'s pending notices: who, when, why, how', async () => {
    db().seedUsers([{ id: 'member-3', lastLoginAt: new Date('2026-11-10T08:00:00Z') }])
    await signIn('admin-1')
    await POST(req({ mode: 'temporary', temporaryPassword: TEMP, reason: 'Asked by phone' }), params('member-3'))
    expect(db().account('member-3')!.pendingNotices).toEqual([{
      id: expect.any(String), type: 'credentials_reset', at: NOW.toISOString(),
      by: { id: 'admin-1', name: 'Laura', email: 'laura@e2e.local' }, reason: 'Asked by phone', mode: 'temporary',
    }])
  })

  test('the same reset twice: two links, the first cancelled, the version raised twice, two notices', async () => {
    await signIn('admin-1')
    const first = await (await POST(req({ mode: 'link' }), params('member-1'))).json()
    h.jar = { auth: await cookieOf('admin-1') }
    const second = await (await POST(req({ mode: 'link' }), params('member-1'))).json()
    expect(second.link).not.toBe(first.link)
    const links = db().invites()
    expect(links.map((v) => v.cancelledAt === null)).toEqual([false, true])
    expect(db().account('member-1')!.sessionVersion).toBe(2)
    expect(db().account('member-1')!.pendingNotices).toHaveLength(2)
    expect(db().audit()).toHaveLength(2)
  })

  test('every socket of the four kinds closes, the acting ones too; no run is stopped by name', async () => {
    await signIn('admin-1')
    await POST(req({ mode: 'link' }), params('member-1'))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('http://agent.test:8080/ws/close')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({
      user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'account',
    })
  })

  test('agent unreachable: still reset, the failure reported and logged', async () => {
    fetchMock.mockImplementation(async () => { throw new TypeError('fetch failed') })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('member-1'))
    expect(res.status).toBe(200)
    expect((await res.json()).agent).toEqual({ sockets: { error: 'agent_unreachable' } })
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(err.mock.calls.some((c) => String(c[0]).startsWith('[rbac] socket-close failed user=member-1 '))).toBe(true)
  })

  test('audit failure → nothing changed', async () => {
    db().failAudit('user.credentials_reset')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    db().seedInvite({ id: 'old-reset', userId: 'member-1', kind: 'reset', tokenHash: 'h1', expiresAt: new Date('2026-11-12T13:00:00Z') })
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('member-1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not reset the credentials', code: 'internal_error' })
    // The log line names the code only: a database error may quote a token hash or a password hash.
    expect(err).toHaveBeenCalledWith('[rbac] credentials reset failed code=internal_error')
    expect(db().account('member-1')).toMatchObject({ password: '$2a$12$hash-of-member-1', sessionVersion: 0, pendingNotices: [] })
    expect(db().tokens()[0].revokedAt).toBeNull()
    expect(db().invites()).toEqual([expect.objectContaining({ id: 'old-reset', cancelledAt: null })])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('an admin acting as someone: the real admin is the actor and the author of the notice', async () => {
    h.jar = { auth: await cookieOf('admin-1'), actAs: await createActAsToken('admin-1', 'member-2') }
    const actAs = `redamon-act-as=${h.jar.actAs}`
    const res = await POST(req({ mode: 'link' }, { cookie: actAs }), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().audit()[0]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'member-2' })
    expect((db().account('member-1')!.pendingNotices as { by: { id: string } }[])[0].by.id).toBe('admin-1')
  })
})

describe('the reason', () => {
  test('reason required for an account that signed in', async () => {
    db().seedUsers([{ id: 'member-3', lastLoginAt: new Date('2026-11-10T08:00:00Z') }])
    await signIn('admin-1')
    for (const body of [{ mode: 'link' }, { mode: 'link', reason: '   ' }, { mode: 'temporary', temporaryPassword: TEMP, reason: null }]) {
      const res = await POST(req(body), params('member-3'))
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ code: 'reason_required', field: 'reason' })
    }
    expect(db().account('member-3')).toMatchObject({ sessionVersion: 0 })
    expect(db().audit()).toEqual([])
    const ok = await POST(req({ mode: 'link', reason: 'Forgot it' }), params('member-3'))
    expect(ok.status).toBe(200)
  })

  test('an account that never signed in needs none', async () => {
    await signIn('admin-1')
    expect((await POST(req({ mode: 'link' }), params('member-1'))).status).toBe(200)
    expect(db().audit()[0].after).toMatchObject({ reason: null })
  })

  test('a reason that is not text, or longer than 500 characters, is refused before anything is read', async () => {
    await signIn('admin-1')
    for (const reason of [42, { x: 1 }, 'x'.repeat(501)]) {
      const res = await POST(req({ mode: 'link', reason }), params('member-1'))
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'reason' })
    }
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })
})

describe('who may reset whom', () => {
  test('Root target refused', async () => {
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link', stepUpPassword: PW.admin }), params('root-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'root_protected' })
    expect(db().account('root-1')!.sessionVersion).toBe(0)
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'rbac.root_protected_refused', actorId: 'admin-1', targetId: 'root-1', after: { attempted: 'reset_credentials' },
    })])
  })

  test('admin target needs Root: another admin is refused before any password is checked', async () => {
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link', stepUpPassword: 'wrong' }), params('admin-2'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'root_only' })
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
  })

  test('admin target needs Root: Root with its own password resets an admin', async () => {
    await signIn('root-1')
    const missing = await POST(req({ mode: 'link' }), params('admin-2'))
    expect(missing.status).toBe(403)
    expect(await missing.json()).toMatchObject({ code: 'step_up_required' })
    const wrong = await POST(req({ mode: 'link', stepUpPassword: 'not-it' }), params('admin-2'))
    expect(await wrong.json()).toMatchObject({ code: 'step_up_failed' })
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
    const ok = await POST(req({ mode: 'link', stepUpPassword: PW.root }), params('admin-2'))
    expect(ok.status).toBe(200)
    expect(db().account('admin-2')).toMatchObject({ password: '', sessionVersion: 1 })
    expect(db().audit().at(-1)).toMatchObject({ actorId: 'root-1', action: 'user.credentials_reset', targetId: 'admin-2' })
  })

  test('an unconfirmed Root holds no such power', async () => {
    db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'automatic', rootConfirmedAt: null })
    clearInstanceRootCacheForTests()
    await signIn('root-1')
    const res = await POST(req({ mode: 'link', stepUpPassword: PW.root }), params('admin-2'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'root_only' })
  })

  test('the own account is not a target', async () => {
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('admin-1'))
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'own_account' })
  })

  test('a member is refused, coded with the permission', async () => {
    await signIn('member-2')
    const res = await POST(req({ mode: 'link' }), params('member-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: expect.any(String), code: 'forbidden', permission: 'users:reset_credentials',
    })
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })

  test('no session 401', async () => {
    expect((await POST(req({ mode: 'link' }), params('member-1'))).status).toBe(401)
  })

  test('an invited account is not reset (its invite is resent instead)', async () => {
    db().seedUsers([{ id: 'member-3', status: 'invited', password: '' }])
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('member-3'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'not_active' })
  })

  test('an unknown account 404', async () => {
    await signIn('admin-1')
    expect((await POST(req({ mode: 'link' }), params('nobody'))).status).toBe(404)
  })
})

describe('the request', () => {
  test.each([
    [{}, 'mode'],
    [{ mode: 'email' }, 'mode'],
    [{ mode: 'temporary' }, 'temporaryPassword'],
    [{ mode: 'temporary', temporaryPassword: 42 }, 'temporaryPassword'],
    [{ mode: 'link', temporaryPassword: TEMP }, 'temporaryPassword'],
  ])('%j → 400 invalid_field', async (body, field) => {
    await signIn('admin-1')
    const res = await POST(req(body), params('member-1'))
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })

  test('cross-origin refused', async () => {
    await signIn('admin-1')
    expect((await POST(req({ mode: 'link' }, { origin: 'https://evil.example' }), params('member-1'))).status).toBe(403)
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })

  test('not JSON → 415', async () => {
    await signIn('admin-1')
    expect((await POST(req('mode=link', { contentType: 'application/x-www-form-urlencoded' }), params('member-1'))).status).toBe(415)
  })

  test('switch off 404, before any check', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    const res = await POST(req({ mode: 'link' }), params('member-1'))
    expect(res.status).toBe(404)
    expect(db().account('member-1')).toMatchObject({ sessionVersion: 0, password: '$2a$12$hash-of-member-1' })
  })
})

describe('the write judges the account again, under the locks (what moved after the route read it)', () => {
  const write = (actor: string, target: string, over: Record<string, unknown> = {}) => resetCredentials(
    req({ mode: 'link' }), { userId: actor, role: 'admin' }, target,
    { mode: 'link', reason: null, adminTarget: false, attempted: 'reset_credentials', ...over },
  )

  test('the account signed in meanwhile: a reason is required after all, nothing written', async () => {
    db().seedUsers([{ id: 'member-3', lastLoginAt: new Date('2026-11-12T11:59:00Z') }])
    const res = await write('admin-1', 'member-3')
    expect(res).toBeInstanceOf(Response)
    expect((res as Response).status).toBe(400)
    expect(await (res as Response).json()).toMatchObject({ code: 'reason_required' })
    expect(db().account('member-3')!.sessionVersion).toBe(0)
  })

  test('the target became Root meanwhile: root_protected, nothing written', async () => {
    db().seedInstance({ rootUserId: 'admin-2', rootAssignedBy: 'host', rootConfirmedAt: new Date() })
    const res = await write('root-1', 'admin-2', { adminTarget: true }) as Response
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'root_protected' })
    expect(db().account('admin-2')).toMatchObject({ sessionVersion: 0, password: '$2a$12$hash-of-admin-2' })
  })

  test('the actor is no longer the confirmed Root: root_only, nothing written', async () => {
    db().seedInstance({ rootUserId: 'admin-1', rootAssignedBy: 'transfer', rootConfirmedAt: new Date() })
    const res = await write('root-1', 'admin-2', { adminTarget: true }) as Response
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'root_only' })
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
  })

  test('the Root lock is taken before the admin-set lock, in the write transaction', async () => {
    await write('admin-1', 'member-1')
    expect(db().rawCalls.filter((c) => /pg_advisory_xact_lock/.test(c))).toHaveLength(2)
    expect(db().rawValues.map((v) => v[0])).toEqual(['rbac-root', 'rbac.admin_set'])
  })

  test('the address the temporary password was judged on changed meanwhile: account_changed, nothing written', async () => {
    const res = await write('admin-1', 'member-1', {
      mode: 'temporary', passwordHash: '$2a$12$new', judgedEmail: 'someone-else@e2e.local',
    }) as Response
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'account_changed' })
    expect(db().account('member-1')!.password).toBe('$2a$12$hash-of-member-1')
  })
})
