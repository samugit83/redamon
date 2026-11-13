/**
 * POST /api/invite/accept {password} (step 2.9, ID-14, ID-15, DV-05), public: the invite cookie
 * names the link (GET /invite/<token> set it). The password meets the policy in force; then, in
 * one transaction, the link is used, the account gets the password and becomes active (a reset
 * also raises the session version: every older cookie ends), the account's other open links are
 * cancelled and `user.invite_accepted` is written; the person is signed in and the invite cookie
 * cleared. Five failed accepts cancel the link (`user.invite_locked`). Unknown, expired, used or
 * cancelled: one answer, 410 `invite_invalid`. With the identity switch off: 404.
 *
 * Step 2.10: accepting a reset link is the first sign-in after a credentials reset, so it records
 * its address and browser (`auth.login.after_reset`) and answers the reset's notice once.
 *
 * Step 5.9: the reset link's accept raised the session version, so the account's sockets close
 * (`onAccessReduced`, `reset_link_used`); an invite's accept raises nothing and asks the agent nothing.
 *
 * The database is the in-memory accountDb (transactions roll back); the clock is injected; the
 * agent is a fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')
const fetchMock = vi.fn()

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
import { verifyPassword, verifyToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetInviteLimitsForTests } from '@/lib/authz/inviteLimits'
import { createLink, signInviteCookie } from '@/lib/authz/invites'
import { getSession } from '@/lib/session'
import { POST } from './route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
let clock = T0
const GOOD = 'violet-harbour-lantern-42'

async function openLink(userId: string, kind: 'invite' | 'reset' = 'invite') {
  return db().$transaction((tx) => createLink(tx as never, { userId, kind, createdById: 'admin-1' }))
}

function req(body: unknown, opts: { cookie?: string; origin?: string; contentType?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.cookie) headers.cookie = opts.cookie
  if (opts.origin) headers.origin = opts.origin
  return new NextRequest('http://redamon.test/api/invite/accept', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

async function accept(linkId: string, password: unknown = GOOD, opts: { origin?: string; extraCookie?: string } = {}) {
  const cookie = `redamon-invite=${await signInviteCookie(linkId)}${opts.extraCookie ? `; ${opts.extraCookie}` : ''}`
  return POST(req({ password }, { cookie, origin: opts.origin }))
}

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie()
}
function cookieValue(res: Response, name: string): string | undefined {
  const line = setCookies(res).find((c) => c.startsWith(`${name}=`))
  return line?.slice(name.length + 1).split(';')[0]
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin' },
    { id: 'invited-1', name: 'Nina', status: 'invited', password: '', email: 'nina@e2e.local' },
    { id: 'member-1', email: 'member-1@e2e.local', sessionVersion: 3 },
  ])
  db().seedInstance({ inviteTtlHours: 168, resetTtlHours: 4, passwordMinLength: 16, publicBaseUrl: 'https://redamon.example.com' })
  setFlagsForTests({ identity: true })
  clock = T0
  setNowForTests(() => clock)
  clearPrincipalCacheForTests()
  resetInviteLimitsForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response('{"closed":1,"stopped_runs":0}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('accepting an invite', () => {
  test('accept signs in: password set, active, link used, audited, login cookie set, invite cookie cleared', async () => {
    const link = await openLink('invited-1')
    const res = await accept(link.linkId)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(await res.json()).toEqual({ id: 'invited-1', name: 'Nina', email: 'nina@e2e.local', role: 'standard' })

    const account = db().account('invited-1')!
    expect(account).toMatchObject({ status: 'active', role: 'standard', mustChangePassword: false, lastLoginAt: T0, sessionVersion: 0 })
    expect(await verifyPassword(GOOD, String(account.password))).toBe(true)
    expect(db().invites()[0]).toMatchObject({ id: link.linkId, usedAt: T0, cancelledAt: null })
    expect(db().audit()).toEqual([expect.objectContaining({
      actorId: 'invited-1', actorEmail: 'nina@e2e.local', action: 'user.invite_accepted', targetType: 'user',
      targetId: 'invited-1', after: { kind: 'invite' },
    })])

    const login = cookieValue(res, 'redamon-auth')!
    expect(await verifyToken(login)).toMatchObject({ sub: 'invited-1', role: 'standard', sv: 0 })
    expect(setCookies(res).find((c) => c.startsWith('redamon-auth='))).toMatch(/HttpOnly/i)
    const cleared = setCookies(res).find((c) => c.startsWith('redamon-invite='))!
    expect(cleared).toMatch(/Max-Age=0/i)
    expect(cleared).toMatch(/Path=\/api\/invite/i)
    // The new cookie opens a session: the account is active now.
    h.jar.auth = login
    expect(await getSession({ fresh: true })).toEqual({ userId: 'invited-1', role: 'standard' })
    // No session version was raised: nothing to close (step 5.9).
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('accept enforces the policy: the instance minimum, the deny list, the repeated character', async () => {
    const link = await openLink('invited-1')
    const cases: [string, string][] = [
      ['fifteen-chars-x', 'password_too_short'],
      ['passwordpassword', 'password_common'],
      ['zzzzzzzzzzzzzzzz', 'password_repeated'],
    ]
    for (const [password, code] of cases) {
      const res = await accept(link.linkId, password)
      expect(res.status, password).toBe(400)
      expect(await res.json(), password).toMatchObject({ code })
    }
    expect(db().account('invited-1')).toMatchObject({ status: 'invited', password: '' })
    expect(db().invites()[0]).toMatchObject({ usedAt: null, cancelledAt: null })
    expect(db().audit()).toEqual([])
  })

  test('the email rule applies to the invited address', async () => {
    db().seedInstance({ passwordMinLength: 12 })
    db().seedUsers([{ id: 'invited-2', status: 'invited', password: '', email: 'longaddress1@e2e.local' }])
    const link = await openLink('invited-2')
    const res = await accept(link.linkId, 'LongAddress1')
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'password_is_email' })
  })

  test('a password that is not text is a failed accept', async () => {
    const link = await openLink('invited-1')
    const res = await accept(link.linkId, 1234567890123456)
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'password_too_short', attemptsLeft: 4 })
  })

  test('five failed accepts lock the link', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const link = await openLink('invited-1')
    for (let i = 1; i <= 4; i++) {
      const res = await accept(link.linkId, 'short')
      expect(res.status).toBe(400)
      expect((await res.json()).attemptsLeft).toBe(5 - i)
    }
    const fifth = await accept(link.linkId, 'short')
    expect(fifth.status).toBe(410)
    expect(await fifth.json()).toEqual({ error: 'This link is not valid or has expired', code: 'invite_invalid' })
    expect(db().invites()[0].cancelledAt).toEqual(T0)
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'user.invite_locked', targetId: 'invited-1', actorId: null, after: { kind: 'invite', failedAccepts: 5 },
    })])
    expect(warn).toHaveBeenCalledWith('[rbac] invite link locked user=invited-1 kind=invite after 5 failed accepts')
    // Even the right password no longer works.
    expect((await accept(link.linkId)).status).toBe(410)
    expect(db().account('invited-1')).toMatchObject({ status: 'invited', password: '' })
  })

  test('a new link starts its own count', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const first = await openLink('invited-1')
    for (let i = 0; i < 4; i++) await accept(first.linkId, 'short')
    const second = await openLink('invited-1')
    expect(((await (await accept(second.linkId, 'short')).json()) as { attemptsLeft: number }).attemptsLeft).toBe(4)
  })

  test('the same link accepted twice at once: one sign-in', async () => {
    const link = await openLink('invited-1')
    const [a, b] = await Promise.all([accept(link.linkId), accept(link.linkId, 'another-good-passphrase-9')])
    expect([a.status, b.status].sort()).toEqual([200, 410])
    expect(db().audit().filter((r) => r.action === 'user.invite_accepted')).toHaveLength(1)
  })

  test('used, expired, cancelled or unknown → 410 invite_invalid, nothing changed', async () => {
    const used = await openLink('invited-1')
    expect((await accept(used.linkId)).status).toBe(200)
    expect((await accept(used.linkId, 'another-good-passphrase-9')).status).toBe(410)

    db().seedUsers([{ id: 'invited-2', status: 'invited', password: '', email: 'invited-2@e2e.local' }])
    const expiring = await openLink('invited-2')
    clock = expiring.expiresAt
    expect((await accept(expiring.linkId)).status).toBe(410)
    clock = T0
    const cancelled = await openLink('invited-2')
    await db().userInvite.updateMany({ where: { id: cancelled.linkId }, data: { cancelledAt: T0 } })
    expect((await accept(cancelled.linkId)).status).toBe(410)
    expect((await accept('invite-404')).status).toBe(410)
    expect(db().account('invited-2')).toMatchObject({ status: 'invited', password: '' })
  })

  test('no cookie, a tampered one, or a login token in its place → 410, and the cookie is cleared', async () => {
    const link = await openLink('invited-1')
    const value = await signInviteCookie(link.linkId)
    for (const cookie of [undefined, `redamon-invite=${value.slice(0, -2)}xx`, 'redamon-invite=']) {
      const res = await POST(req({ password: GOOD }, { cookie }))
      expect(res.status, String(cookie)).toBe(410)
      expect(await res.json()).toMatchObject({ code: 'invite_invalid' })
    }
    expect(db().account('invited-1')).toMatchObject({ status: 'invited' })
  })

  test('audit failure → nothing changed', async () => {
    const link = await openLink('invited-1')
    db().failAudit('user.invite_accepted')
    expect((await accept(link.linkId)).status).toBe(500)
    expect(db().account('invited-1')).toMatchObject({ status: 'invited', password: '' })
    expect(db().invites()[0]).toMatchObject({ usedAt: null })
  })

  test('an act-as cookie left in the browser is cleared with the sign-in', async () => {
    const link = await openLink('invited-1')
    const res = await accept(link.linkId, GOOD, { extraCookie: 'redamon-act-as=stale' })
    expect(setCookies(res).find((c) => c.startsWith('redamon-act-as='))).toMatch(/Max-Age=0/i)
  })
})

describe('accepting a reset link', () => {
  test('the password replaced, the session version raised, the role kept, other open links cancelled', async () => {
    const reset = await openLink('member-1', 'reset')
    const res = await accept(reset.linkId)
    expect(res.status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ status: 'active', role: 'standard', sessionVersion: 4 })
    expect(await verifyToken(cookieValue(res, 'redamon-auth')!)).toMatchObject({ sub: 'member-1', sv: 4 })
    // Step 2.10 adds the sign-in's own row (auth.login.after_reset, below) beside it.
    expect(db().audit().filter((r) => r.action === 'user.reset_link_used')).toEqual([expect.objectContaining({
      action: 'user.reset_link_used', targetId: 'member-1', actorId: 'member-1', after: { kind: 'reset', sessionVersion: 4 },
    })])
  })

  test("the raised session version closes the account's sockets, an admin's acting as it included (step 5.9)", async () => {
    const reset = await openLink('member-1', 'reset')
    expect((await accept(reset.linkId)).status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('http://agent.test:8080/ws/close')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({
      user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'account',
    })
  })

  test('the agent unreachable: the sign-in still lands and the failure is logged', async () => {
    fetchMock.mockImplementation(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }) })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const reset = await openLink('member-1', 'reset')
    const res = await accept(reset.linkId)
    expect(res.status).toBe(200)
    expect(cookieValue(res, 'redamon-auth')).toBeTruthy()
    const lines = err.mock.calls.map((c) => String(c[0]))
    expect(lines.some((l) => l.startsWith('[rbac] socket-close failed user=member-1 '))).toBe(true)
    expect(lines.some((l) => l.startsWith('[rbac] revocation step failed step=close_sockets reason=reset_link_used user=member-1'))).toBe(true)
  })

  const NOTICE = {
    id: '6f1c2c1e-1111-4a4a-9a9a-000000000002', type: 'credentials_reset', at: '2026-11-12T09:30:00.000Z',
    by: { id: 'admin-1', name: 'Laura', email: 'laura@e2e.local' }, reason: 'Locked out', mode: 'link',
  }
  async function acceptWithBrowser(linkId: string) {
    return POST(new NextRequest('http://redamon.test/api/invite/accept', {
      method: 'POST',
      headers: {
        host: 'redamon.test', 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.23', 'user-agent': 'Safari/19 test',
        cookie: `redamon-invite=${await signInviteCookie(linkId)}`,
      },
      body: JSON.stringify({ password: GOOD }),
    }))
  }

  test('the first sign-in after a reset records its address and browser (step 2.10)', async () => {
    db().seedUsers([{ id: 'member-2', email: 'member-2@e2e.local', pendingNotices: [NOTICE] }])
    const reset = await openLink('member-2', 'reset')
    expect((await acceptWithBrowser(reset.linkId)).status).toBe(200)
    expect(db().audit().filter((r) => r.action === 'auth.login.after_reset')).toEqual([expect.objectContaining({
      actorId: 'member-2', targetType: 'user', targetId: 'member-2',
      after: { ip: '198.51.100.23', ipTrusted: false, userAgent: 'Safari/19 test', resetAt: NOTICE.at, resetMode: 'link' },
    })])
  })

  test("the reset's notice is answered once with the sign-in and marked shown (step 2.10)", async () => {
    db().seedUsers([{ id: 'member-2', email: 'member-2@e2e.local', pendingNotices: [NOTICE] }])
    const reset = await openLink('member-2', 'reset')
    const body = await (await acceptWithBrowser(reset.linkId)).json()
    expect(body.notices).toEqual([{
      id: NOTICE.id, type: 'credentials_reset', at: NOTICE.at, by: { name: 'Laura', email: 'laura@e2e.local' }, reason: 'Locked out', mode: 'link',
    }])
    expect(db().account('member-2')!.pendingNotices).toEqual([{ ...NOTICE, shownAt: T0.toISOString() }])
  })

  test('an invite accept records no address or browser (step 2.10)', async () => {
    const link = await openLink('invited-1')
    await acceptWithBrowser(link.linkId)
    expect(db().audit().map((r) => r.action)).toEqual(['user.invite_accepted'])
  })
})

describe('the route itself', () => {
  test('cross-origin 403 and not JSON 415, before the link is read', async () => {
    const link = await openLink('invited-1')
    expect((await accept(link.linkId, GOOD, { origin: 'https://evil.example' })).status).toBe(403)
    const cookie = `redamon-invite=${await signInviteCookie(link.linkId)}`
    expect((await POST(req('password=x', { cookie, contentType: 'application/x-www-form-urlencoded' }))).status).toBe(415)
    expect(db().account('invited-1')).toMatchObject({ status: 'invited' })
  })

  test('switch off 404, nothing changed', async () => {
    const link = await openLink('invited-1')
    setFlagsForTests({ identity: false })
    expect((await accept(link.linkId)).status).toBe(404)
    expect(db().account('invited-1')).toMatchObject({ status: 'invited', password: '' })
  })
})

describe("the cookie's maxAge equals the token lifetime on invite accept (step 2.11, ID-24)", () => {
  function issued(res: Response): { lifetime: number; maxAge: number } {
    const line = setCookies(res).find((c) => c.startsWith('redamon-auth='))!
    const [, body] = line.slice('redamon-auth='.length).split(';')[0].split('.')
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString()) as Record<string, number>
    return { lifetime: claims.exp - claims.iat, maxAge: Number(/Max-Age=(\d+)/i.exec(line)?.[1]) }
  }

  test("a member's accept: the instance member lifetime", async () => {
    db().seedInstance({ inviteTtlHours: 168, resetTtlHours: 4, passwordMinLength: 16, memberSessionTtlHours: 24 })
    const link = await openLink('invited-1')
    expect(issued(await accept(link.linkId))).toEqual({ lifetime: 24 * 3600, maxAge: 24 * 3600 })
  })

  test('an admin\'s reset link: the admin lifetime (12 h when the row holds none)', async () => {
    db().seedUsers([{ id: 'admin-9', role: 'admin', email: 'admin-9@e2e.local' }])
    const link = await openLink('admin-9', 'reset')
    expect(issued(await accept(link.linkId))).toEqual({ lifetime: 12 * 3600, maxAge: 12 * 3600 })
  })
})
