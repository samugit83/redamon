/**
 * PUT /api/users/[id]/password on someone else's account is a credentials reset (step 2.10,
 * ID-18, ID-19): with the identity switch on, the password an admin sets for someone takes the
 * same path as "Reset credentials" in temporary mode, so the takeover it allows is never silent:
 * the session version rises and the MCP tokens are revoked whether or not a change is required,
 * the open links are cancelled, a notice joins the account, an account that has signed in before
 * needs a reason, and `user.credentials_reset` commits with the change (fail closed). The own
 * change and the identity switch off keep their behaviour.
 *
 * Real session helpers, tokens and bcrypt; the database is the in-memory accountDb; the agent is
 * a fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'p'.repeat(64))
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
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { setNowForTests } from '@/lib/authz/clock'
import { getSession } from '@/lib/session'
import { PUT } from './route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()
const NOW = new Date('2026-11-12T12:00:00Z')
const TEMP = 'Temporary-orchid-paddle-42'
const SIGNED_IN = new Date('2026-11-10T08:00:00Z')

function put(id: string, body: Record<string, unknown>) {
  return PUT(new NextRequest(`http://redamon.test/api/users/${id}/password`, {
    method: 'PUT', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id }) })
}
const cookieOf = async (userId: string) => {
  const a = db().account(userId)!
  return createToken(userId, String(a.role), Number(a.sessionVersion ?? 0))
}

beforeEach(async () => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', name: 'Laura', role: 'admin', email: 'laura@e2e.local' },
    { id: 'member-1', name: 'Marco', lastLoginAt: SIGNED_IN },
    { id: 'member-2', name: 'Pia' },
  ])
  db().seedToken({ id: 'tok-1', userId: 'member-1' })
  setFlagsForTests({ identity: true })
  setNowForTests(() => NOW)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 0, stopped_runs: 0, by_kind: {} }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
  h.jar = { auth: await cookieOf('admin-1') }
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("an admin sets someone else's password (identity switch on)", () => {
  test('an account that signed in before needs a reason; nothing changes without one', async () => {
    const res = await put('member-1', { newPassword: TEMP })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'reason_required', field: 'reason' })
    expect(db().account('member-1')).toMatchObject({ sessionVersion: 0, password: '$2a$12$hash-of-member-1', pendingNotices: [] })
    expect(db().audit()).toEqual([])
  })

  test('with a reason: the password, the version, the tokens, the notice and the row together', async () => {
    const old = await cookieOf('member-1')
    const res = await put('member-1', { newPassword: TEMP, reason: 'Locked out' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true, revokedMcpTokens: 1 })
    const account = db().account('member-1')!
    expect(account).toMatchObject({ mustChangePassword: true, sessionVersion: 1 })
    expect(bcrypt.compareSync(TEMP, String(account.password))).toBe(true)
    expect(account.pendingNotices).toEqual([expect.objectContaining({
      type: 'credentials_reset', by: { id: 'admin-1', name: 'Laura', email: 'laura@e2e.local' }, reason: 'Locked out', mode: 'temporary',
    })])
    expect(db().tokens()[0].revokedAt).toBeInstanceOf(Date)
    expect(db().audit()).toEqual([expect.objectContaining({
      actorId: 'admin-1', action: 'user.credentials_reset', targetId: 'member-1',
      after: { mode: 'temporary', mustChangePassword: true, sessionVersion: 1, revokedMcpTokens: 1, cancelledLinks: 0, reason: 'Locked out' },
    })])
    expect(db().transactions).toBe(1)
    h.jar = { auth: old }
    expect(await getSession()).toBeNull()
  })

  test('without a required change the account is still signed out everywhere (a reset ends every session)', async () => {
    const res = await put('member-2', { newPassword: TEMP, requirePasswordChange: false })
    expect(res.status).toBe(200)
    expect(db().account('member-2')).toMatchObject({ mustChangePassword: false, sessionVersion: 1 })
    expect(db().audit()[0].after).toMatchObject({ mode: 'temporary', mustChangePassword: false, reason: null })
  })

  test("the account's open links are cancelled", async () => {
    db().seedInvite({ id: 'old-reset', userId: 'member-2', kind: 'reset', tokenHash: 'h1', expiresAt: new Date('2026-11-12T13:00:00Z') })
    await put('member-2', { newPassword: TEMP })
    expect(db().invites()[0].cancelledAt).toEqual(NOW)
  })

  test('audit failure → nothing changed', async () => {
    db().failAudit('user.credentials_reset')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await put('member-2', { newPassword: TEMP })
    expect(res.status).toBe(500)
    expect(db().account('member-2')).toMatchObject({ sessionVersion: 0, password: '$2a$12$hash-of-member-2', pendingNotices: [] })
  })

  test('the policy still answers before the reason', async () => {
    const res = await put('member-1', { newPassword: 'member-1@e2e.local' })
    expect((await res.json()).code).toBe('password_is_email')
  })

  test('a reason that is not text is refused before anything is written', async () => {
    const res = await put('member-1', { newPassword: TEMP, reason: 7 })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field: 'reason' })
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })

  test('an invited account is not set a password (its invite link is its way in)', async () => {
    db().seedUsers([{ id: 'member-3', status: 'invited', password: '' }])
    const res = await put('member-3', { newPassword: TEMP })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'not_active' })
  })
})

describe('unchanged', () => {
  test("the account's own change: no reason, no notice, no reset row", async () => {
    db().seedUsers([{ id: 'member-4', password: bcrypt.hashSync('the-current-one-0001', 4), lastLoginAt: SIGNED_IN }])
    h.jar = { auth: await cookieOf('member-4') }
    const res = await put('member-4', { newPassword: TEMP, currentPassword: 'the-current-one-0001' })
    expect(res.status).toBe(200)
    expect(db().account('member-4')).toMatchObject({ sessionVersion: 0, pendingNotices: [] })
    expect(db().audit().map((r) => r.action)).toEqual(['user.password_changed'])
  })

  test('switch off: Phase 1 writes the password alone, no reason asked, no notice', async () => {
    setFlagsForTests({ identity: false })
    const res = await put('member-1', { newPassword: TEMP })
    expect(res.status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ sessionVersion: 0, mustChangePassword: false, pendingNotices: [] })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
