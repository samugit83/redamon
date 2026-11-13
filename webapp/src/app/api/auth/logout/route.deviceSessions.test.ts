/**
 * The token paths and sign-out with device sessions (step 6.10, GV-17), RBAC_GOVERNANCE_ENABLED on:
 *   - an invite accept signs in with a new device session (address and browser of the request);
 *   - a forced password change re-issues the cookie on the SAME device session (no new row, the row's
 *     expiry follows the new token) (assumption of the kickoff correction);
 *   - sign-out ends the browser's row (`signed_out`), so a copy of the cookie is refused from then on;
 *     the account's other browsers stay signed in.
 * Switch off: none of this writes or reads a row (DV-30).
 *
 * Real routes and session helpers; the database is the in-memory accountDb. Sign-in itself is
 * login/route.deviceSessions.test.ts.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/logout/route.deviceSessions.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { decodeJwt } from 'jose'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'j'.repeat(64))

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
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearDeviceSessionCacheForTests } from '@/lib/authz/deviceSessions'
import { resetInviteLimitsForTests } from '@/lib/authz/inviteLimits'
import { createLink, signInviteCookie } from '@/lib/authz/invites'
import { __resetThrottle } from '@/lib/loginThrottle'
import { getSession } from '@/lib/session'
import { POST as logout } from './route'
import { POST as acceptInvite } from '@/app/api/invite/accept/route'
import { PUT as changePassword } from '@/app/api/users/[id]/password/route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-13T12:00:00Z')
const LATER = new Date(T0.getTime() + 24 * 3600_000)
const GOVERNANCE = { identity: true, permissions: true, governance: true }
const CURRENT = 'current-password-of-m1'
const NEW_PASSWORD = 'violet-harbour-lantern-42'
const BROWSER = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', 'x-forwarded-for': '203.0.113.50' }

function req(path: string, method: string, body?: unknown, cookie?: string): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json', ...BROWSER }
  if (cookie) headers.cookie = cookie
  return new NextRequest(`http://redamon.test${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })
}
const loginCookie = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith('redamon-auth='))?.slice('redamon-auth='.length).split(';')[0]
async function signedInWith(token: string): Promise<boolean> {
  const before = h.jar.auth
  h.jar.auth = token
  const session = await getSession()
  h.jar.auth = before
  return session !== null
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin' },
    { id: 'invited-1', name: 'Nina', status: 'invited', password: '', email: 'nina@e2e.local' },
    { id: 'm1', sessionVersion: 2, password: bcrypt.hashSync(CURRENT, 4) },
  ])
  db().seedInstance({ inviteTtlHours: 168, resetTtlHours: 4, passwordMinLength: 12, memberSessionTtlHours: 168 })
  db().seedSession({ id: 'm1-laptop', userId: 'm1', sessionVersion: 2, expiresAt: LATER, createdAt: T0 })
  db().seedSession({ id: 'm1-phone', userId: 'm1', sessionVersion: 2, expiresAt: LATER, createdAt: T0 })
  setFlagsForTests(GOVERNANCE)
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearDeviceSessionCacheForTests()
  resetInviteLimitsForTests()
  __resetThrottle()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('an invite accept signs in on a new device session', () => {
  test('one row with the request\'s address and browser; the login cookie names it and signs in', async () => {
    const link = await db().$transaction((tx) => createLink(tx as never, { userId: 'invited-1', kind: 'invite', createdById: 'admin-1' }))
    const res = await acceptInvite(req('/api/invite/accept', 'POST', { password: NEW_PASSWORD }, `redamon-invite=${await signInviteCookie(link.linkId)}`))
    expect(res.status).toBe(200)
    const rows = db().sessions().filter((s) => s.userId === 'invited-1')
    expect(rows).toEqual([expect.objectContaining({ ip: '203.0.113.50', userAgent: BROWSER['user-agent'], sessionVersion: 0, revokedAt: null })])
    const token = loginCookie(res)!
    expect(decodeJwt(token).sid).toBe(rows[0].id)
    expect(await signedInWith(token)).toBe(true)
  })
})

describe('a forced password change keeps the browser\'s device session', () => {
  test('the re-issued cookie names the same row; no new row; the row\'s expiry follows the new token', async () => {
    await db().user.update({ where: { id: 'm1' }, data: { mustChangePassword: true } })
    h.jar.auth = await createToken('m1', 'standard', 2, { pwc: true, sid: 'm1-laptop' })
    const res = await changePassword(
      req('/api/users/m1/password', 'PUT', { currentPassword: CURRENT, newPassword: NEW_PASSWORD }, undefined),
      { params: Promise.resolve({ id: 'm1' }) },
    )
    expect(res.status).toBe(200)
    const token = loginCookie(res)!
    expect(decodeJwt(token)).toMatchObject({ sid: 'm1-laptop' })
    expect(decodeJwt(token)).not.toHaveProperty('pwc')
    expect(db().sessions().filter((s) => s.userId === 'm1').map((s) => s.id)).toEqual(['m1-laptop', 'm1-phone'])
    expect(db().sessions().find((s) => s.id === 'm1-laptop')?.expiresAt).toEqual(new Date(T0.getTime() + 168 * 3600_000))
    expect(await signedInWith(token)).toBe(true)
  })
})

describe('sign-out ends the browser\'s device session', () => {
  test('signed_out; a copy of the cookie is refused; the other browser goes on', async () => {
    const laptop = await createToken('m1', 'standard', 2, { sid: 'm1-laptop' })
    h.jar.auth = laptop
    const res = await logout(req('/api/auth/logout', 'POST', {}, `redamon-auth=${laptop}`))
    expect(res.status).toBe(200)
    expect(db().sessions().find((s) => s.id === 'm1-laptop')).toMatchObject({ revokedAt: T0, revokedById: 'm1', endedBy: 'sign_out' })
    expect(await signedInWith(laptop)).toBe(false)
    expect(await signedInWith(await createToken('m1', 'standard', 2, { sid: 'm1-phone' }))).toBe(true)
  })

  test('a failed write never fails the sign-out (logged)', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(db().userSession, 'updateMany').mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    h.jar.auth = await createToken('m1', 'standard', 2, { sid: 'm1-laptop' })
    expect((await logout(req('/api/auth/logout', 'POST', {}))).status).toBe(200)
    expect(error).toHaveBeenCalledWith('[rbac] device session not ended at sign-out code=P1001')
  })

  test('switch off: sign-out touches no row', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.jar.auth = await createToken('m1', 'standard', 2, { sid: 'm1-laptop' })
    const writes = vi.spyOn(db().userSession, 'updateMany')
    expect((await logout(req('/api/auth/logout', 'POST', {}))).status).toBe(200)
    expect(writes).not.toHaveBeenCalled()
    expect(db().sessions().every((s) => s.revokedAt === null)).toBe(true)
  })
})
