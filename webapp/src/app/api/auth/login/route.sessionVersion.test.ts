/**
 * Sign-in and the account state (step 2.2): the login token carries the session version
 * the account holds (ID-21), read by the same single query that finds the account; a
 * successful sign-in records its time (whatever the identity switch: the Users page shows
 * it) and drops the account from this process's principal cache. A failed sign-in writes
 * nothing, and a last-login write that fails never fails the sign-in.
 *
 * Real tokens; Prisma, bcrypt and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 's'.repeat(64))

const h = vi.hoisted(() => ({ compare: vi.fn(), queryRaw: vi.fn(), executeRaw: vi.fn(), invalidate: vi.fn() }))

vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, compare: (...a: unknown[]) => h.compare(...a) } }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => h.queryRaw(strings, ...values),
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => h.executeRaw(strings, ...values),
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn().mockResolvedValue(undefined), writeActAsAudit: vi.fn() }))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/principal')>()),
  invalidatePrincipal: (...a: unknown[]) => h.invalidate(...a),
}))

import { __resetThrottle } from '@/lib/loginThrottle'
import { verifyToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { POST } from './route'

const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Alice', email: 'alice@x.test', password: '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  role: 'standard', status: 'active', sessionVersion: 0, mustChangePassword: false, lastLoginAt: null, ...over,
})

function login(email = 'alice@x.test') {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'a-submitted-password' }),
  }))
}

/** The `redamon-auth` value the response sets. */
function cookieOf(res: Response): string {
  const set = res.headers.get('set-cookie') ?? ''
  const m = /redamon-auth=([^;]+)/.exec(set)
  if (!m) throw new Error('no auth cookie set')
  return m[1]
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.executeRaw.mockResolvedValue(1)
  setNowForTests(() => new Date('2026-11-12T10:00:00.000Z'))
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('POST /api/auth/login and the account state', () => {
  test("the token carries the account's session version", async () => {
    h.queryRaw.mockResolvedValue([account({ sessionVersion: 7 })])
    const res = await login()
    expect(res.status).toBe(200)
    expect(await verifyToken(cookieOf(res))).toEqual({ sub: 'u1', role: 'standard', sv: 7 })
  })

  test('an account at version 0 signs a version-0 token', async () => {
    h.queryRaw.mockResolvedValue([account()])
    expect((await verifyToken(cookieOf(await login())))?.sv).toBe(0)
  })

  for (const identity of [false, true]) {
    test(`a successful sign-in records its time and drops the cached account (switch ${identity ? 'on' : 'off'})`, async () => {
      setFlagsForTests({ identity })
      h.queryRaw.mockResolvedValue([account()])
      expect((await login()).status).toBe(200)
      expect(h.executeRaw).toHaveBeenCalledTimes(1)
      expect(h.executeRaw.mock.calls[0].slice(1)).toEqual(['2026-11-12T10:00:00.000Z', 'u1'])
      expect(h.invalidate).toHaveBeenCalledWith('u1')
    })
  }

  test('still one read on the sign-in path: the account state comes with the account', async () => {
    h.queryRaw.mockResolvedValue([account({ sessionVersion: 2 })])
    await login()
    expect(h.queryRaw).toHaveBeenCalledTimes(1)
  })

  test.each([
    ['a wrong password', () => { h.queryRaw.mockResolvedValue([account()]); h.compare.mockResolvedValue(false) }],
    ['an unknown email', () => { h.queryRaw.mockResolvedValue([]) }],
    ['a passwordless account', () => { h.queryRaw.mockResolvedValue([account({ password: '' })]) }],
  ])('%s writes nothing', async (_label, arrange) => {
    arrange()
    expect((await login()).status).toBe(401)
    expect(h.executeRaw).not.toHaveBeenCalled()
    expect(h.invalidate).not.toHaveBeenCalled()
  })

  test('a failed last-login write still signs in', async () => {
    h.queryRaw.mockResolvedValue([account({ sessionVersion: 1 })])
    h.executeRaw.mockRejectedValue(Object.assign(new Error('deadlock'), { code: 'P2034' }))
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const res = await login()
      expect(res.status).toBe(200)
      expect((await verifyToken(cookieOf(res)))?.sv).toBe(1)
      expect(err).toHaveBeenCalledWith('[rbac] last-login write failed user=u1 code=P2034')
    } finally {
      err.mockRestore()
    }
  })
})
