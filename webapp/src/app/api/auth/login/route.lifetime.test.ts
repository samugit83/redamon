/**
 * Sign-in and the session lifetimes (step 2.11, ID-24). With the identity switch on the login
 * token lives `memberSessionTtlHours` for a member and `adminSessionTtlHours` for an admin (Root
 * is an admin), an admin's carries its idle limit and last activity, and the cookie's Max-Age is
 * the token's lifetime. With the switch off: today's 7 days for everyone, no idle claim, nothing
 * read. A failed read of the lifetimes never fails the sign-in.
 *
 * Real tokens; Prisma, bcrypt and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 's'.repeat(64))

const h = vi.hoisted(() => ({
  compare: vi.fn(),
  account: null as Record<string, unknown> | null,
  row: null as Record<string, unknown> | null,
  reads: [] as unknown[],
  fail: false,
}))

vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, compare: (...a: unknown[]) => h.compare(...a) } }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: async (strings: TemplateStringsArray) => {
      if (/^\s*SELECT id, name, email, password/.test(strings.join('?'))) return h.account ? [h.account] : []
      throw new Error('unexpected query')
    },
    $executeRaw: async () => 1,
    instanceSettings: {
      findUnique: async (a: unknown) => {
        h.reads.push(a)
        if (h.fail) throw Object.assign(new Error('read failed'), { code: 'P1001' })
        return h.row
      },
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn().mockResolvedValue(undefined), writeActAsAudit: vi.fn() }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { POST } from './route'

const HOUR = 3600
const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Alice', email: 'alice@x.test', password: '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  role: 'standard', status: 'active', sessionVersion: 1, mustChangePassword: false, lastLoginAt: null, pendingNotices: [], ...over,
})

function login() {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@x.test', password: 'a-submitted-password' }),
  }))
}

/** The login token the answer sets and the cookie's Max-Age. */
function issued(res: Response): { claims: ReturnType<typeof decodeJwt>; maxAge: number } {
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-auth='))
  if (!line) throw new Error('no auth cookie set')
  const maxAge = Number(/Max-Age=(\d+)/i.exec(line)?.[1])
  return { claims: decodeJwt(line.slice('redamon-auth='.length).split(';')[0]), maxAge }
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.account = account()
  h.row = { passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12, adminIdleMinutes: 60 }
  h.reads = []
  h.fail = false
  setFlagsForTests({ identity: true })
})
afterEach(() => setFlagsForTests(null))

describe("the cookie's maxAge equals the token lifetime on login", () => {
  test('a member: 168 h, no idle claim', async () => {
    const { claims, maxAge } = issued(await login())
    expect(claims.exp! - claims.iat!).toBe(168 * HOUR)
    expect(maxAge).toBe(168 * HOUR)
    expect(claims).not.toHaveProperty('idl')
    expect(claims).not.toHaveProperty('adm')
  })

  test('an admin: 12 h, adm, idl 60 and lat', async () => {
    h.account = account({ role: 'admin' })
    const { claims, maxAge } = issued(await login())
    expect(claims.exp! - claims.iat!).toBe(12 * HOUR)
    expect(maxAge).toBe(12 * HOUR)
    expect(claims).toMatchObject({ adm: 1, idl: 60, lat: claims.iat, sv: 1 })
  })

  test("Root's shorter values apply at the next sign-in", async () => {
    h.row = { ...h.row, adminSessionTtlHours: 1, adminIdleMinutes: 10 }
    h.account = account({ role: 'admin' })
    const { claims, maxAge } = issued(await login())
    expect(maxAge).toBe(HOUR)
    expect(claims.idl).toBe(10)
  })

  test('a failed read never fails the sign-in: the defaults apply', async () => {
    h.fail = true
    h.account = account({ role: 'admin' })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const res = await login()
      expect(res.status).toBe(200)
      expect(issued(res).maxAge).toBe(12 * HOUR)
    } finally {
      err.mockRestore()
    }
  })

  test('a refused sign-in reads no lifetime', async () => {
    h.compare.mockResolvedValue(false)
    expect((await login()).status).toBe(401)
    expect(h.reads).toEqual([])
  })
})

describe('switch off → today\'s 7 days, no idle', () => {
  test('member and admin alike, and nothing read', async () => {
    setFlagsForTests({ identity: false })
    for (const role of ['standard', 'admin']) {
      h.account = account({ role })
      const { claims, maxAge } = issued(await login())
      expect(claims.exp! - claims.iat!).toBe(7 * 24 * HOUR)
      expect(maxAge).toBe(7 * 24 * HOUR)
      expect(Object.keys(claims).sort()).toEqual(['exp', 'iat', 'role', 'sub', 'sv'])
    }
    expect(h.reads).toEqual([])
  })
})
