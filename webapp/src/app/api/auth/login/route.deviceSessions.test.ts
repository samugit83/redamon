/**
 * Sign-in and device sessions (step 6.10, GV-17). With RBAC_GOVERNANCE_ENABLED on, each successful
 * sign-in writes one `UserSession` row for the browser (its address, whether the address is trusted,
 * its browser, the account's session version, the token's expiry) and the login token names it as
 * `sid`. A refused sign-in writes none. With the switch off: no row, no `sid` (DV-30).
 *
 * Real tokens; Prisma, bcrypt and the audit writer are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/login/route.deviceSessions.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 'q'.repeat(64))

const h = vi.hoisted(() => ({
  compare: vi.fn(),
  account: null as Record<string, unknown> | null,
  sessions: [] as Array<Record<string, unknown>>,
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
      findUnique: async () => ({ passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12, adminIdleMinutes: 60 }),
    },
    userSession: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        const row = { id: `ckdevice${h.sessions.length + 1}`, ...data }
        h.sessions.push(row)
        return { id: row.id }
      },
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn().mockResolvedValue(undefined), writeActAsAudit: vi.fn() }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { POST } from './route'

const T0 = new Date('2026-11-13T12:00:00Z')
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1.15'

function login(headers: Record<string, string> = {}) {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'user-agent': UA, 'x-forwarded-for': '198.51.100.23, 10.0.0.2', ...headers },
    body: JSON.stringify({ email: 'alice@x.test', password: 'a-submitted-password' }),
  }))
}
const issued = (res: Response) => {
  const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-auth='))
  return line ? decodeJwt(line.slice('redamon-auth='.length).split(';')[0]) : null
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.account = {
    id: 'u1', name: 'Alice', email: 'alice@x.test', password: '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    role: 'standard', status: 'active', sessionVersion: 4, mustChangePassword: false, lastLoginAt: T0, pendingNotices: [],
  }
  h.sessions = []
  setFlagsForTests({ identity: true, permissions: true, governance: true })
  setNowForTests(() => T0)
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('login creates a session', () => {
  test('one row for the browser and the token names it', async () => {
    const res = await login()
    expect(res.status).toBe(200)
    expect(h.sessions).toEqual([{
      id: 'ckdevice1', userId: 'u1', sessionVersion: 4, createdAt: T0, lastSeenAt: T0,
      expiresAt: new Date(T0.getTime() + 168 * 3600_000), ip: '198.51.100.23', ipTrusted: false, userAgent: UA,
    }])
    expect(issued(res)).toMatchObject({ sub: 'u1', sv: 4, sid: 'ckdevice1' })
  })

  test('behind the trusted proxy the address is recorded as trusted', async () => {
    vi.stubEnv('TRUST_PROXY', '1')
    await login()
    expect(h.sessions[0]).toMatchObject({ ip: '198.51.100.23', ipTrusted: true })
    vi.unstubAllEnvs()
    vi.stubEnv('AUTH_SECRET', 'q'.repeat(64))
  })

  test('a refused sign-in writes no row and sets no cookie', async () => {
    h.compare.mockResolvedValue(false)
    const res = await login()
    expect(res.status).toBe(401)
    expect(h.sessions).toEqual([])
    expect(issued(res)).toBeNull()
  })

  test('switch off: no row and no sid', async () => {
    for (const flags of [{ identity: true, permissions: true }, { identity: true }, {}]) {
      setFlagsForTests(flags)
      const res = await login()
      expect(res.status).toBe(200)
      expect(issued(res)).not.toHaveProperty('sid')
    }
    expect(h.sessions).toEqual([])
  })
})
