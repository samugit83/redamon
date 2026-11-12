/**
 * Sign-in after a credentials reset (step 2.10, ID-19, DV-11; feature document §7.1): the
 * person is told at their next sign-in ("your password was reset by Laura on 12 Nov"), once, and
 * the first sign-in after a reset records its address and browser in `auth.login.after_reset`,
 * only then. The login reads the notices and the last sign-in from its one sign-in row (still
 * one query and one compare on every path), answers the pending notices and marks them shown.
 * With the identity switch off none of it: Phase 1's sign-in.
 *
 * Real tokens; Prisma, bcrypt and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'n'.repeat(64))

const h = vi.hoisted(() => ({
  compare: vi.fn(),
  account: null as Record<string, unknown> | null,
  reads: 0,
  writes: [] as { sql: string; values: unknown[] }[],
  audit: vi.fn(),
}))

vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, compare: (...a: unknown[]) => h.compare(...a) } }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: async (strings: TemplateStringsArray) => {
      const sql = strings.join('?')
      if (!/^\s*SELECT id, name, email, password/.test(sql)) throw new Error(`unexpected query ${sql}`)
      h.reads++
      return h.account ? [h.account] : []
    },
    $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      h.writes.push({ sql: strings.join('?'), values })
      // The notices write marks them shown: the stored list is what the next sign-in reads.
      if (/SET pending_notices/.test(strings.join('?'))) h.account!.pendingNotices = JSON.parse(String(values[0]))
      return 1
    },
    instanceSettings: { findUnique: async () => ({ passwordMinLength: 12, passwordAskChangeIfShort: false }) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a), writeActAsAudit: vi.fn() }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { POST } from './route'

const HASH = '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const RESET_AT = '2026-11-12T10:00:00.000Z'
const notice = (over: Record<string, unknown> = {}) => ({
  id: '6f1c2c1e-1111-4a4a-9a9a-000000000001', type: 'credentials_reset', at: RESET_AT,
  by: { id: 'admin-1', name: 'Laura', email: 'laura@e2e.local' }, reason: 'Locked out', mode: 'temporary', ...over,
})
const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Marco', email: 'marco@x.test', password: HASH, role: 'standard', status: 'active',
  sessionVersion: 1, mustChangePassword: false, lastLoginAt: new Date('2026-11-01T08:00:00Z'), pendingNotices: [notice()], ...over,
})

function login(headers: Record<string, string> = {}) {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '203.0.113.7', 'user-agent': 'Firefox/140 test', ...headers },
    body: JSON.stringify({ email: 'marco@x.test', password: 'a-long-enough-pass' }),
  }))
}
const rows = (action: string) => h.audit.mock.calls.map((c) => c[0] as Record<string, unknown>).filter((r) => r.action === action)
const noticeWrites = () => h.writes.filter((w) => /SET pending_notices/.test(w.sql))

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.account = account()
  h.reads = 0
  h.writes = []
  h.audit.mockResolvedValue(undefined)
  setFlagsForTests({ identity: true })
  setNowForTests(() => new Date('2026-11-12T11:00:00Z'))
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('the notice of a reset', () => {
  test('notice shown once: answered at the next sign-in, then marked shown', async () => {
    const res = await login()
    expect(res.status).toBe(200)
    expect((await res.json()).notices).toEqual([{
      id: notice().id, type: 'credentials_reset', at: RESET_AT, by: { name: 'Laura', email: 'laura@e2e.local' },
      reason: 'Locked out', mode: 'temporary',
    }])
    expect(noticeWrites()).toHaveLength(1)
    expect(h.account!.pendingNotices).toEqual([{ ...notice(), shownAt: '2026-11-12T11:00:00.000Z' }])

    const again = await login()
    expect(await again.json()).not.toHaveProperty('notices')
    expect(noticeWrites()).toHaveLength(1)
  })

  test("the person never receives the admin's account id", async () => {
    const res = await login()
    expect(JSON.stringify(await res.json())).not.toContain('admin-1')
  })

  test('still one read on the sign-in path: the notices come with the sign-in row', async () => {
    await login()
    expect(h.reads).toBe(1)
  })

  test('a wrong password learns nothing about the notices and marks nothing', async () => {
    h.compare.mockResolvedValue(false)
    const res = await login()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    expect(noticeWrites()).toEqual([])
    expect(rows('auth.login.after_reset')).toEqual([])
  })

  test('a temporary password: the answer says it must change and carries the notice', async () => {
    h.account = account({ mustChangePassword: true })
    const body = await (await login()).json()
    expect(body).toMatchObject({ mustChangePassword: true, notices: [expect.objectContaining({ mode: 'temporary' })] })
  })
})

describe('address and browser, only for the first sign-in after a reset', () => {
  test('first sign-in after reset audits address and browser', async () => {
    await login()
    expect(rows('auth.login.after_reset')).toEqual([{
      actorId: 'u1', action: 'auth.login.after_reset', targetType: 'user', targetId: 'u1',
      after: { ip: '203.0.113.7', ipTrusted: false, userAgent: 'Firefox/140 test', resetAt: RESET_AT, resetMode: 'temporary' },
    }])
  })

  test('an account that never signed in before the reset counts too', async () => {
    h.account = account({ lastLoginAt: null })
    await login()
    expect(rows('auth.login.after_reset')).toHaveLength(1)
  })

  test('later sign-ins do not', async () => {
    h.account = account({ lastLoginAt: new Date('2026-11-12T10:30:00Z') })
    await login()
    expect(rows('auth.login.after_reset')).toEqual([])
  })

  test('the row carries no password and no notice text', async () => {
    await login()
    const text = JSON.stringify(rows('auth.login.after_reset'))
    expect(text).not.toContain('a-long-enough-pass')
    expect(text).not.toContain('Locked out')
  })
})

describe('identity switch off: Phase 1 sign-in', () => {
  test('no notice answered, nothing marked, no after-reset row', async () => {
    setFlagsForTests({ identity: false })
    const res = await login()
    expect(res.status).toBe(200)
    expect(await res.json()).not.toHaveProperty('notices')
    expect(noticeWrites()).toEqual([])
    expect(rows('auth.login.after_reset')).toEqual([])
  })
})
