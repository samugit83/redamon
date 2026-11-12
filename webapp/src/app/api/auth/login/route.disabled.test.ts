/**
 * Sign-in of a disabled account (step 2.3, ID-13). With the identity switch on it is refused
 * with the same answer as a wrong password, after the same single read and single compare,
 * and audited `auth.login.disabled` with the account as target (never the password). It stays
 * refused even when a password was set while it was disabled. With the switch off the answer
 * and the row are exactly Phase 1's: its empty password makes it `auth.login.failure`.
 *
 * Real tokens and throttle; Prisma, bcrypt and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 's'.repeat(64))

const h = vi.hoisted(() => ({ compare: vi.fn(), queryRaw: vi.fn(), executeRaw: vi.fn(), audit: vi.fn() }))

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
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a), writeActAsAudit: vi.fn() }))

import { __resetThrottle, checkLockout } from '@/lib/loginThrottle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { POST } from './route'

const HASH = '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Alice', email: 'alice@x.test', password: HASH,
  role: 'standard', status: 'active', sessionVersion: 0, mustChangePassword: false, lastLoginAt: null, ...over,
})
const DISABLED = { status: 'disabled', password: '', sessionVersion: 1 }

function login() {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'user-agent': 'vitest' },
    body: JSON.stringify({ email: 'alice@x.test', password: 'the-right-password' }),
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.executeRaw.mockResolvedValue(1)
  h.audit.mockResolvedValue(undefined)
})
afterEach(() => setFlagsForTests(null))

describe('switch on', () => {
  beforeEach(() => setFlagsForTests({ identity: true }))

  test('disabled account refused, generic message', async () => {
    h.queryRaw.mockResolvedValue([account(DISABLED)])
    const res = await login()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    expect(res.headers.get('set-cookie')).toBeNull()
    expect(h.audit).toHaveBeenCalledTimes(1)
    expect(h.audit.mock.calls[0][0]).toEqual({
      action: 'auth.login.disabled', targetType: 'user', targetId: 'u1',
      after: { email: 'alice@x.test', ip: null, ipTrusted: false, userAgent: 'vitest' },
    })
    expect(JSON.stringify(h.audit.mock.calls)).not.toContain('the-right-password')
  })

  test('one read and one compare, as for a wrong password; no last-login write', async () => {
    h.queryRaw.mockResolvedValue([account(DISABLED)])
    await login()
    expect(h.queryRaw).toHaveBeenCalledTimes(1)
    expect(h.compare).toHaveBeenCalledTimes(1)
    expect(h.executeRaw).not.toHaveBeenCalled()
  })

  test('a password set while it was disabled does not let it in', async () => {
    h.queryRaw.mockResolvedValue([account({ status: 'disabled', password: HASH })])
    const res = await login()
    expect(res.status).toBe(401)
    expect(h.audit.mock.calls[0][0].action).toBe('auth.login.disabled')
  })

  test('the refusal counts against the lockout like any failed sign-in', async () => {
    h.queryRaw.mockResolvedValue([account(DISABLED)])
    for (let i = 0; i < 5; i++) await login()
    expect(checkLockout('alice@x.test', null).locked).toBe(true)
  })

  test('an account in another state that is not active (invited) is refused as a plain failure', async () => {
    h.queryRaw.mockResolvedValue([account({ status: 'invited', password: '' })])
    expect((await login()).status).toBe(401)
    expect(h.audit.mock.calls[0][0].action).toBe('auth.login.failure')
  })

  test('an active account still signs in', async () => {
    h.queryRaw.mockResolvedValue([account()])
    expect((await login()).status).toBe(200)
    expect(h.audit.mock.calls[0][0].action).toBe('auth.login.success')
  })
})

describe('switch off: Phase 1 behaviour', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('a disabled account (empty password) is an ordinary failure', async () => {
    h.queryRaw.mockResolvedValue([account(DISABLED)])
    const res = await login()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    expect(h.audit.mock.calls[0][0]).toEqual({
      action: 'auth.login.failure', targetType: 'user',
      after: { email: 'alice@x.test', ip: null, ipTrusted: false, userAgent: 'vitest' },
    })
  })

  test('the status alone decides nothing: an account holding a password signs in', async () => {
    h.queryRaw.mockResolvedValue([account({ status: 'disabled', password: HASH })])
    expect((await login()).status).toBe(200)
  })
})
