/**
 * Sign-in and must-change (step 2.8, ID-17, ID-29). With the identity switch on, an account
 * whose password must change gets a login token carrying `pwc: 1` (the middleware then holds
 * it on the change page), read from the same single sign-in row. Root's optional prompt
 * (`passwordAskChangeIfShort`): a password shorter than the instance minimum flags the account
 * at sign-in, raising its session version in the same statement, so the token carries the new
 * version and older cookies end. Only when the setting is on; never with the switch off; a
 * failure to read or write it never fails the sign-in.
 *
 * Real tokens; Prisma, bcrypt and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 's'.repeat(64))

const h = vi.hoisted(() => ({
  compare: vi.fn(),
  account: null as Record<string, unknown> | null,
  policy: { passwordMinLength: 16, passwordAskChangeIfShort: true } as Record<string, unknown> | null,
  policyReads: 0,
  failPolicy: false,
  flagWrites: [] as { sql: string; values: unknown[] }[],
  failFlag: false,
  audit: vi.fn(),
}))

vi.mock('bcryptjs', async (orig) => {
  const actual = await orig<{ default: Record<string, unknown> }>()
  const real = (actual.default ?? actual) as Record<string, unknown>
  return { default: { ...real, compare: (...a: unknown[]) => h.compare(...a) } }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = strings.join('?')
      if (/^\s*SELECT id, name, email, password/.test(sql)) return h.account ? [h.account] : []
      if (/UPDATE users SET must_change_password = true/.test(sql)) {
        if (h.failFlag) throw Object.assign(new Error('write failed'), { code: 'P2010' })
        h.flagWrites.push({ sql, values })
        return [{ sessionVersion: (h.account!.sessionVersion as number) + 1 }]
      }
      throw new Error(`unexpected query ${sql}`)
    },
    $executeRaw: async () => 1,
    instanceSettings: {
      findUnique: async () => {
        h.policyReads++
        if (h.failPolicy) throw Object.assign(new Error('read failed'), { code: 'P1001' })
        return h.policy
      },
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a), writeActAsAudit: vi.fn() }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { verifyToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { POST } from './route'

const HASH = '$2a$12$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const account = (over: Record<string, unknown> = {}) => ({
  id: 'u1', name: 'Alice', email: 'alice@x.test', password: HASH,
  role: 'standard', status: 'active', sessionVersion: 3, mustChangePassword: false, lastLoginAt: null, ...over,
})

function login(password = 'a-long-enough-pass') {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@x.test', password }),
  }))
}

async function claims(res: Response) {
  const m = /redamon-auth=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')
  if (!m) throw new Error('no auth cookie set')
  return verifyToken(m[1])
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  h.compare.mockResolvedValue(true)
  h.account = account()
  h.policy = { passwordMinLength: 16, passwordAskChangeIfShort: true }
  h.policyReads = 0
  h.failPolicy = false
  h.flagWrites = []
  h.failFlag = false
  h.audit.mockResolvedValue(undefined)
  setFlagsForTests({ identity: true })
})
afterEach(() => setFlagsForTests(null))

describe('an account that must change its password', () => {
  test('its login token carries pwc and the answer says so', async () => {
    h.account = account({ mustChangePassword: true })
    const res = await login()
    expect(res.status).toBe(200)
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3, pwc: true })
    expect(await res.json()).toMatchObject({ id: 'u1', mustChangePassword: true })
    // Already flagged: nothing is written again and the version stays.
    expect(h.flagWrites).toEqual([])
  })

  test('an account without the flag gets a token without the claim', async () => {
    h.policy = { passwordMinLength: 12, passwordAskChangeIfShort: true }
    const res = await login('a-long-enough-pass')
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3 })
    expect(await res.json()).not.toHaveProperty('mustChangePassword')
  })

  test('a wrong password learns nothing about the flag', async () => {
    h.account = account({ mustChangePassword: true })
    h.compare.mockResolvedValue(false)
    const res = await login()
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    expect(h.policyReads).toBe(0)
  })
})

describe('short password at login sets the flag only when the setting is on', () => {
  test('setting on, shorter than the instance minimum: flagged, version raised, token carries both', async () => {
    const res = await login('fifteen-chars-x')
    expect(res.status).toBe(200)
    expect(h.flagWrites).toHaveLength(1)
    expect(h.flagWrites[0].sql).toMatch(/must_change_password = true, session_version = session_version \+ 1/)
    expect(h.flagWrites[0].values).toEqual(['u1'])
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 4, pwc: true })
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'user.password_change_required', targetType: 'user', targetId: 'u1',
      after: { reason: 'short_password', minLength: 16 },
    }))
  })

  test('the length counts characters, as the policy does', async () => {
    await login('🔑'.repeat(16))
    expect(h.flagWrites).toEqual([])
  })

  test('setting off: a short password signs in unflagged', async () => {
    h.policy = { passwordMinLength: 16, passwordAskChangeIfShort: false }
    const res = await login('fifteen-chars-x')
    expect(h.flagWrites).toEqual([])
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3 })
  })

  test('long enough: nothing set', async () => {
    await login('sixteen-chars-xy')
    expect(h.flagWrites).toEqual([])
  })

  test('a failed read or write never fails the sign-in; it is logged with its code', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.failPolicy = true
    let res = await login('fifteen-chars-x')
    expect(res.status).toBe(200)
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3 })
    h.failPolicy = false
    h.failFlag = true
    res = await login('fifteen-chars-x')
    expect(res.status).toBe(200)
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3 })
    const lines = err.mock.calls.map((c) => String(c[0]))
    expect(lines.filter((l) => l.startsWith('[rbac] short-password check failed user=u1 code='))).toHaveLength(2)
    expect(lines.join(' ')).not.toContain('fifteen-chars-x')
    err.mockRestore()
  })
})

describe('identity switch off: Phase 1 sign-in', () => {
  test('no claim even for a flagged account, no setting read, nothing written', async () => {
    setFlagsForTests({ identity: false })
    h.account = account({ mustChangePassword: true })
    const res = await login('fifteen-chars-x')
    expect(await claims(res)).toEqual({ sub: 'u1', role: 'standard', sv: 3 })
    expect(await res.json()).not.toHaveProperty('mustChangePassword')
    expect(h.policyReads).toBe(0)
    expect(h.flagWrites).toEqual([])
  })
})
