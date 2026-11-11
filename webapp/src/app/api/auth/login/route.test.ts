/**
 * Login route: baseline 200/401 behavior + R5 auth-event auditing.
 *
 * R5 assertions: login success/failure/logout emit an audit event with the
 * source IP; the FAILURE event must NOT contain the password or bcrypt hash.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/login/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

// The sign-in lookup is one raw query (lib/authz/accountEmail.ts). The tests
// below predate it and set the one account they expect with
// mockUserFindUnique, which the query mock serves as its single row.
const mockUserFindUnique = vi.fn()
const mockQueryRaw = vi.fn(async () => {
  const row = await mockUserFindUnique()
  return row ? [row] : []
})
vi.mock('@/lib/prisma', () => ({
  default: { $queryRaw: (...a: unknown[]) => (mockQueryRaw as (...x: unknown[]) => unknown)(...a) },
}))

const mockVerifyPassword = vi.fn()
vi.mock('@/lib/auth', async (orig) => {
  const actual = await orig<typeof import('@/lib/auth')>()
  return {
    ...actual,
    verifyPassword: (p: string, h: string) => mockVerifyPassword(p, h),
    createToken: async () => 'signed.jwt.token',
  }
})

const mockWriteAudit = vi.fn().mockResolvedValue(undefined)
vi.mock('@/lib/audit', () => ({
  writeAudit: (a: unknown) => mockWriteAudit(a),
  writeActAsAudit: vi.fn(),
}))

import { __resetThrottle } from '@/lib/loginThrottle'
import { POST } from './route'

function req(body: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '203.0.113.9', ...headers },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  vi.stubEnv('LOGIN_MAX_ATTEMPTS', '3')
  vi.stubEnv('LOGIN_LOCKOUT_SECONDS', '900')
})

describe('POST /api/auth/login', () => {
  test('missing fields -> 400', async () => {
    const res = await POST(req({ email: '' }))
    expect(res.status).toBe(400)
  })

  test('unknown user -> 401 and a failure audit with the attempted email + IP', async () => {
    mockUserFindUnique.mockResolvedValue(null)
    const res = await POST(req({ email: 'nobody@example.com', password: 'guess' }))
    expect(res.status).toBe(401)
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.failure')!
    expect(call).toBeDefined()
    expect(call[0].after.email).toBe('nobody@example.com')
    expect(call[0].after.ip).toBe('203.0.113.9')
  })

  test('failure audit NEVER contains the password or hash', async () => {
    mockUserFindUnique.mockResolvedValue({ id: 'u1', password: '$2b$10$HASHHASHHASH', role: 'user' })
    mockVerifyPassword.mockResolvedValue(false)
    await POST(req({ email: 'u@example.com', password: 'sup3rsecret' }))
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.failure')!
    const serialized = JSON.stringify(call[0])
    expect(serialized).not.toContain('sup3rsecret')
    expect(serialized).not.toContain('$2b$10$HASHHASHHASH')
  })

  test('valid login -> 200 and a success audit', async () => {
    mockUserFindUnique.mockResolvedValue({
      id: 'u1', name: 'U', email: 'u@example.com', password: '$2b$10$x', role: 'user',
    })
    mockVerifyPassword.mockResolvedValue(true)
    const res = await POST(req({ email: 'u@example.com', password: 'right' }))
    expect(res.status).toBe(200)
    const call = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.success')!
    expect(call).toBeDefined()
    expect(call[0].actorId).toBe('u1')
  })

  test('S11: lockout after N failures -> 429 with Retry-After + lockout audit', async () => {
    mockUserFindUnique.mockResolvedValue(null)
    // 3 failures (threshold) from the same email + IP.
    for (let i = 0; i < 3; i++) await POST(req({ email: 'brute@x.com', password: 'x' }))
    // 4th is throttled BEFORE hitting the DB.
    const res = await POST(req({ email: 'brute@x.com', password: 'x' }))
    expect(res.status).toBe(429)
    expect(res.headers.get('Retry-After')).toBeTruthy()
    const lock = mockWriteAudit.mock.calls.find(c => c[0].action === 'auth.login.lockout')
    expect(lock).toBeDefined()
  })

  test('S12: cookie is Secure only over https', async () => {
    mockUserFindUnique.mockResolvedValue({ id: 'u1', name: 'U', email: 'u@x.com', password: '$2b$10$x', role: 'user' })
    mockVerifyPassword.mockResolvedValue(true)
    vi.stubEnv('NODE_ENV', 'production')
    // https -> Secure
    const httpsRes = await POST(req({ email: 'u@x.com', password: 'p' }, { 'x-forwarded-proto': 'https' }))
    expect(httpsRes.headers.get('set-cookie') || '').toMatch(/Secure/i)
    // plain http -> not Secure (local login must keep working)
    __resetThrottle()
    const httpRes = await POST(req({ email: 'u@x.com', password: 'p' }))
    expect(httpRes.headers.get('set-cookie') || '').not.toMatch(/Secure/i)
  })

  test('S11: untrusted (local) XFF is NOT used as a lockout key - no cross-user DoS', async () => {
    // TRUST_PROXY unset -> ipTrusted=false -> per-IP key not created. One email's
    // failures from the shared gateway IP must NOT lock a DIFFERENT email.
    mockUserFindUnique.mockResolvedValue(null)
    for (let i = 0; i < 3; i++) await POST(req({ email: 'victimA@x.com', password: 'x' }, { 'x-forwarded-for': '172.26.0.1' }))
    // A different account from the SAME (untrusted) IP is still allowed to try.
    const res = await POST(req({ email: 'victimB@x.com', password: 'x' }, { 'x-forwarded-for': '172.26.0.1' }))
    expect(res.status).toBe(401) // not 429 - victimB is not locked by victimA's IP
  })

  test('S11: behind a trusted proxy, per-IP lockout DOES engage', async () => {
    vi.stubEnv('TRUST_PROXY', 'true')
    mockUserFindUnique.mockResolvedValue(null)
    // 3 failures across different emails from one trusted client IP trip the IP key.
    await POST(req({ email: 'a@x.com', password: 'x' }, { 'x-forwarded-for': '203.0.113.7' }))
    await POST(req({ email: 'b@x.com', password: 'x' }, { 'x-forwarded-for': '203.0.113.7' }))
    await POST(req({ email: 'c@x.com', password: 'x' }, { 'x-forwarded-for': '203.0.113.7' }))
    const res = await POST(req({ email: 'd@x.com', password: 'x' }, { 'x-forwarded-for': '203.0.113.7' }))
    expect(res.status).toBe(429) // IP key locked
  })

  test('S11: a successful login clears the counter', async () => {
    // 2 failures, then success clears, so subsequent failures start fresh.
    mockUserFindUnique.mockResolvedValueOnce(null)
    await POST(req({ email: 'mix@x.com', password: 'bad' }))
    mockUserFindUnique.mockResolvedValue({ id: 'u9', name: 'U', email: 'mix@x.com', password: '$2b$10$x', role: 'user' })
    mockVerifyPassword.mockResolvedValue(true)
    const ok = await POST(req({ email: 'mix@x.com', password: 'good' }))
    expect(ok.status).toBe(200)
    // Counter cleared: two more failures should NOT be locked yet (threshold 3).
    mockUserFindUnique.mockResolvedValue(null)
    mockVerifyPassword.mockResolvedValue(false)
    await POST(req({ email: 'mix@x.com', password: 'bad' }))
    const res = await POST(req({ email: 'mix@x.com', password: 'bad' }))
    expect(res.status).toBe(401)
  })
})

describe('POST /api/auth/login — the database is down', () => {
  test('a 500 that names the Prisma code, so a DB outage reads apart from a pool timeout', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockUserFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const res = await POST(req({ email: 'a@b.c', password: 'pw' }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Internal server error', code: 'P1001' })
  })
})

describe('POST /api/auth/login — email case (NF-09)', () => {
  const alice = (over: Record<string, unknown> = {}) => ({
    id: 'u-alice', name: 'Alice', email: 'alice@x.test', password: '$2b$10$alice', role: 'standard', ...over,
  })

  test('Alice@x finds alice@x and signs in', async () => {
    mockQueryRaw.mockResolvedValueOnce([alice()])
    mockVerifyPassword.mockResolvedValue(true)
    const res = await POST(req({ email: 'Alice@X.test', password: 'right' }))
    expect(res.status).toBe(200)
    expect((await res.json()).id).toBe('u-alice')
    expect(mockVerifyPassword).toHaveBeenCalledWith('right', '$2b$10$alice')
  })

  test('two accounts differing in case: the exact match signs in, never the other', async () => {
    mockQueryRaw.mockResolvedValueOnce([
      alice({ id: 'u-upper', email: 'Alice@x.test', password: '$2b$10$upper' }),
      alice({ id: 'u-lower', email: 'alice@x.test', password: '$2b$10$lower' }),
    ])
    mockVerifyPassword.mockResolvedValue(true)
    const res = await POST(req({ email: 'alice@x.test', password: 'right' }))
    expect(res.status).toBe(200)
    expect((await res.json()).id).toBe('u-lower')
    expect(mockVerifyPassword).toHaveBeenCalledWith('right', '$2b$10$lower')
  })

  test('two accounts differing in case and no exact match: refused as invalid credentials', async () => {
    mockQueryRaw.mockResolvedValueOnce([
      alice({ id: 'u-upper', email: 'Alice@x.test', password: '$2b$10$upper' }),
      alice({ id: 'u-lower', email: 'alice@x.test', password: '$2b$10$lower' }),
    ])
    mockVerifyPassword.mockResolvedValue(true)
    const res = await POST(req({ email: 'ALICE@x.test', password: 'right' }))
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    // Neither account's hash was even tried.
    const hashes = mockVerifyPassword.mock.calls.map(c => c[1])
    expect(hashes).not.toContain('$2b$10$upper')
    expect(hashes).not.toContain('$2b$10$lower')
  })

  test('the lookup binds the email: a LIKE wildcard matches nothing by itself', async () => {
    await POST(req({ email: 'a_ice@x.test', password: 'whatever' }))
    expect(mockQueryRaw).toHaveBeenCalledTimes(1)
    const [strings, ...values] = mockQueryRaw.mock.calls[0] as unknown as [string[], ...unknown[]]
    expect(strings.join('$')).toMatch(/lower\(email\)\s*=\s*lower\(\$\)/)
    expect(strings.join('$')).not.toMatch(/like/i)
    expect(values).toEqual(['a_ice@x.test'])
  })

  test('case variants of one email share one lockout key', async () => {
    mockUserFindUnique.mockResolvedValue(alice())
    mockVerifyPassword.mockResolvedValue(false)
    await POST(req({ email: 'alice@x.test', password: 'bad' }))
    await POST(req({ email: 'Alice@x.test', password: 'bad' }))
    await POST(req({ email: 'ALICE@X.TEST', password: 'bad' }))
    const res = await POST(req({ email: 'aLiCe@x.test', password: 'bad' }))
    expect(res.status).toBe(429)
  })

  test('an email or password that is not a string -> 400, nothing read', async () => {
    expect((await POST(req({ email: ['a@x.test'], password: 'pw' }))).status).toBe(400)
    expect((await POST(req({ email: 'a@x.test', password: { $ne: '' } }))).status).toBe(400)
    expect(mockQueryRaw).not.toHaveBeenCalled()
  })
})
