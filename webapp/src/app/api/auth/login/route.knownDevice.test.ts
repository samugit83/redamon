/**
 * D6 — anyone could keep any account out by sending a few wrong passwords for its e-mail.
 * A browser that signed in to the e-mail before carries a known-device entry and is counted on
 * its own key, so it signs in through the e-mail's lockout; every other browser is still
 * locked, and the e-mail still counts the guesses sent against it.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/login/route.knownDevice.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const mockUserFindUnique = vi.fn()
const mockQueryRaw = vi.fn(async () => {
  const row = await mockUserFindUnique()
  return row ? [row] : []
})
vi.mock('@/lib/prisma', () => ({
  default: {
    $queryRaw: (...a: unknown[]) => (mockQueryRaw as (...x: unknown[]) => unknown)(...a),
    $executeRaw: vi.fn(async () => 1),
  },
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
import { LOGIN_DEVICE_COOKIE } from '@/lib/loginDevice'
import { POST } from './route'

const ROOT = { id: 'root1', name: 'Root', email: 'root@example.com', password: '$2b$10$x', role: 'admin' }
const RIGHT = 'the-right-password'

function login(email: string, password: string, { cookie, ip = '203.0.113.9' }: { cookie?: string; ip?: string } = {}) {
  return POST(new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': ip,
      ...(cookie ? { cookie: `${LOGIN_DEVICE_COOKIE}=${cookie}` } : {}),
    },
    body: JSON.stringify({ email, password }),
  }))
}

function deviceCookieOf(res: Response): string | undefined {
  const header = res.headers.get('set-cookie') ?? ''
  const m = new RegExp(`${LOGIN_DEVICE_COOKIE}=([^;]+)`).exec(header)
  return m ? decodeURIComponent(m[1]) : undefined
}

/** Five wrong passwords for the e-mail, from a browser that never signed in to it. */
async function attackerLocks(email: string) {
  for (let i = 0; i < 5; i++) await login(email, 'wrong', { ip: '198.51.100.66' })
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
  vi.stubEnv('LOGIN_MAX_ATTEMPTS', '5')
  vi.stubEnv('LOGIN_LOCKOUT_SECONDS', '900')
  mockUserFindUnique.mockResolvedValue(ROOT)
  mockVerifyPassword.mockImplementation(async (p: string) => p === RIGHT)
})

describe('POST /api/auth/login, known devices (D6)', () => {
  test('a successful sign-in hands the browser a known-device entry', async () => {
    const res = await login(ROOT.email, RIGHT)
    expect(res.status).toBe(200)
    expect(deviceCookieOf(res)).toBeTruthy()
  })

  test('a failed sign-in hands out no entry', async () => {
    const res = await login(ROOT.email, 'wrong')
    expect(res.status).toBe(401)
    expect(deviceCookieOf(res)).toBeUndefined()
  })

  test("the attack: Root's own browser still signs in while a stranger holds the lockout", async () => {
    const device = deviceCookieOf(await login(ROOT.email, RIGHT))!
    await attackerLocks(ROOT.email)

    // A browser without an entry is locked out, right password or not (brute force stays capped).
    const fresh = await login(ROOT.email, RIGHT, { ip: '192.0.2.10' })
    expect(fresh.status).toBe(429)

    // Root's browser signs in from the same address as before.
    const own = await login(ROOT.email, RIGHT, { cookie: device })
    expect(own.status).toBe(200)
    const successes = mockWriteAudit.mock.calls.filter((c) => c[0].action === 'auth.login.success')
    expect(successes[0][0].after.knownDevice).toBeUndefined()
    expect(successes.at(-1)![0].after.knownDevice).toBe(true)
  })

  test("Root's success through a known device does not lift the stranger's lock on the e-mail", async () => {
    const device = deviceCookieOf(await login(ROOT.email, RIGHT))!
    await attackerLocks(ROOT.email)
    expect((await login(ROOT.email, RIGHT, { cookie: device })).status).toBe(200)
    expect((await login(ROOT.email, RIGHT, { ip: '192.0.2.10' })).status).toBe(429)
  })

  test('a known device has a lockout of its own', async () => {
    const device = deviceCookieOf(await login(ROOT.email, RIGHT))!
    for (let i = 0; i < 5; i++) expect((await login(ROOT.email, 'wrong', { cookie: device })).status).toBe(401)
    const locked = await login(ROOT.email, RIGHT, { cookie: device })
    expect(locked.status).toBe(429)
    const lockout = mockWriteAudit.mock.calls.find((c) => c[0].action === 'auth.login.lockout')!
    expect(lockout[0].after.knownDevice).toBe(true)
    // ...and its failures never touched the e-mail: another browser still signs in.
    expect((await login(ROOT.email, RIGHT, { ip: '192.0.2.10' })).status).toBe(200)
  })

  test("an entry for another e-mail does not get a browser past Root's lockout", async () => {
    mockUserFindUnique.mockResolvedValueOnce({ ...ROOT, id: 'm1', email: 'member@example.com', role: 'user' })
    const memberDevice = deviceCookieOf(await login('member@example.com', RIGHT))!
    await attackerLocks(ROOT.email)
    expect((await login(ROOT.email, RIGHT, { cookie: memberDevice })).status).toBe(429)
  })

  test('a forged entry is ignored and counts against the e-mail as before', async () => {
    await attackerLocks(ROOT.email)
    const forged = `d1.${'A'.repeat(22)}.${'B'.repeat(22)}.9999999999.${'C'.repeat(43)}`
    expect((await login(ROOT.email, RIGHT, { cookie: forged })).status).toBe(429)
  })

  test('the entry is renewed with the same id at the next sign-in', async () => {
    const first = deviceCookieOf(await login(ROOT.email, RIGHT))!
    const second = deviceCookieOf(await login(ROOT.email, RIGHT, { cookie: first }))!
    expect(second.split('.')[1]).toBe(first.split('.')[1])
  })
})
