/**
 * The admin idle timeout at the edge (step 2.11, ID-24). With the identity switch on, an admin's
 * login token carries its idle limit `idl` (minutes) and its last activity `lat`: the middleware
 * refuses a token idle longer than `idl` (pages go to /login, APIs answer 401 `session_ended`,
 * which sends the browser to sign-in; the cookie is cleared) and, at most once a minute, hands
 * the browser the same token with `lat` moved to now (same expiry, same claims), so activity keeps
 * the session alive up to its fixed lifetime. A member's token (no idle claims) is never refreshed.
 * With the switch off neither happens (Phase 1). Time comes from the authz clock.
 *
 * Run: npx vitest run src/middleware.sessionIdle.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { SignJWT, decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 'i'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-xyz')

import { middleware } from './middleware'
import { setFlagsForTests } from './lib/authz/flags'
import { setNowForTests } from './lib/authz/clock'

const KEY = new TextEncoder().encode('i'.repeat(64))
const T0 = Math.floor(Date.now() / 1000)

async function token(claims: Record<string, unknown>, expSeconds = 12 * 3600): Promise<string> {
  return new SignJWT({ sub: 'a1', role: 'admin', sv: 4, ...claims })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(T0)
    .setExpirationTime(T0 + expSeconds)
    .sign(KEY)
}
const adminToken = (over: Record<string, unknown> = {}) => token({ adm: 1, idl: 60, lat: T0, ...over })

function req(path: string, cookie: string, method = 'GET'): NextRequest {
  return new NextRequest(`http://localhost:3000${path}`, { method, headers: { cookie: `redamon-auth=${cookie}` } })
}
const at = (seconds: number) => setNowForTests(() => new Date((T0 + seconds) * 1000))
const passed = (res: Response) => res.status === 200 && res.headers.get('location') === null

/** The redamon-auth value a response sets, or null. */
function setAuth(res: Response): { value: string; header: string } | null {
  const header = res.headers.getSetCookie?.().find((c) => c.startsWith('redamon-auth=')) ?? null
  if (!header) return null
  return { value: header.slice('redamon-auth='.length).split(';')[0], header }
}

beforeEach(() => setFlagsForTests({ identity: true }))
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('idle admin refused', () => {
  test('a page after more than idl minutes without activity goes to /login and the cookie is cleared', async () => {
    at(61 * 60)
    const res = await middleware(req('/graph', await adminToken()))
    expect(res.status).toBe(307)
    expect(res.headers.get('location')).toBe('http://localhost:3000/login')
    const cleared = setAuth(res)
    expect(cleared?.value).toBe('')
  })

  test('an API answers 401 session_ended (the browser then signs in again) and clears the cookie', async () => {
    at(61 * 60)
    const res = await middleware(req('/api/auth/me', await adminToken()))
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({
      error: 'Your session ended after a period of inactivity. Sign in again.', code: 'session_ended',
    })
    expect(setAuth(res)?.value).toBe('')
  })

  test('the limit is the token\'s own idl', async () => {
    at(6 * 60)
    expect((await middleware(req('/api/projects', await adminToken({ idl: 5 })))).status).toBe(401)
    expect(passed(await middleware(req('/api/projects', await adminToken({ idl: 10 }))))).toBe(true)
  })

  test('exactly idl minutes is still active', async () => {
    at(60 * 60)
    expect(passed(await middleware(req('/api/projects', await adminToken())))).toBe(true)
  })

  test('an idle account that must change its password is refused too (no change page while idle)', async () => {
    at(61 * 60)
    const res = await middleware(req('/account', await adminToken({ pwc: 1 })))
    expect(res.headers.get('location')).toBe('http://localhost:3000/login')
  })
})

describe('lat refreshed at most once a minute', () => {
  test('within the minute: passes, no new cookie', async () => {
    at(59)
    const res = await middleware(req('/api/projects', await adminToken()))
    expect(passed(res)).toBe(true)
    expect(setAuth(res)).toBeNull()
  })

  test('after a minute: the same token with lat = now, same expiry, Max-Age = what is left', async () => {
    at(90)
    const old = await adminToken({ pwc: 1 })
    const res = await middleware(req('/account', old))
    expect(passed(res)).toBe(true)
    const fresh = setAuth(res)!
    const before = decodeJwt(old)
    const after = decodeJwt(fresh.value)
    expect(after).toEqual({ ...before, lat: T0 + 90 })
    expect(fresh.header).toMatch(/Max-Age=43110/i)
    expect(fresh.header).toMatch(/HttpOnly/i)
    expect(fresh.header).toMatch(/SameSite=lax/i)
    expect(fresh.header).toMatch(/Path=\//)
  })

  test('the refreshed token keeps the session alive past the first idle limit', async () => {
    at(50 * 60)
    const first = setAuth(await middleware(req('/api/projects', await adminToken())))!
    at(100 * 60)
    expect(passed(await middleware(req('/api/projects', first.value)))).toBe(true)
  })

  test('pages refresh too', async () => {
    at(120)
    expect(setAuth(await middleware(req('/graph', await adminToken())))).not.toBeNull()
  })

  test('a clock behind the token (another copy, a skew) neither refuses nor refreshes', async () => {
    at(-30)
    const res = await middleware(req('/api/projects', await adminToken()))
    expect(passed(res)).toBe(true)
    expect(setAuth(res)).toBeNull()
  })
})

describe('tokens without idle claims', () => {
  test('a member token is never refused for idleness nor refreshed', async () => {
    at(30 * 24 * 3600 - 60)
    const res = await middleware(req('/api/projects', await token({}, 31 * 24 * 3600)))
    expect(passed(res)).toBe(true)
    expect(setAuth(res)).toBeNull()
  })

  test('half an idle pair, or a malformed one, makes the token invalid', async () => {
    at(10)
    for (const bad of [{ idl: 60 }, { lat: T0 }, { idl: 0, lat: T0 }, { idl: 60, lat: 'x' }, { adm: 2 }]) {
      const res = await middleware(req('/graph', await token(bad)))
      expect(res.headers.get('location')).toBe('http://localhost:3000/login')
    }
  })
})

describe('switch off: no idle, no refresh (Phase 1)', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('an idle admin token passes and is not refreshed', async () => {
    at(5 * 3600)
    const res = await middleware(req('/api/projects', await adminToken()))
    expect(passed(res)).toBe(true)
    expect(setAuth(res)).toBeNull()
  })
})

describe('what the idle check never touches', () => {
  test('public paths and the internal key', async () => {
    at(61 * 60)
    const idle = await adminToken()
    expect(passed(await middleware(req('/api/health', idle)))).toBe(true)
    const internal = new NextRequest('http://localhost:3000/api/projects/p1', { headers: { 'x-internal-key': 'internal-secret-xyz' } })
    expect(passed(await middleware(internal))).toBe(true)
  })
})
