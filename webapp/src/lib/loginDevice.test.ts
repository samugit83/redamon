/**
 * D6 — known-device entries: what knownLoginDevice accepts and what rememberLoginDevice writes.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/loginDevice.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import {
  LOGIN_DEVICE_COOKIE, LOGIN_DEVICE_COOKIE_PATH, LOGIN_DEVICE_MAX_AGE, LOGIN_DEVICE_MAX_ENTRIES,
  knownLoginDevice, rememberLoginDevice,
} from './loginDevice'

const SECRET = 'd'.repeat(64)

function req(cookie?: string, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { ...(cookie !== undefined ? { cookie: `${LOGIN_DEVICE_COOKIE}=${cookie}` } : {}), ...headers },
  })
}

/** The cookie value rememberLoginDevice sets for `email`, given the browser's current one. */
function remember(email: string, current?: string, now?: number, headers: Record<string, string> = {}): string {
  const res = NextResponse.json({})
  rememberLoginDevice(res, req(current, headers), email, now)
  const c = res.cookies.get(LOGIN_DEVICE_COOKIE)
  if (!c) throw new Error('no device cookie written')
  return c.value
}

beforeEach(() => vi.stubEnv('AUTH_SECRET', SECRET))
afterEach(() => vi.unstubAllEnvs())

describe('rememberLoginDevice', () => {
  test('writes an httpOnly, SameSite=Strict cookie scoped to the sign-in route', () => {
    const res = NextResponse.json({})
    rememberLoginDevice(res, req(), 'root@example.com')
    const header = res.headers.get('set-cookie') ?? ''
    expect(header).toContain(`${LOGIN_DEVICE_COOKIE}=`)
    expect(header).toMatch(/HttpOnly/i)
    expect(header).toMatch(/SameSite=strict/i)
    expect(header).toContain(`Path=${LOGIN_DEVICE_COOKIE_PATH}`)
    expect(header).toContain(`Max-Age=${LOGIN_DEVICE_MAX_AGE}`)
    // Plain HTTP (local posture): not Secure, or the browser would never send it back.
    expect(header).not.toMatch(/;\s*Secure/i)
  })

  test('is Secure behind the HTTPS proxy in production', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const res = NextResponse.json({})
    rememberLoginDevice(res, req(undefined, { 'x-forwarded-proto': 'https' }), 'root@example.com')
    expect(res.headers.get('set-cookie') ?? '').toMatch(/;\s*Secure/i)
  })

  test('never puts the e-mail in the cookie in clear', () => {
    const value = remember('Root@Example.com')
    expect(value.toLowerCase()).not.toContain('root')
    expect(value).not.toContain('example')
  })

  test('keeps the same device id across sign-ins and renews the entry', () => {
    const t0 = Date.UTC(2026, 0, 1)
    const first = remember('a@example.com', undefined, t0)
    const id1 = knownLoginDevice(req(first), 'a@example.com', t0)
    const second = remember('a@example.com', first, t0 + 1000 * 60 * 60 * 24 * 100)
    const id2 = knownLoginDevice(req(second), 'a@example.com', t0 + 1000 * 60 * 60 * 24 * 100)
    expect(id1).toBeTruthy()
    expect(id2).toBe(id1)
    // Renewed: still valid 170 days after the second sign-in, which the first entry was not.
    const later = t0 + 1000 * 60 * 60 * 24 * 270
    expect(knownLoginDevice(req(first), 'a@example.com', later)).toBeNull()
    expect(knownLoginDevice(req(second), 'a@example.com', later)).toBe(id1)
  })

  test('keeps one entry per e-mail, most recent first, at most the cap', () => {
    let value: string | undefined
    const emails = Array.from({ length: LOGIN_DEVICE_MAX_ENTRIES + 2 }, (_, i) => `u${i}@example.com`)
    for (const e of emails) value = remember(e, value)
    expect(value!.split('~')).toHaveLength(LOGIN_DEVICE_MAX_ENTRIES)
    // The newest ones are known, the two oldest dropped.
    for (const e of emails.slice(-LOGIN_DEVICE_MAX_ENTRIES)) expect(knownLoginDevice(req(value), e)).toBeTruthy()
    for (const e of emails.slice(0, 2)) expect(knownLoginDevice(req(value), e)).toBeNull()
  })

  test('different e-mails in one browser get different device ids', () => {
    const value = remember('b@example.com', remember('a@example.com'))
    const a = knownLoginDevice(req(value), 'a@example.com')
    const b = knownLoginDevice(req(value), 'b@example.com')
    expect(a).toBeTruthy()
    expect(b).toBeTruthy()
    expect(a).not.toBe(b)
  })

  test('writes nothing without an AUTH_SECRET, or with the compose default', () => {
    for (const secret of ['', 'changeme']) {
      vi.stubEnv('AUTH_SECRET', secret)
      const res = NextResponse.json({})
      rememberLoginDevice(res, req(), 'a@example.com')
      expect(res.cookies.get(LOGIN_DEVICE_COOKIE)).toBeUndefined()
    }
  })
})

describe('knownLoginDevice', () => {
  test('recognises the e-mail whatever its case', () => {
    const value = remember('Root@Example.com')
    expect(knownLoginDevice(req(value), 'root@example.com')).toBeTruthy()
    expect(knownLoginDevice(req(value), 'ROOT@EXAMPLE.COM')).toBeTruthy()
  })

  test('an entry for one e-mail is no entry for another', () => {
    const value = remember('member@example.com')
    expect(knownLoginDevice(req(value), 'root@example.com')).toBeNull()
  })

  test('no cookie, an empty one, or garbage: unknown', () => {
    expect(knownLoginDevice(req(), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req(''), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req('not-an-entry'), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req('x'.repeat(5000)), 'a@example.com')).toBeNull()
  })

  test('a forged or altered entry is refused', () => {
    const value = remember('a@example.com')
    const [v, id, tag, exp, sig] = value.split('.')
    const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1)
    expect(knownLoginDevice(req([v, flip(id), tag, exp, sig].join('.')), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req([v, id, flip(tag), exp, sig].join('.')), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req([v, id, tag, String(Number(exp) + 1), sig].join('.')), 'a@example.com')).toBeNull()
    expect(knownLoginDevice(req([v, id, tag, exp, flip(sig)].join('.')), 'a@example.com')).toBeNull()
  })

  test('an entry signed under another AUTH_SECRET is refused', () => {
    const value = remember('a@example.com')
    vi.stubEnv('AUTH_SECRET', 'e'.repeat(64))
    expect(knownLoginDevice(req(value), 'a@example.com')).toBeNull()
  })

  test('an expired entry is refused', () => {
    const t0 = Date.UTC(2026, 0, 1)
    const value = remember('a@example.com', undefined, t0)
    expect(knownLoginDevice(req(value), 'a@example.com', t0 + (LOGIN_DEVICE_MAX_AGE - 1) * 1000)).toBeTruthy()
    expect(knownLoginDevice(req(value), 'a@example.com', t0 + LOGIN_DEVICE_MAX_AGE * 1000)).toBeNull()
  })

  test('a forged entry beside a valid one does not hide the valid one', () => {
    const value = remember('a@example.com')
    expect(knownLoginDevice(req(`garbage~${value}`), 'a@example.com')).toBeTruthy()
  })

  test('unknown without an AUTH_SECRET', () => {
    const value = remember('a@example.com')
    vi.stubEnv('AUTH_SECRET', '')
    expect(knownLoginDevice(req(value), 'a@example.com')).toBeNull()
  })
})
