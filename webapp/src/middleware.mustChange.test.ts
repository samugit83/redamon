/**
 * The middleware and must-change passwords (step 2.8, ID-17). With the identity switch on, a
 * login token carrying `pwc: 1` reaches only the change page and what it needs: every other
 * page is sent to /account?changePassword=1 and every other API answers 403
 * `must_change_password`. Allowed: /account, /api/auth/me, /api/auth/logout, the password
 * policy, and PUT of the account's own password. With the switch off the claim decides
 * nothing (Phase 1). A pwc that is present but not 1 makes the token invalid.
 *
 * Run: npx vitest run src/middleware.mustChange.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { SignJWT } from 'jose'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-xyz')

import { middleware } from './middleware'
import { setFlagsForTests } from './lib/authz/flags'

async function token(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT({ sub: 'u1', role: 'standard', sv: 0, ...claims })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode('c'.repeat(64)))
}

function req(path: string, cookie: string, method = 'GET', headers: Record<string, string> = {}): NextRequest {
  return new NextRequest(`http://localhost:3000${path}`, {
    method, headers: { cookie: `redamon-auth=${cookie}`, ...headers },
  })
}

const passed = (res: Response) => res.status === 200 && res.headers.get('location') === null

beforeEach(() => setFlagsForTests({ identity: true }))
afterEach(() => setFlagsForTests(null))

describe('must-change blocks API and pages except the allowed ones', () => {
  test.each(['/graph', '/projects', '/settings', '/settings/users', '/', '/account/other'])('page %s goes to the change page', async (path) => {
    const res = await middleware(req(path, await token({ pwc: 1 })))
    expect(res.status).toBe(307)
    expect(res.headers.get('location')).toBe('http://localhost:3000/account?changePassword=1')
  })

  test.each([
    ['GET', '/api/projects'],
    ['GET', '/api/users'],
    ['POST', '/api/auth/act-as'],
    ['PUT', '/api/users/u2/password'],
    ['GET', '/api/users/u1/password'],
    ['PUT', '/api/users/u1'],
    ['GET', '/api/account/activity'],
  ])('%s %s answers 403 must_change_password', async (method, path) => {
    const res = await middleware(req(path, await token({ pwc: 1 }), method))
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: 'You must change your password before you continue.', code: 'must_change_password',
    })
  })

  test.each([
    ['GET', '/account'],
    ['GET', '/api/auth/me'],
    ['POST', '/api/auth/logout'],
    ['GET', '/api/auth/password-policy'],
    ['PUT', '/api/users/u1/password'],
  ])('%s %s is allowed', async (method, path) => {
    expect(passed(await middleware(req(path, await token({ pwc: 1 }), method)))).toBe(true)
  })

  test('the query string does not open a path: /account?x stays the page, /graph?account stays blocked', async () => {
    expect(passed(await middleware(req('/account?changePassword=1', await token({ pwc: 1 }))))).toBe(true)
    expect((await middleware(req('/graph?next=/account', await token({ pwc: 1 })))).status).toBe(307)
  })

  test('an admin with a temporary password reaches the change form, and nothing else', async () => {
    const admin = await token({ sub: 'admin-1', role: 'admin', pwc: 1 })
    expect(passed(await middleware(req('/account', admin)))).toBe(true)
    expect(passed(await middleware(req('/api/users/admin-1/password', admin, 'PUT')))).toBe(true)
    expect((await middleware(req('/settings/users', admin))).headers.get('location')).toBe('http://localhost:3000/account?changePassword=1')
    expect((await middleware(req('/api/users', admin))).status).toBe(403)
  })

  test('a token without the claim goes where it asks', async () => {
    expect(passed(await middleware(req('/graph', await token({}))))).toBe(true)
    expect(passed(await middleware(req('/api/projects', await token({}))))).toBe(true)
  })

  test('the internal key never meets the gate', async () => {
    const res = await middleware(new NextRequest('http://localhost:3000/api/projects/p1', {
      headers: { 'x-internal-key': 'internal-secret-xyz', cookie: `redamon-auth=${await token({ pwc: 1 })}` },
    }))
    expect(passed(res)).toBe(true)
  })
})

describe('a malformed pwc', () => {
  test.each([true, '1', 0, 2])('pwc %s makes the token invalid: 401 for the API, sign-in for pages', async (pwc) => {
    expect((await middleware(req('/api/projects', await token({ pwc })))).status).toBe(401)
    const page = await middleware(req('/graph', await token({ pwc })))
    expect(page.headers.get('location')).toBe('http://localhost:3000/login')
  })
})

describe('identity switch off', () => {
  test('pwc decides nothing: pages and APIs pass as in Phase 1', async () => {
    setFlagsForTests({ identity: false })
    expect(passed(await middleware(req('/graph', await token({ pwc: 1 }))))).toBe(true)
    expect(passed(await middleware(req('/api/projects', await token({ pwc: 1 }))))).toBe(true)
  })
})
