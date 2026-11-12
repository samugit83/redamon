/**
 * Unit tests for Next.js auth middleware.
 *
 * Run: npx vitest run src/middleware.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

// Mock environment
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-abc')

import { middleware, internalKeyRouteAllowed } from './middleware'
import { SignJWT } from 'jose'

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

async function createTestToken(userId: string, role: string): Promise<string> {
  const secret = new TextEncoder().encode('b'.repeat(64))
  return new SignJWT({ sub: userId, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret)
}

function makeRequest(
  path: string,
  options: { cookie?: string; headers?: Record<string, string> } = {}
): NextRequest {
  const url = `http://localhost:3000${path}`
  const headers = new Headers(options.headers || {})
  if (options.cookie) {
    headers.set('cookie', `redamon-auth=${options.cookie}`)
  }
  return new NextRequest(url, { headers })
}

/* ------------------------------------------------------------------ */
/*  Public paths                                                       */
/* ------------------------------------------------------------------ */

describe('middleware - public paths', () => {
  test.each([
    '/login',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/health',
  ])('allows %s without auth', async (path) => {
    const req = makeRequest(path)
    const res = await middleware(req)
    // NextResponse.next() returns a response with no redirect
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  Tunnel-config sync allowlist (security boundary)                   */
/* ------------------------------------------------------------------ */

describe('middleware - tunnel-config sync allowlist', () => {
  test('allows POST /api/global/tunnel-config/sync without auth (public trigger)', async () => {
    const req = makeRequest('/api/global/tunnel-config/sync')
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('does NOT expose the secret-returning GET /api/global/tunnel-config', async () => {
    // The parent path returns unmasked tunnel credentials and must stay gated.
    // Allowlisting the /sync subpath must not leak it.
    const req = makeRequest('/api/global/tunnel-config')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })

  test('does NOT allowlist sibling paths sharing the prefix', async () => {
    const req = makeRequest('/api/global/tunnel-config/sync-evil')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

/* ------------------------------------------------------------------ */
/*  Static assets                                                      */
/* ------------------------------------------------------------------ */

describe('middleware - static assets', () => {
  test.each([
    '/_next/static/chunk.js',
    '/_next/image?url=test',
    '/favicon.ico',
    '/favicon.png',
    '/logo.png',
    '/js_logo.png',
  ])('allows %s without auth', async (path) => {
    const req = makeRequest(path)
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  Internal requests                                                  */
/* ------------------------------------------------------------------ */

describe('middleware - internal requests', () => {
  test('allows request with valid X-Internal-Key', async () => {
    const req = makeRequest('/api/users', {
      headers: { 'x-internal-key': 'internal-secret-abc' },
    })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('rejects request with wrong X-Internal-Key', async () => {
    const req = makeRequest('/api/users', {
      headers: { 'x-internal-key': 'wrong-key' },
    })
    const res = await middleware(req)
    // Should redirect or return 401
    const isRedirect = res.headers.get('location')?.includes('/login')
    const is401 = res.status === 401
    expect(isRedirect || is401).toBe(true)
  })
})

/* ------------------------------------------------------------------ */
/*  Unauthenticated requests                                           */
/* ------------------------------------------------------------------ */

describe('middleware - unauthenticated', () => {
  test('redirects page request to /login', async () => {
    const req = makeRequest('/graph')
    const res = await middleware(req)
    expect(res.headers.get('location')).toContain('/login')
  })

  test('returns 401 for API request', async () => {
    const req = makeRequest('/api/projects')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

/* ------------------------------------------------------------------ */
/*  Authenticated requests                                             */
/* ------------------------------------------------------------------ */

describe('middleware - authenticated', () => {
  test('allows request with valid JWT cookie', async () => {
    const token = await createTestToken('user-1', 'admin')
    const req = makeRequest('/graph', { cookie: token })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('injects x-user-id and x-user-role headers', async () => {
    const token = await createTestToken('user-xyz', 'standard')
    const req = makeRequest('/api/projects', { cookie: token })
    const res = await middleware(req)

    // The middleware calls NextResponse.next() with modified request headers
    // We can verify no redirect/401
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('rejects expired token for page request', async () => {
    // Create an already-expired token
    const secret = new TextEncoder().encode('b'.repeat(64))
    const token = await new SignJWT({ sub: 'user-1', role: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(secret)

    const req = makeRequest('/graph', { cookie: token })
    const res = await middleware(req)
    expect(res.headers.get('location')).toContain('/login')
  })

  test('returns 401 for expired token on API request', async () => {
    const secret = new TextEncoder().encode('b'.repeat(64))
    const token = await new SignJWT({ sub: 'user-1', role: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(secret)

    const req = makeRequest('/api/projects', { cookie: token })
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

describe('internal-key allowlist — auth-profile observe', () => {
  // The ingest worker POSTs extracted login material here with X-Internal-Key.
  // Omitted from the allowlist it is only logged today, but 401s the moment
  // INTERNAL_KEY_ALLOWLIST_ENFORCE=true — and the recorded session vanishes.
  test('observe route is allowlisted for POST', () => {
    expect(internalKeyRouteAllowed('POST', '/api/internal/auth-profile/proj-1/observe')).toBe(true)
  })

  test('allowlist does not open the whole auth-profile namespace', () => {
    expect(internalKeyRouteAllowed('GET', '/api/internal/auth-profile/proj-1/observe')).toBe(false)
    expect(internalKeyRouteAllowed('POST', '/api/internal/auth-profile/proj-1')).toBe(false)
  })
})

/* ------------------------------------------------------------------ */
/*  MCP: the inbound server is public; the OUTBOUND plugin admin is not */
/* ------------------------------------------------------------------ */

describe('MCP path separation (plan 9.1/9.2)', () => {
  test('/api/mcp-server passes the middleware with no cookie', async () => {
    // An MCP client presents a bearer and no cookie. Without this the request
    // is rejected before the handler, which does its own credential check.
    const res = await middleware(makeRequest('/api/mcp-server'))
    expect(res.status).toBe(200)
  })

  test.each([
    '/api/mcp/manifest',
    '/api/mcp/reload',
    '/api/mcp/test',
  ])('%s is still NOT public', async path => {
    // The outbound plugin-admin namespace. Making it public - which a
    // PUBLIC_PATHS entry of '/api/mcp' would do, since matching is
    // `startsWith(p + '/')` - would expose all three unauthenticated.
    const res = await middleware(makeRequest(path))
    expect(res.status).toBe(401)
  })

  test('a path merely starting with the same letters is not public', async () => {
    const res = await middleware(makeRequest('/api/mcp-servers-admin'))
    expect(res.status).toBe(401)
  })

  test('a sub-path of the MCP server is public too, and nothing else is', async () => {
    expect((await middleware(makeRequest('/api/mcp-server/'))).status).toBe(200)
    expect((await middleware(makeRequest('/api/mcpserver'))).status).toBe(401)
  })
})

describe('plugin token-auth prefixes (RV-33)', () => {
  // Plugin code calls the Gateway with a call token and the runner calls the run list
  // with its key; neither has a session cookie. The handlers authenticate themselves
  // and never honour the cookie, X-Internal-Key or getEffectiveUser.
  test.each([
    '/api/plugin-gateway/v1/data/get',
    '/api/plugin-gateway/v1/session/read',
    '/api/plugin-runner/v1/run-list',
  ])('%s passes the middleware with no cookie', async (path) => {
    const res = await middleware(makeRequest(path))
    expect(res.status).toBe(200)
    expect(res.headers.get('location')).toBeNull()
  })

  test.each([
    '/api/plugin-gateway/v10/data/get',
    '/api/plugin-gateway/v1',
    '/api/plugin-gateway',
    '/api/plugin-gatewayx/v1/data/get',
    '/api/plugin-runner/v2/run-list',
    '/api/plugin-runnerx/v1/run-list',
    '/api/plugins/status',
    '/api/plugins',
    '/api/internal/plugins/reconcile',
  ])('%s still needs a session', async (path) => {
    const res = await middleware(makeRequest(path))
    expect(res.status).toBe(401)
  })

  test.each(['/api/plugin-gateway/v1/data/get', '/api/plugin-runner/v1/run-list'])(
    '%s never carries user headers, not even ones the caller sent', async (path) => {
      const res = await middleware(makeRequest(path, {
        headers: { 'x-user-id': 'admin-user', 'x-user-role': 'admin', authorization: 'Bearer t' },
      }))
      expect(res.status).toBe(200)
      // The headers the handler receives are exactly this list (Next.js request override).
      const forwarded = (res.headers.get('x-middleware-override-headers') ?? '').split(',')
      expect(forwarded).toContain('authorization')
      expect(forwarded).not.toContain('x-user-id')
      expect(forwarded).not.toContain('x-user-role')
      expect(res.headers.get('x-middleware-request-x-user-id')).toBeNull()
    })
})

describe('the /plugins page', () => {
  test('signed in: the page itself', async () => {
    const res = await middleware(makeRequest('/plugins', { cookie: await createTestToken('user-1', 'admin') }))
    expect(res.headers.get('x-middleware-rewrite')).toBeNull()
  })

  test('signed out: the login redirect as for any page', async () => {
    const res = await middleware(makeRequest('/plugins'))
    expect(res.headers.get('location')).toContain('/login')
  })
})

/* ------------------------------------------------------------------ */
/*  Invite links (step 2.9): public only while the identity switch is on */
/* ------------------------------------------------------------------ */

describe('invite public (step 2.9)', () => {
  const on = async () => (await import('./lib/authz/flags')).setFlagsForTests({ identity: true })
  const off = async () => (await import('./lib/authz/flags')).setFlagsForTests({ identity: false })

  test.each(['/invite', '/invite/some-token', '/api/invite/state', '/api/invite/accept'])(
    'switch on: %s passes with no cookie, no referrer',
    async (path) => {
      await on()
      const res = await middleware(makeRequest(path))
      expect(res.status).toBe(200)
      expect(res.headers.get('location')).toBeNull()
      expect(res.headers.get('referrer-policy')).toBe('no-referrer')
      await off()
    },
  )

  test('switch on: a client cannot hand the handler a user id', async () => {
    await on()
    const res = await middleware(makeRequest('/api/invite/state', { headers: { 'x-user-id': 'admin-1', 'x-user-role': 'admin' } }))
    // The headers the handler receives are exactly this list (Next.js request override).
    const forwarded = res.headers.get('x-middleware-override-headers')
    expect(forwarded).not.toBeNull()
    expect(forwarded!.split(',')).not.toContain('x-user-id')
    expect(forwarded!.split(',')).not.toContain('x-user-role')
    expect(res.headers.get('x-middleware-request-x-user-id')).toBeNull()
    expect(res.headers.get('x-middleware-request-x-user-role')).toBeNull()
    await off()
  })

  test.each(['/invitex', '/inviter/x', '/api/invites', '/api/invite-state', '/api/users/invite'])(
    'switch on: %s is not public',
    async (path) => {
      await on()
      const res = await middleware(makeRequest(path))
      expect(res.status === 401 || res.headers.get('location')?.endsWith('/login')).toBe(true)
      await off()
    },
  )

  test('switch off: the invite paths are like any unknown path (sign-in redirect, 401)', async () => {
    await off()
    const page = await middleware(makeRequest('/invite/some-token'))
    expect(page.headers.get('location')).toBe('http://localhost:3000/login')
    expect((await middleware(makeRequest('/api/invite/state'))).status).toBe(401)
    expect((await middleware(makeRequest('/invite'))).headers.get('location')).toBe('http://localhost:3000/login')
  })
})
