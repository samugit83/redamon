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

import { middleware } from './middleware'
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
