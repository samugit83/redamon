/**
 * Unit tests for session helpers.
 *
 * Run: npx vitest run src/lib/session.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

// Mock environment
vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'test-internal-key-12345')

// Mock next/headers cookies
let mockCookieValue: string | undefined = undefined

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && mockCookieValue) {
        return { value: mockCookieValue }
      }
      return undefined
    },
  })),
}))

import { getSession, requireSession, requireAdmin, isInternalRequest } from './session'
import { createToken } from './auth'

/* ------------------------------------------------------------------ */
/*  getSession                                                         */
/* ------------------------------------------------------------------ */

describe('getSession', () => {
  beforeEach(() => {
    mockCookieValue = undefined
  })

  test('returns null when no cookie exists', async () => {
    const session = await getSession()
    expect(session).toBeNull()
  })

  test('returns session from valid token', async () => {
    const token = await createToken('user-abc', 'admin')
    mockCookieValue = token

    const session = await getSession()
    expect(session).not.toBeNull()
    expect(session!.userId).toBe('user-abc')
    expect(session!.role).toBe('admin')
  })

  test('returns null for invalid token', async () => {
    mockCookieValue = 'invalid-token'

    const session = await getSession()
    expect(session).toBeNull()
  })

  test('returns session with standard role', async () => {
    const token = await createToken('user-std', 'standard')
    mockCookieValue = token

    const session = await getSession()
    expect(session).not.toBeNull()
    expect(session!.role).toBe('standard')
  })
})

/* ------------------------------------------------------------------ */
/*  requireSession                                                     */
/* ------------------------------------------------------------------ */

describe('requireSession', () => {
  beforeEach(() => {
    mockCookieValue = undefined
  })

  test('returns NextResponse 401 when no session', async () => {
    const result = await requireSession()
    expect(result).toBeInstanceOf(NextResponse)
    const res = result as NextResponse
    expect(res.status).toBe(401)
  })

  test('returns session when valid token exists', async () => {
    const token = await createToken('user-ok', 'admin')
    mockCookieValue = token

    const result = await requireSession()
    expect(result).not.toBeInstanceOf(NextResponse)
    expect((result as { userId: string }).userId).toBe('user-ok')
  })
})

/* ------------------------------------------------------------------ */
/*  requireAdmin                                                       */
/* ------------------------------------------------------------------ */

describe('requireAdmin', () => {
  beforeEach(() => {
    mockCookieValue = undefined
  })

  test('returns 401 when no session', async () => {
    const result = await requireAdmin()
    expect(result).toBeInstanceOf(NextResponse)
    expect((result as NextResponse).status).toBe(401)
  })

  test('returns 403 when user is standard', async () => {
    const token = await createToken('user-std', 'standard')
    mockCookieValue = token

    const result = await requireAdmin()
    expect(result).toBeInstanceOf(NextResponse)
    expect((result as NextResponse).status).toBe(403)
  })

  test('returns session when user is admin', async () => {
    const token = await createToken('user-admin', 'admin')
    mockCookieValue = token

    const result = await requireAdmin()
    expect(result).not.toBeInstanceOf(NextResponse)
    expect((result as { userId: string; role: string }).role).toBe('admin')
  })
})

/* ------------------------------------------------------------------ */
/*  isInternalRequest                                                  */
/* ------------------------------------------------------------------ */

describe('isInternalRequest', () => {
  function makeRequest(headers: Record<string, string> = {}): NextRequest {
    const req = new NextRequest('http://localhost:3000/api/test', {
      headers,
    })
    return req
  }

  test('returns false when no header present', () => {
    const req = makeRequest()
    expect(isInternalRequest(req)).toBe(false)
  })

  test('returns false when header value is wrong', () => {
    const req = makeRequest({ 'x-internal-key': 'wrong-key' })
    expect(isInternalRequest(req)).toBe(false)
  })

  test('returns true when header matches INTERNAL_API_KEY', () => {
    const req = makeRequest({ 'x-internal-key': 'test-internal-key-12345' })
    expect(isInternalRequest(req)).toBe(true)
  })

  test('returns false when INTERNAL_API_KEY is "changeme"', () => {
    const originalKey = process.env.INTERNAL_API_KEY
    process.env.INTERNAL_API_KEY = 'changeme'
    const req = makeRequest({ 'x-internal-key': 'changeme' })
    expect(isInternalRequest(req)).toBe(false)
    process.env.INTERNAL_API_KEY = originalKey
  })
})
