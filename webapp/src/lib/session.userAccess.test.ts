/**
 * Unit tests for the REAL requireUserAccess ownership gate (STRIDE I1 closure).
 *
 * Run: npx vitest run src/lib/session.userAccess.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-xyz')

let authCookie: string | undefined

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && authCookie ? { value: authCookie } : undefined),
  })),
}))

// getSession reads role and existence from the database (HD-10): every account these
// tests sign in as, or act as, exists with the role its token claims.
const DB_ROLES: Record<string, string> = { 'victim': 'standard', 'attacker': 'standard', 'admin-1': 'admin' }
const dbUser = async ({ where }: { where: { id: string } }) =>
  DB_ROLES[where.id]
    ? { id: where.id, email: `${where.id}@e2e.local`, role: DB_ROLES[where.id], password: 'h', createdAt: new Date(0) }
    : null
vi.mock('@/lib/prisma', () => ({ default: { user: { findUnique: (a: { where: { id: string } }) => dbUser(a) } } }))

import { requireUserAccess } from './session'
import { createToken } from './auth'

function req(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://x/api/users/victim/settings', { headers })
}

beforeEach(() => {
  authCookie = undefined
})

describe('requireUserAccess', () => {
  test('internal-key caller -> allowed (null), no session needed', async () => {
    const r = await requireUserAccess(req({ 'x-internal-key': 'internal-key-xyz' }), 'victim')
    expect(r).toBeNull()
  })

  test('no session, no key -> 401', async () => {
    const r = await requireUserAccess(req(), 'victim')
    expect((r as NextResponse).status).toBe(401)
  })

  test('owner -> allowed (null)', async () => {
    authCookie = await createToken('victim', 'standard')
    const r = await requireUserAccess(req(), 'victim')
    expect(r).toBeNull()
  })

  test('EXPLOIT: standard user requesting another user -> 403', async () => {
    authCookie = await createToken('attacker', 'standard')
    const r = await requireUserAccess(req(), 'victim')
    expect((r as NextResponse).status).toBe(403)
  })

  test('admin requesting another user -> allowed (masked-read convenience preserved)', async () => {
    authCookie = await createToken('admin-1', 'admin')
    const r = await requireUserAccess(req(), 'victim')
    expect(r).toBeNull()
  })
})
