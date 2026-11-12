/**
 * Unit tests for the admin-only act-as (impersonation) endpoint.
 *
 * Run: npx vitest run src/app/api/auth/act-as/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const mockRequireAdmin = vi.fn()
const mockGetSession = vi.fn()
vi.mock('@/lib/session', () => ({
  requireAdmin: () => mockRequireAdmin(),
  getSession: () => mockGetSession(),
}))

const mockUserFindUnique = vi.fn()
// The instance settings row (identity switch on): no Root here, the session lifetimes of step 2.11.
const mockInstanceFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: unknown) => mockUserFindUnique(a) },
    instanceSettings: { findUnique: (a: unknown) => mockInstanceFindUnique(a) },
  },
}))

const mockWriteActAsAudit = vi.fn().mockResolvedValue(undefined)
vi.mock('@/lib/audit', () => ({
  writeActAsAudit: (a: unknown) => mockWriteActAsAudit(a),
  writeAudit: vi.fn(),
}))

import bcrypt from 'bcryptjs'
import { decodeJwt } from 'jose'
import { __resetThrottle } from '@/lib/loginThrottle'
import { createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { POST, DELETE } from './route'

function req(body?: unknown): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/act-as', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  __resetThrottle()
})

describe('POST /api/auth/act-as', () => {
  test('non-admin -> passes through requireAdmin 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(403)
  })

  test('admin acting as an existing user -> sets httpOnly act-as cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X' })
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: 'user-X' })
    const setCookie = res.headers.get('set-cookie') || ''
    expect(setCookie).toContain('redamon-act-as=')
    expect(setCookie).toMatch(/HttpOnly/i)
  })

  test('writes act-as audit on mint', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X' })
    await POST(req({ targetUserId: 'user-X' }))
    expect(mockWriteActAsAudit).toHaveBeenCalledWith(
      expect.objectContaining({ adminId: 'admin-1', targetUserId: 'user-X', event: 'start' })
    )
  })

  test('writes act-as end audit on self-clear', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    await POST(req({ targetUserId: 'admin-1' }))
    expect(mockWriteActAsAudit).toHaveBeenCalledWith(
      expect.objectContaining({ adminId: 'admin-1', event: 'end' })
    )
  })

  test('admin acting as a nonexistent user -> 404', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue(null)
    const res = await POST(req({ targetUserId: 'ghost' }))
    expect(res.status).toBe(404)
  })

  test('missing targetUserId -> 400', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({}))
    expect(res.status).toBe(400)
  })

  test('acting as self -> clears the cookie (stop simulating)', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({ targetUserId: 'admin-1' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })
})

describe('DELETE /api/auth/act-as', () => {
  test('non-admin -> 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await DELETE(req())
    expect(res.status).toBe(403)
  })

  test('admin -> clears the cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await DELETE(req())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })

  // HD-14: the cookie is decoded before it is cleared, so the end row names whom
  // the admin stopped acting as.
  const delWithCookie = (cookie: string) =>
    new NextRequest('http://localhost:3000/api/auth/act-as', { method: 'DELETE', headers: { cookie } })

  test('end row carries the target', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const token = await createActAsToken('admin-1', 'user-X')
    const res = await DELETE(delWithCookie(`redamon-act-as=${token}`))
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
    expect(mockWriteActAsAudit).toHaveBeenCalledTimes(1)
    expect(mockWriteActAsAudit).toHaveBeenCalledWith({ adminId: 'admin-1', targetUserId: 'user-X', event: 'end' })
  })

  test('a DELETE with no act-as cookie writes no row', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await DELETE(req())
    expect(res.status).toBe(200)
    expect(mockWriteActAsAudit).not.toHaveBeenCalled()
  })

  test('a cookie another admin minted, or one that does not verify, writes no row and is still cleared', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const foreign = await createActAsToken('admin-2', 'user-X')
    for (const cookie of [`redamon-act-as=${foreign}`, 'redamon-act-as=not.a.token']) {
      const res = await DELETE(delWithCookie(cookie))
      expect(res.status).toBe(200)
      expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
    }
    expect(mockWriteActAsAudit).not.toHaveBeenCalled()
  })
})

describe('act-as — a failure inside the handler', () => {
  test('POST answers a sentence and a code instead of an empty-bodied 500', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server"), { code: 'P1001' }))
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not switch user', code: 'P1001' })
  })

  test('DELETE answers a sentence and a code too', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockWriteActAsAudit.mockRejectedValueOnce(Object.assign(new Error('Timed out'), { code: 'P2024' }))
    // The end row is written only for an act-as cookie this admin minted (HD-14).
    const token = await createActAsToken('admin-1', 'user-X')
    const res = await DELETE(new NextRequest('http://localhost:3000/api/auth/act-as', {
      method: 'DELETE', headers: { cookie: `redamon-act-as=${token}` },
    }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not stop switching user', code: 'P2024' })
  })
})

// The step-up (HD-09, ID-25): acting as an admin borrows an admin's powers, so it
// needs the password of the REAL signed-in admin, never the target's.
describe('acting as an admin needs step-up', () => {
  const ADMIN_PW = 'admin-one-passphrase'
  const rows: Record<string, { id: string; role: string; password: string }> = {
    'admin-1': { id: 'admin-1', role: 'admin', password: bcrypt.hashSync(ADMIN_PW, 4) },
    'admin-2': { id: 'admin-2', role: 'admin', password: bcrypt.hashSync('admin-two-passphrase', 4) },
    'user-X': { id: 'user-X', role: 'standard', password: bcrypt.hashSync('member-passphrase', 4) },
  }
  beforeEach(() => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockGetSession.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockImplementation(async (a: { where: { id: string } }) => rows[a.where.id] ?? null)
  })

  test('acting as an admin needs step-up', async () => {
    const missing = await POST(req({ targetUserId: 'admin-2' }))
    expect(missing.status).toBe(403)
    expect((await missing.json()).code).toBe('step_up_required')
    expect(missing.headers.get('set-cookie')).toBeNull()

    const wrong = await POST(req({ targetUserId: 'admin-2', stepUpPassword: 'admin-two-passphrase' }))
    expect(wrong.status).toBe(403)
    expect((await wrong.json()).code).toBe('step_up_failed')
    expect(mockWriteActAsAudit).not.toHaveBeenCalled()

    const ok = await POST(req({ targetUserId: 'admin-2', stepUpPassword: ADMIN_PW }))
    expect(ok.status).toBe(200)
    expect(await ok.json()).toEqual({ actingAs: 'admin-2' })
    expect(ok.headers.get('set-cookie') || '').toContain('redamon-act-as=')
    expect(mockWriteActAsAudit).toHaveBeenCalledWith(expect.objectContaining({ targetUserId: 'admin-2', event: 'start' }))
  })

  test('acting as a member needs none', async () => {
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(200)
  })

  test('the target is read with its role', async () => {
    await POST(req({ targetUserId: 'user-X' }))
    expect(mockUserFindUnique).toHaveBeenCalledWith({ where: { id: 'user-X' }, select: { id: true, role: true } })
  })

  test('an unknown target is still a 404, before any password check', async () => {
    const res = await POST(req({ targetUserId: 'ghost', stepUpPassword: 'whatever' }))
    expect(res.status).toBe(404)
  })
})

describe("the cookie's maxAge equals the token lifetime on act-as (step 2.11, ID-24)", () => {
  function issued(res: Response): { lifetime: number; maxAge: number } {
    const line = res.headers.getSetCookie().find((c) => c.startsWith('redamon-act-as='))!
    const c = decodeJwt(line.slice('redamon-act-as='.length).split(';')[0])
    return { lifetime: c.exp! - c.iat!, maxAge: Number(/Max-Age=(\d+)/i.exec(line)?.[1]) }
  }

  beforeEach(() => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X', role: 'standard' })
    clearInstanceRootCacheForTests()
  })

  test('identity switch on: as long as an admin session (12 h by default)', async () => {
    setFlagsForTests({ identity: true })
    try {
      mockInstanceFindUnique.mockResolvedValue({ rootUserId: null, adminSessionTtlHours: 12 })
      expect(issued(await POST(req({ targetUserId: 'user-X' })))).toEqual({ lifetime: 12 * 3600, maxAge: 12 * 3600 })
      mockInstanceFindUnique.mockResolvedValue({ rootUserId: null, adminSessionTtlHours: 2 })
      expect(issued(await POST(req({ targetUserId: 'user-X' })))).toEqual({ lifetime: 2 * 3600, maxAge: 2 * 3600 })
    } finally {
      setFlagsForTests(null)
    }
  })

  test('switch off: today\'s 12 h, no instance row read', async () => {
    setFlagsForTests({ identity: false })
    try {
      expect(issued(await POST(req({ targetUserId: 'user-X' })))).toEqual({ lifetime: 12 * 3600, maxAge: 12 * 3600 })
      expect(mockInstanceFindUnique).not.toHaveBeenCalled()
    } finally {
      setFlagsForTests(null)
    }
  })
})
