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
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (a: unknown) => mockUserFindUnique(a) } },
}))

const mockWriteActAsAudit = vi.fn().mockResolvedValue(undefined)
vi.mock('@/lib/audit', () => ({
  writeActAsAudit: (a: unknown) => mockWriteActAsAudit(a),
  writeAudit: vi.fn(),
}))

import bcrypt from 'bcryptjs'
import { __resetThrottle } from '@/lib/loginThrottle'
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
    const res = await DELETE(new NextRequest('http://localhost:3000/api/auth/act-as', { method: 'DELETE' }))
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
