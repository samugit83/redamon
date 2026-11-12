/**
 * Stored-XSS hardening — GET /api/projects/[id]/reports/[reportId].
 *
 * Report HTML embeds target-influenced strings and is served inline, so the
 * response must block MIME sniffing and neutralize script execution with a
 * restrictive CSP.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireEffectiveUser = vi.fn()
const mockRequireProjectAccess = vi.fn()
const mockReportFindFirst = vi.fn()
const mockExistsSync = vi.fn()
const mockReadFileSync = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: (...a: unknown[]) => mockRequireEffectiveUser(...a),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: { report: { findFirst: (...a: unknown[]) => mockReportFindFirst(...a), delete: vi.fn() } },
}))
vi.mock('fs', () => ({
  existsSync: (...a: unknown[]) => mockExistsSync(...a),
  readFileSync: (...a: unknown[]) => mockReadFileSync(...a),
  unlinkSync: vi.fn(),
}))

import { GET, DELETE } from './route'

const params = (id: string, reportId: string) => ({ params: Promise.resolve({ id, reportId }) })

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEffectiveUser.mockResolvedValue({ userId: 'u1', role: 'user' })
  mockRequireProjectAccess.mockResolvedValue(null) // allowed
  mockReportFindFirst.mockResolvedValue({
    id: 'r1', projectId: 'p1', filePath: '/data/reports/r.html', filename: 'r.html',
  })
  mockExistsSync.mockReturnValue(true)
  mockReadFileSync.mockReturnValue(Buffer.from('<html><body>report</body></html>'))
})

describe('GET report — security headers', () => {
  test('serves the report with nosniff and a script-blocking CSP', async () => {
    const res = await GET(new NextRequest('http://x'), params('p1', 'r1'))
    expect(res.status).toBe(200)
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
    const csp = res.headers.get('Content-Security-Policy') || ''
    expect(csp).toContain("default-src 'none'")
    expect(csp).toContain("frame-ancestors 'none'")
    // no 'script-src' allowance -> scripts fall back to default-src 'none'
    expect(csp).not.toMatch(/script-src\s+[^;]*'unsafe-inline'/)
  })

  test('still enforces project ownership before serving', async () => {
    mockRequireProjectAccess.mockResolvedValue(NextResponse.json({ error: 'not found' }, { status: 404 }))
    const res = await GET(new NextRequest('http://x'), params('p1', 'r1'))
    expect(res.status).toBe(404)
    expect(mockReadFileSync).not.toHaveBeenCalled()
  })
})

describe('a failure says why, never with the server path (G-22, P-33)', () => {
  test('a file read error answers its errno, not the message naming the path', async () => {
    mockReadFileSync.mockImplementation(() => {
      throw Object.assign(new Error("EACCES: permission denied, open '/data/reports/r.html'"), { code: 'EACCES' })
    })
    const res = await GET(new NextRequest('http://x'), params('p1', 'r1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Download failed', code: 'EACCES' })
  })

  test('a missing file keeps its specific 404 text', async () => {
    mockExistsSync.mockReturnValue(false)
    const res = await GET(new NextRequest('http://x'), params('p1', 'r1'))
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Report file not found on disk' })
  })

  test('a failed delete answers its code', async () => {
    mockReportFindFirst.mockRejectedValue(Object.assign(new Error('db'), { code: 'P1001' }))
    const res = await DELETE(new NextRequest('http://x', { method: 'DELETE' }), params('p1', 'r1'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Delete failed', code: 'P1001' })
  })
})
