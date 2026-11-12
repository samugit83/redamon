/**
 * STRIDE I1 (single-item closure) — GET /api/users/[id]/tradecraft-resources
 * ownership + githubTokenOverride unmask gating (route wiring).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindMany = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({
  default: { userTradecraftResource: { findMany: (...a: unknown[]) => mockFindMany(...a) } },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))

import { GET } from './route'

const GH = 'ghp_TRADECRAFTSECRET5555'
const RES = [{ id: 'r1', userId: 'victim', name: 'X', githubTokenOverride: GH }]
const FORBIDDEN = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
function req(url: string): NextRequest { return new NextRequest(url) }
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  mockFindMany.mockReset().mockResolvedValue(RES)
  mockRequireUserAccess.mockReset()
  mockIsInternal.mockReset()
})

describe('GET /api/users/[id]/tradecraft-resources — I1', () => {
  test('EXPLOIT: guard denies (cross-user) → 403, no token, no DB read', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await GET(req('http://x/api/users/victim/tradecraft-resources?internal=true'), params('victim'))
    expect(res.status).toBe(403)
    expect(await res.text()).not.toContain(GH)
    expect(mockFindMany).not.toHaveBeenCalled()
  })

  test('owner with ?internal=true, no header → 200 masked', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await GET(req('http://x/api/users/victim/tradecraft-resources?internal=true'), params('victim'))
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(GH)
  })

  test('internal-key header + ?internal=true → 200 unmasked (agent path)', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/tradecraft-resources?internal=true'), params('victim'))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain(GH)
  })
})
