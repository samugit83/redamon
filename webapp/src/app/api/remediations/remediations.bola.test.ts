/**
 * BOLA wiring for remediations (A3-cont): cypherfix X-Internal-Key carve-out is
 * honored (agent triage/codefix keep working) but cross-user browser callers are
 * blocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockCreate = vi.fn()
const mockIsInternal = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { remediation: { create: (...a: unknown[]) => mockCreate(...a) } },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => mockIsInternal(...a) }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))

import { POST } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
function post(body: unknown): NextRequest {
  return new NextRequest('http://x/api/remediations', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
}
const REM = { projectId: 'victimProj', title: 't', description: 'd' }

beforeEach(() => {
  vi.clearAllMocks()
  mockCreate.mockResolvedValue({ id: 'r1', ...REM })
})

describe('POST /api/remediations — cypherfix carve-out + BOLA', () => {
  test('internal-key caller (cypherfix) → guard skipped, creates', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await POST(post(REM))
    expect(res.status).toBe(201)
    expect(mockRequireProjectAccess).not.toHaveBeenCalled()
    expect(mockCreate).toHaveBeenCalled()
  })

  test('EXPLOIT: browser cross-user → 404, no create', async () => {
    mockIsInternal.mockReturnValue(false)
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(post(REM))
    expect(res.status).toBe(404)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('browser owner → 201', async () => {
    mockIsInternal.mockReturnValue(false)
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'victimProj', userId: 'victim' } })
    const res = await POST(post(REM))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })
})
