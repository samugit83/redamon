/**
 * BOLA / impersonation exploit-repro — GET/PUT/DELETE /api/projects/[id].
 *
 * The operator-reported bug: an admin simulating user X pastes a URL containing a
 * projectId owned by a DIFFERENT user Y and sees Y's project. Root cause: the route
 * did a bare findUnique with no ownership check. Fix: requireProjectAccess(eff, id)
 * (S15/E15), with an X-Internal-Key carve-out for the agent/orchestrator.
 *
 * Cross-user access is reported as 404 (anti-enumeration). Enforcement is ON by
 * default; access.test.ts proves no value of ACCESS_ENFORCE opts out.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProjectFindUnique = vi.fn()
const mockProjectDelete = vi.fn()
const mockGetEffectiveUser = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockProjectFindUnique(...a),
      delete: (...a: unknown[]) => mockProjectDelete(...a),
    },
    // Engagement authorizations are archived before a delete rather than
    // cascading with it; a project with none needs no archive at all.
    engagementAuthorization: { count: async () => 0 },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn().mockResolvedValue({ ok: true, json: async () => ({ deleted: [] }) }) }))
// Real access.ts guards, but drive their effective-user + internal inputs.
vi.mock('@/lib/session', () => ({ isInternalRequest: (...a: unknown[]) => mockIsInternal(...a), isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET, DELETE } from './route'

// requireProjectAccess (real) resolves the owner via prisma.project.findUnique.
// The GET handler then does a SECOND findUnique (with includes) for the payload.
function wireProjectOwner(ownerId: string) {
  mockProjectFindUnique.mockImplementation((args: { select?: unknown }) =>
    args?.select
      ? Promise.resolve({ id: 'proj-Y', userId: ownerId }) // requireProjectAccess probe
      : Promise.resolve({ id: 'proj-Y', userId: ownerId, name: 'Y project', targetDomain: 'y.tld', user: { id: ownerId } }),
  )
}
function get(): NextRequest { return new NextRequest('http://x/api/projects/proj-Y') }
function del(): NextRequest { return new NextRequest('http://x/api/projects/proj-Y', { method: 'DELETE' }) }
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE // default = enforce
  mockProjectDelete.mockResolvedValue({ id: 'proj-Y', userId: 'victim' })
})

describe('GET /api/projects/[id] — BOLA / impersonation', () => {
  test('EXPLOIT: admin simulating X (eff=attacker) requests Y-owned project → 404', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    wireProjectOwner('victim')
    const res = await GET(get(), params('proj-Y'))
    expect(res.status).toBe(404)
    expect(await res.text()).not.toContain('y.tld')
  })

  test('owner (eff === project owner) → 200', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetEffectiveUser.mockResolvedValue({ userId: 'victim' })
    wireProjectOwner('victim')
    const res = await GET(get(), params('proj-Y'))
    expect(res.status).toBe(200)
  })

  test('internal-key caller (agent) → 200 (carve-out, no session)', async () => {
    mockIsInternal.mockReturnValue(true)
    wireProjectOwner('victim')
    const res = await GET(get(), params('proj-Y'))
    expect(res.status).toBe(200)
    expect(mockGetEffectiveUser).not.toHaveBeenCalled()
  })
})

describe('DELETE /api/projects/[id] — BOLA', () => {
  test('EXPLOIT: cross-user delete → 404, no delete', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    wireProjectOwner('victim')
    const res = await DELETE(del(), params('proj-Y'))
    expect(res.status).toBe(404)
    expect(mockProjectDelete).not.toHaveBeenCalled()
  })

  test('owner delete → 200', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'victim' })
    wireProjectOwner('victim')
    const res = await DELETE(del(), params('proj-Y'))
    expect(res.status).toBe(200)
    expect(mockProjectDelete).toHaveBeenCalled()
  })
})
