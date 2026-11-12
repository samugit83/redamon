/**
 * BOLA wiring for the scan/pipeline [projectId] routes (A4) — representative:
 * recon start. A cross-user guardProject denial short-circuits before the route
 * forwards to the orchestrator (no scan spawned for another user's project).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
const mockOrchestratorFetch = vi.fn()
const mockProjectFindUnique = vi.fn()
const mockStart = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuardProject(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) } },
}))
// The scan itself (including the snapshot freeze) lives behind startFullScan; for
// a denied caller it must never run at all.
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'victim' }) }))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => mockStart(...a) }))

import { POST } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (projectId: string) => ({ params: Promise.resolve({ projectId }) })
function post(): NextRequest {
  return new NextRequest('http://x/api/recon/victimProj/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectFindUnique.mockResolvedValue({ id: 'victimProj', userId: 'victim' })
  mockOrchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({}) })
  mockStart.mockResolvedValue({
    ok: true, state: {}, versionId: 'v2', versionSeq: 2, versionLabel: 'Scan 2',
    frozenVersionId: 'v1', frozenNodeCount: 10, scanJobId: 'job1',
  })
})

describe('POST /api/recon/[projectId]/start — BOLA', () => {
  test('EXPLOIT: cross-user start → 404, orchestrator NOT called, no snapshot taken', async () => {
    mockGuardProject.mockResolvedValue(NOT_FOUND)
    const res = await POST(post(), params('victimProj'))
    expect(res.status).toBe(404)
    // A denied caller must not be able to start a scan — or trigger a snapshot —
    // on another user's project.
    expect(mockStart).not.toHaveBeenCalled()
  })

  test('owner → guard passes, proceeds past the guard', async () => {
    mockGuardProject.mockResolvedValue(null)
    await POST(post(), params('victimProj'))
    expect(mockGuardProject).toHaveBeenCalledWith('victimProj')
    expect(mockStart).toHaveBeenCalled()
  })
})
