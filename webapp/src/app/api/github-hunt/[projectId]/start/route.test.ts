/**
 * GitHub Secret Hunt start: a third-party engagement is held to the full
 * start's engagement rule (R-11). The hunt reads an organization's
 * repositories, which is why the queued start already checks it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  countAuthorizations: vi.fn(),
  orchestratorFetch: vi.fn(),
  recordScanStart: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/scanTimeline', () => ({ recordScanStart: (...a: unknown[]) => h.recordScanStart(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
// The hunt requires a prior recon output file; make it present.
vi.mock('fs', async orig => ({ ...(await orig<typeof import('fs')>()), existsSync: () => true }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    engagementAuthorization: {
      count: (...a: unknown[]) => h.countAuthorizations(...a),
      findFirst: async () => null,
    },
  },
}))

import { POST } from './route'

const call = () => POST(
  new NextRequest('http://localhost/api/github-hunt/p1/start', { method: 'POST' }),
  { params: Promise.resolve({ projectId: 'p1' }) },
)

const project = (over: Record<string, unknown> = {}) => ({
  id: 'p1', userId: 'u1', name: 'Hunt', targetDomain: 'example.com', ipMode: false, targetIps: [],
  domainBatchMode: false, domainBatchHosts: [],
  engagementKind: 'third_party', roeGlobalMaxRps: 3, ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.findProject.mockResolvedValue(project())
  h.countAuthorizations.mockResolvedValue(1)
  h.recordScanStart.mockResolvedValue(null)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'starting' }) })
})

describe('a third-party engagement (R-11)', () => {
  test('with no rate ceiling is refused with 422 before the orchestrator', async () => {
    h.findProject.mockResolvedValue(project({ roeGlobalMaxRps: 0 }))
    const res = await call()
    expect(res.status).toBe(422)
    const { error } = await res.json()
    expect(error).toMatch(/^This is a third-party engagement and it is not startable: /)
    expect(error).toContain('roeGlobalMaxRps is 0')
    expect(error).toMatch(/Use preflight_scope_check to see the whole picture\.$/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test('with no authorization record is refused too', async () => {
    h.countAuthorizations.mockResolvedValue(0)
    const res = await call()
    expect(res.status).toBe(422)
    expect((await res.json()).error).toContain('No authorization record')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('with a ceiling and an authorization record it starts', async () => {
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
    expect(h.recordScanStart).toHaveBeenCalledWith(expect.objectContaining({ kind: 'github_hunt' }))
  })

  test('an internal project with no ceiling is not held by it', async () => {
    h.findProject.mockResolvedValue(project({ engagementKind: 'internal', roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(0)
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })

  test('a missing project keeps its 404', async () => {
    h.findProject.mockResolvedValue(null)
    const res = await call()
    expect(res.status).toBe(404)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})
