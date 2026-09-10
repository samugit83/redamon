/**
 * Strategy row 2: GVM must accept a Domain-batch project.
 *
 * The precondition was mode-aware for IP vs domain only: a batch project has an
 * empty targetDomain, so it fell into the domain branch and was rejected with
 * "Project has no target domain configured" - every follow-on scanner unreachable
 * on a batch project even after recon had populated the graph. GVM takes its
 * scope from recon_<id>.json (which the batch merges across all its groups), so
 * the host list existing is the only precondition it needs.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  orchestratorFetch: vi.fn(),
  existsSync: vi.fn(),
  recordScanStart: vi.fn(),
  guard: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))
vi.mock('@/lib/access', () => ({
  guardProject: (...a: unknown[]) => h.guard(...a),
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }),
  requireProjectAccess: vi.fn().mockResolvedValue({ project: { id: 'p1', userId: 'u1' } }),
}))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  recordScanStart: (...a: unknown[]) => h.recordScanStart(...a),
}))

import { POST } from './route'

const call = () => POST(
  new NextRequest('http://localhost/api/gvm/p1/start', { method: 'POST' }),
  { params: Promise.resolve({ projectId: 'p1' }) },
)

const BATCH = {
  id: 'p1', userId: 'u1', name: 'Batch', targetDomain: '', ipMode: false, targetIps: [],
  domainBatchMode: true, domainBatchHosts: ['a.example.com', 'b.other.com'],
}

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.existsSync.mockReturnValue(true)
  h.recordScanStart.mockResolvedValue(null)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'starting' }) })
  h.findProject.mockResolvedValue(BATCH)
})

describe('domain batch precondition', () => {
  test('a batch project with hosts passes the target precondition', async () => {
    const res = await call()
    expect(res.status).not.toBe(400)
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })

  test('it does not report a missing target domain', async () => {
    const res = await call()
    const body = await res.json().catch(() => ({}))
    expect(JSON.stringify(body)).not.toContain('no target domain')
  })

  test('a batch project with no hosts is refused', async () => {
    h.findProject.mockResolvedValue({ ...BATCH, domainBatchHosts: [] })
    const res = await call()
    expect(res.status).toBe(400)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('the recon file is still required', async () => {
    // GVM scopes itself from the merged canonical file; without it there is
    // nothing to scan whatever the target mode.
    h.existsSync.mockReturnValue(false)
    const res = await call()
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('Recon data not found')
  })

  test('a single-domain project with no target still fails as before', async () => {
    h.findProject.mockResolvedValue({
      ...BATCH, domainBatchMode: false, domainBatchHosts: [], targetDomain: '',
    })
    const res = await call()
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('no target domain')
  })

  test('an IP project is unaffected', async () => {
    h.findProject.mockResolvedValue({
      ...BATCH, domainBatchMode: false, domainBatchHosts: [], ipMode: true, targetIps: ['10.0.0.1'],
    })
    const res = await call()
    expect(res.status).not.toBe(400)
  })

  test('ownership is still enforced before anything else', async () => {
    const { NextResponse } = await import('next/server')
    h.guard.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await call()
    expect(res.status).toBe(404)
    expect(h.findProject).not.toHaveBeenCalled()
  })
})
