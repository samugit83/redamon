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
  legacy: vi.fn(),
  countAuthorizations: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    engagementAuthorization: {
      count: (...a: unknown[]) => h.countAuthorizations(...a),
      findFirst: async () => null,
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({
  guardProject: (...a: unknown[]) => h.guard(...a),
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }),
  requireProjectAccess: vi.fn().mockResolvedValue({ project: { id: 'p1', userId: 'u1' } }),
}))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  recordScanStart: (...a: unknown[]) => h.recordScanStart(...a),
}))

vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
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
  h.countAuthorizations.mockResolvedValue(0)
  h.legacy.mockResolvedValue([])
})

describe('a third-party engagement (R-11)', () => {
  // GVM sweeps ports on somebody else's estate: a manual start is held to the
  // same engagement rule as the full start and the queued start.
  test('with no rate ceiling is refused with 422 before the orchestrator', async () => {
    h.findProject.mockResolvedValue({ ...BATCH, engagementKind: 'third_party', roeGlobalMaxRps: 0 })
    h.countAuthorizations.mockResolvedValue(1)
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
    h.findProject.mockResolvedValue({ ...BATCH, engagementKind: 'third_party', roeGlobalMaxRps: 3 })
    const res = await call()
    expect(res.status).toBe(422)
    expect((await res.json()).error).toContain('No authorization record')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('with a ceiling and an authorization record it starts', async () => {
    h.findProject.mockResolvedValue({ ...BATCH, engagementKind: 'third_party', roeGlobalMaxRps: 3 })
    h.countAuthorizations.mockResolvedValue(1)
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
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

describe('an old-model graph', () => {
  test('refuses the start with 409 and names the old Domain nodes', async () => {
    h.legacy.mockResolvedValue(['co.uk'])
    const res = await call()
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toMatch(/built before the current scope model; run a full recon first/)
    expect(body.legacyGraph).toEqual(['co.uk'])
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('is asked with the derived scope groups of the batch', async () => {
    await call()
    expect(h.legacy.mock.calls[0][0]).toBe('u1')
    expect(h.legacy.mock.calls[0][2].map((g: { scanRoot: string }) => g.scanRoot))
      .toEqual(['example.com', 'other.com'])
  })

  test('an unanswerable check lets the start through', async () => {
    h.legacy.mockResolvedValue(null)
    const res = await call()
    expect(res.status).toBe(200)
  })
})

describe('a start the orchestrator or the DB refuses', () => {
  beforeEach(() => {
    h.findProject.mockResolvedValue({ ...BATCH, domainBatchMode: false, domainBatchHosts: [], targetDomain: 'example.com' })
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  test('a non-JSON 500 still says which status the orchestrator answered', async () => {
    h.orchestratorFetch.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await call()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to start GVM scan', code: 'orchestrator_error', upstreamStatus: 500,
    })
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test("the orchestrator's own reason code is passed through", async () => {
    h.orchestratorFetch.mockResolvedValue(new Response(
      JSON.stringify({ detail: { detail: 'GVM container could not be created', code: 'spawn_failed' } }),
      { status: 500 },
    ))
    const body = await (await call()).json()
    expect(body).toMatchObject({ error: 'GVM container could not be created', code: 'spawn_failed', upstreamStatus: 500 })
  })

  test('a memory-governor refusal keeps its limit for the queue offer', async () => {
    const limit = { limitType: 'ram', detail: 'Not enough memory', current: 9, ceiling: 8 }
    h.orchestratorFetch.mockResolvedValue(new Response(JSON.stringify({ detail: limit }), { status: 409 }))
    const res = await call()
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.limit).toEqual(limit)
    expect(body.upstreamStatus).toBe(409)
    expect(typeof body.error).toBe('string')
  })

  test('an unreachable orchestrator is a 503 naming it, with the errno', async () => {
    const err = new TypeError('fetch failed')
    ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })
    h.orchestratorFetch.mockRejectedValue(err)
    const res = await call()
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to start GVM scan', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('a DB failure answers its Prisma code, never the message', async () => {
    h.findProject.mockRejectedValue(Object.assign(
      new Error("Can't reach database server while reading target example.com"),
      { name: 'PrismaClientInitializationError', code: 'P1001' },
    ))
    const res = await call()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to start GVM scan', code: 'P1001' })
    expect(JSON.stringify(body)).not.toContain('example.com')
  })
})

describe('the job credential (step 1.16)', () => {
  test('the orchestrator call carries a job credential for the project owner', async () => {
    const { verifyJobCredential } = await import('@/lib/authz/machineCredential')
    const saved = process.env.INTERNAL_API_KEY
    process.env.INTERNAL_API_KEY = 'start-path-test-master'
    try {
      h.findProject.mockResolvedValue({ ...BATCH, engagementKind: 'third_party', roeGlobalMaxRps: 3 })
      h.countAuthorizations.mockResolvedValue(1)
      const res = await call()
      expect(res.status).toBe(200)
      const sent = JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)
      expect(verifyJobCredential(sent.job_credential)).toMatchObject({ aud: 'scan', ten: 'u1', pid: 'p1' })
      expect(sent.user_id).toBe('u1')
    } finally {
      if (saved === undefined) delete process.env.INTERNAL_API_KEY
      else process.env.INTERNAL_API_KEY = saved
    }
  })
})
