/**
 * Partial recon start: the history row records the scope the orchestrator
 * GRANTED (its returned `roots`), never the scope the client asked for.
 *
 * Fixture roots are alpha.test / beta.test / gamma.test only.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  findUnique: vi.fn(),
  orchestratorFetch: vi.fn(),
  recordScanStart: vi.fn(),
  legacy: vi.fn(),
  countAuthorizations: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'u1' }) }))
vi.mock('@/lib/scanTimeline', () => ({ recordScanStart: (...a: unknown[]) => h.recordScanStart(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findUnique(...a) },
    engagementAuthorization: {
      count: (...a: unknown[]) => h.countAuthorizations(...a),
      findFirst: async () => null,
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))

import { POST } from './route'

function post(body: unknown) {
  return POST(
    new NextRequest('http://x/api/recon/p1/partial', { method: 'POST', body: JSON.stringify(body) }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.findUnique.mockResolvedValue({ id: 'p1', userId: 'u1', targetDomain: '' })
  h.countAuthorizations.mockResolvedValue(0)
  h.legacy.mockResolvedValue([])
  h.orchestratorFetch.mockResolvedValue({
    ok: true,
    json: async () => ({ run_id: 'r1', status: 'running', roots: ['alpha.test', 'beta.test'] }),
  })
})

describe('partial recon start', () => {
  test('forwards the requested roots to the orchestrator', async () => {
    await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test', 'beta.test', 'evil.test'] } })
    const sent = JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)
    expect(sent.graph_inputs).toEqual({ domains: ['alpha.test', 'beta.test', 'evil.test'] })
    expect(sent.user_id).toBe('u1')
  })

  test('records the roots the orchestrator granted, not the request', async () => {
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test', 'beta.test', 'evil.test'] } })
    expect(res.status).toBe(200)
    expect(h.recordScanStart).toHaveBeenCalledWith(expect.objectContaining({
      kind: 'partial_recon', runId: 'r1', targets: ['alpha.test', 'beta.test'],
    }))
  })

  test('an orchestrator without roots in its answer records none', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r2' }) })
    await post({ tool_id: 'Tlsx', graph_inputs: { domain: 'alpha.test' } })
    expect(h.recordScanStart.mock.calls[0][0].targets).toEqual([])
  })

  test('a refused start records nothing and passes the refusal on', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 400,
      json: async () => ({ detail: 'None of the requested domains is a target of this project.' }),
    })
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['evil.test'] } })
    expect(res.status).toBe(400)
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })
})

describe('a third-party engagement (R-11)', () => {
  // The full start refuses these with 422; a partial Nuclei or port scan
  // reaches the same estate, so it must be refused the same way.
  const thirdParty = (over: Record<string, unknown> = {}) => ({
    id: 'p1', userId: 'u1', targetDomain: 'alpha.test',
    engagementKind: 'third_party', roeGlobalMaxRps: 3, ...over,
  })

  test('with no rate ceiling is refused with 422 before the orchestrator', async () => {
    h.findUnique.mockResolvedValue(thirdParty({ roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(1)
    const res = await post({ tool_id: 'Nuclei', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(422)
    const { error } = await res.json()
    expect(error).toMatch(/^This is a third-party engagement and it is not startable: /)
    expect(error).toContain('roeGlobalMaxRps is 0')
    expect(error).toMatch(/Use preflight_scope_check to see the whole picture\.$/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test('with no authorization record is refused too', async () => {
    h.findUnique.mockResolvedValue(thirdParty())
    const res = await post({ tool_id: 'Naabu', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(422)
    expect((await res.json()).error).toContain('No authorization record')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('with a ceiling and an authorization record it starts', async () => {
    h.findUnique.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockResolvedValue(1)
    const res = await post({ tool_id: 'Nuclei', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
})

describe('an old-model graph (§4.11.6)', () => {
  test('refuses the start with 409 and the message, before any container', async () => {
    h.findUnique.mockResolvedValue({
      id: 'p1', userId: 'u1', targetDomain: '', domainBatchMode: true,
      domainBatchHosts: ['www.acme.co.uk', '*.beta.test'],
    })
    h.legacy.mockResolvedValue(['co.uk'])
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['acme.co.uk'] } })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toContain("This project's graph was built before the current scope model; run a full recon first")
    expect(body.code).toBe('legacy_graph')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.recordScanStart).not.toHaveBeenCalled()
    // the scope it judged is the PSL-regrouped one
    expect(h.legacy.mock.calls[0][2].map((g: { scanRoot: string }) => g.scanRoot))
      .toEqual(['acme.co.uk', 'beta.test'])
  })

  test('a check Neo4j could not answer lets the start through to the container backstop', async () => {
    h.legacy.mockResolvedValue(null)
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(200)
  })
})

describe('a partial start that got no answer says whether it may have started', () => {
  beforeEach(() => { vi.spyOn(console, 'error').mockImplementation(() => {}) })

  test('a refused connection is 503 orchestrator_unreachable: not started, safe to retry', async () => {
    h.orchestratorFetch.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8010'), { code: 'ECONNREFUSED' }),
    }))
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'The orchestrator could not be reached, so the partial recon was not started.',
      code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test('a timeout is 504 orchestrator_timeout with an unknown outcome, never the bare abort message', async () => {
    h.orchestratorFetch.mockRejectedValue(
      Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(504)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'orchestrator_timeout', startOutcome: 'unknown' })
    expect(body.error).toMatch(/unknown whether the partial recon started/)
    expect(JSON.stringify(body)).not.toMatch(/aborted due to timeout/)
  })

  test('an answered refusal keeps the orchestrator code and status', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 500,
      json: async () => ({ detail: { detail: 'Failed to start: image missing', code: 'spawn_failed' } }),
    })
    const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } })
    expect(res.status).toBe(500)
    expect(await res.json()).toMatchObject({
      error: 'Failed to start: image missing', code: 'spawn_failed', upstreamStatus: 500,
    })
  })

  test('an unexpected throw answers a fixed sentence and a code', async () => {
    h.findUnique.mockRejectedValue(Object.assign(new Error('select * from "Project" where id = p1'), { code: 'P1001' }))
    const res = await post({ tool_id: 'Tlsx' })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to start partial recon', code: 'P1001' })
  })
})

describe('the job credential (step 1.16)', () => {
  test('the orchestrator call carries a job credential for the project owner', async () => {
    const { verifyJobCredential } = await import('@/lib/authz/machineCredential')
    const saved = process.env.INTERNAL_API_KEY
    process.env.INTERNAL_API_KEY = 'start-path-test-master'
    try {
      const res = await post({ tool_id: 'Tlsx', graph_inputs: { domains: ['alpha.test'] } })
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
