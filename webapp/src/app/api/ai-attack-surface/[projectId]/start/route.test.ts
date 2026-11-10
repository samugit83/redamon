/**
 * AI Gauntlet start: a third-party engagement is held to the full start's
 * engagement rule (R-11). The run sends prompts to somebody else's AI
 * endpoints, so a project that may not start a full scan may not start this.
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
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
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

import { POST } from './route'

const call = () => POST(
  new NextRequest('http://localhost/api/ai-attack-surface/p1/start', {
    method: 'POST',
    body: JSON.stringify({ tool: 'garak', targets: ['https://ai.example.com/v1/chat'] }),
  }),
  { params: Promise.resolve({ projectId: 'p1' }) },
)

const project = (over: Record<string, unknown> = {}) => ({
  id: 'p1', userId: 'u1', targetDomain: 'example.com', subdomainList: [],
  ipMode: false, domainBatchMode: false, domainBatchHosts: [],
  engagementKind: 'third_party', roeGlobalMaxRps: 3, ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.findProject.mockResolvedValue(project())
  h.countAuthorizations.mockResolvedValue(1)
  h.recordScanStart.mockResolvedValue(null)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1', status: 'running' }) })
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
    expect(h.recordScanStart).toHaveBeenCalledWith(expect.objectContaining({ kind: 'ai_attack', runId: 'r1' }))
  })

  test('an internal project with no ceiling is not held by it', async () => {
    h.findProject.mockResolvedValue(project({ engagementKind: 'internal', roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(0)
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
})

// The run writes findings into the live graph, so like every other manual start
// (and the queue's dispatchStart, L-12) it must not begin while a version
// activation is swapping that graph.
describe('a version activation in progress', () => {
  const activationRead = (args: { select?: Record<string, unknown> }) => Boolean(args?.select?.activationState)

  test('refuses with the activation 409 before the project, the engagement or the orchestrator', async () => {
    h.findProject.mockImplementation(async (args: { select?: Record<string, unknown> }) => (
      activationRead(args)
        ? { activationState: 'activating', activationStartedAt: new Date() }
        : project()
    ))
    const res = await call()
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.activationInProgress).toBe(true)
    expect(body.error).toMatch(/version activation is in progress/)
    expect(h.findProject).toHaveBeenCalledTimes(1)
    expect(h.countAuthorizations).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.recordScanStart).not.toHaveBeenCalled()
  })

  test('a lock past its TTL does not hold the start', async () => {
    h.findProject.mockImplementation(async (args: { select?: Record<string, unknown> }) => (
      activationRead(args)
        ? { activationState: 'activating', activationStartedAt: new Date(Date.now() - 24 * 3600 * 1000) }
        : project()
    ))
    const res = await call()
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
})
