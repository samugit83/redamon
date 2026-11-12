/**
 * Route tests for the AI Attack Surface webapp routes.
 *  - targets / findings: mock getGraphSession, assert the Cypher params + mapping
 *  - start: mock prisma + fetch, assert the orchestrator forward + project guard
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      return { records: runReturn.map((row) => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => findUnique(...a) } } }))

// Ownership is covered by the BOLA + live E2E tests; stub the guard open here so
// these tests stay focused on the route's neo4j/data behavior.
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const targetsRoute = await import('./[projectId]/targets/route')
const findingsRoute = await import('./[projectId]/findings/route')
const startRoute = await import('./[projectId]/start/route')

const params = (projectId: string, runId?: string) => ({
  params: Promise.resolve(runId ? { projectId, runId } : { projectId }),
})

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
  findUnique.mockReset()
  vi.restoreAllMocks()
})

describe('targets route', () => {
  test('queries by project and maps endpoints', async () => {
    runReturn = [{
      baseUrl: 'http://h:8000', path: '/v1/chat/completions', method: 'POST',
      interfaceType: 'llm-chat', modelFamily: 'qwen', modelIds: ['qwen2.5:7b'],
      supportsTools: true, streaming: false,
    }]
    const res = await targetsRoute.GET({} as never, params('proj1') as never)
    const body = await res.json()
    expect(runCalls[0].params).toEqual({ pid: 'proj1' })
    expect(runCalls[0].cypher).toMatch(/ai_interface_type IN \['llm-chat', 'llm-completion'\]/)
    expect(body.count).toBe(1)
    expect(body.targets[0]).toMatchObject({ baseUrl: 'http://h:8000', interfaceType: 'llm-chat', modelIds: ['qwen2.5:7b'] })
  })

  test('null modelIds becomes empty array', async () => {
    runReturn = [{ baseUrl: 'http://h', path: '/c', method: 'POST', interfaceType: 'llm-chat', modelIds: null }]
    const res = await targetsRoute.GET({} as never, params('p') as never)
    const body = await res.json()
    expect(body.targets[0].modelIds).toEqual([])
  })
})

describe('findings route', () => {
  test('filters to AI attack sources and maps ASR/trials', async () => {
    runReturn = [{
      id: 'aiatk_1', source: 'garak', name: 'n', severity: 'high', type: 'ai_attack_jailbreak',
      owaspLlmId: 'LLM01', asr: 1.0, trials: { low: 1, high: 0 }, payloadClass: 'garak-dan',
      oracleKind: 'classifier', target: 'http://h', endpointPath: '/v1/chat/completions',
    }]
    const res = await findingsRoute.GET({} as never, params('proj1') as never)
    const body = await res.json()
    expect(runCalls[0].params).toMatchObject({ pid: 'proj1', sources: ['garak', 'pyrit', 'giskard', 'promptfoo'] })
    expect(body.findings[0].asr).toBe(1.0)
    expect(body.findings[0].trials).toBe(1)        // neo4j Integer -> number
    expect(body.findings[0].payloadClass).toBe('garak-dan')
  })
})

describe('start route', () => {
  function req(body: unknown) {
    return { json: async () => body } as never
  }

  test('404 when project not found', async () => {
    findUnique.mockResolvedValue(null)
    const res = await startRoute.POST(req({ tool: 'garak' }), params('nope') as never)
    expect(res.status).toBe(404)
  })

  test('forwards launch to the orchestrator with project user_id', async () => {
    findUnique.mockResolvedValue({ id: 'proj1', userId: 'user1' })
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ run_id: 'r1', status: 'running', tool: 'garak' }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const res = await startRoute.POST(
      req({
        tool: 'garak', targets: [{ baseurl: 'http://h', path: '/c', custom: true }],
        bounds: { trials: 1 }, roe_confirmed: true, probes: ['dan'],
        api_key: 'tok', auth_header: 'Authorization', auth_scheme: 'Bearer',
      }),
      params('proj1') as never,
    )
    const body = await res.json()
    expect(body.run_id).toBe('r1')
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toMatch(/\/ai-attack-surface\/proj1\/start$/)
    const forwarded = JSON.parse((opts as { body: string }).body)
    expect(forwarded).toMatchObject({
      project_id: 'proj1', user_id: 'user1', tool: 'garak',
      roe_confirmed: true, probes: ['dan'],
      api_key: 'tok', auth_header: 'Authorization', auth_scheme: 'Bearer',
    })
    // custom target passes through verbatim
    expect(forwarded.targets[0]).toMatchObject({ baseurl: 'http://h', custom: true })
  })

  test('surfaces orchestrator error status', async () => {
    findUnique.mockResolvedValue({ id: 'proj1', userId: 'user1' })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: 'limit reached' }), { status: 409 }),
    ))
    const res = await startRoute.POST(req({ tool: 'garak' }), params('proj1') as never)
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toMatch(/limit/)
    expect(body.upstreamStatus).toBe(409)
  })
})
