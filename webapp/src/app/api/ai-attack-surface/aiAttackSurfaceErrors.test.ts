/**
 * The AI Gauntlet routes say WHY they failed: an orchestrator that never answered
 * is a 503/504 with its code (never a synthetic idle or an empty run list), one
 * that answered keeps its status and code, and a Neo4j failure answers its code,
 * never the driver's message (it can quote the Cypher or target data).
 *
 * Run: npx vitest run src/app/api/ai-attack-surface/aiAttackSurfaceErrors.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const graph = vi.hoisted(() => ({ fail: null as Error | null }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async () => {
      if (graph.fail) throw graph.fail
      return { records: [] }
    },
    close: async () => {},
  }),
}))

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => findUnique(...a) } } }))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))
vi.mock('@/lib/scanTimeline', () => ({
  reconcileRunScanJobs: vi.fn().mockResolvedValue(undefined),
  recordScanStart: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('@/lib/legacyGraph', () => ({ legacyGraphDomains: vi.fn().mockResolvedValue([]), legacyGraphRefusal: vi.fn() }))
// A startable engagement: the R-11 gate has its own tests in start/route.test.ts.
vi.mock('@/lib/engagement', () => ({
  currentRoeTextSha256: vi.fn().mockResolvedValue(null),
  loadEngagement: vi.fn().mockResolvedValue({ blockers: [] }),
}))
vi.mock('@/lib/session', () => ({ getEffectiveUser: vi.fn().mockResolvedValue(null) }))

const startRoute = await import('./[projectId]/start/route')
const allRoute = await import('./[projectId]/all/route')
const statusRoute = await import('./[projectId]/[runId]/status/route')
const stopRoute = await import('./[projectId]/[runId]/stop/route')
const logsRoute = await import('./[projectId]/[runId]/logs/route')
const targetsRoute = await import('./[projectId]/targets/route')
const findingsRoute = await import('./[projectId]/findings/route')

const fetchMock = vi.fn()
const p = (runId?: string) => ({ params: Promise.resolve(runId ? { projectId: 'p1', runId } : { projectId: 'p1' }) }) as never
const startReq = { json: async () => ({ tool: 'garak' }) } as never

function refused(code = 'ECONNREFUSED') {
  return Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect'), { code }) })
}

beforeEach(() => {
  graph.fail = null
  fetchMock.mockReset()
  findUnique.mockReset().mockResolvedValue({ id: 'p1', userId: 'u1' })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('start', () => {
  test('an orchestrator that never answered is a 503 naming it, with the errno', async () => {
    fetchMock.mockRejectedValue(refused())
    const res = await startRoute.POST(startReq, p())
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({
      error: 'Failed to start AI Gauntlet scan', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    })
  })

  test('a timeout is a 504', async () => {
    fetchMock.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const res = await startRoute.POST(startReq, p())
    expect(res.status).toBe(504)
    expect((await res.json()).code).toBe('orchestrator_timeout')
  })

  test('a plain-text 500 keeps the fixed message, its status and a code', async () => {
    fetchMock.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await startRoute.POST(startReq, p())
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to start AI Gauntlet scan', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test('the orchestrator\'s own reason code passes through', async () => {
    fetchMock.mockResolvedValue(new Response(
      JSON.stringify({ detail: { detail: 'Could not create the scan container', code: 'spawn_failed' } }),
      { status: 500 },
    ))
    const body = await (await startRoute.POST(startReq, p())).json()
    expect(body.code).toBe('spawn_failed')
    expect(body.error).toBe('Could not create the scan container')
  })

  test('a DB failure answers its code, not its message', async () => {
    findUnique.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection from pool target.example'), { code: 'P2024' }))
    const res = await startRoute.POST(startReq, p())
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to start AI Gauntlet scan', code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('target.example')
  })
})

describe('run list and status', () => {
  test('an unreachable orchestrator is a 503, not an empty run list', async () => {
    fetchMock.mockRejectedValue(refused())
    const res = await allRoute.GET({} as never, p())
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.code).toBe('orchestrator_unreachable')
    expect(body).not.toHaveProperty('runs')
  })

  test('an orchestrator 503 is a 502 with its status, not an empty run list', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Service not initialized' }), { status: 503 }))
    const res = await allRoute.GET({} as never, p())
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'Service not initialized', code: 'orchestrator_error', upstreamStatus: 503 })
  })

  test('an unreachable orchestrator is not reported as an idle run', async () => {
    fetchMock.mockRejectedValue(refused())
    const res = await statusRoute.GET({} as never, p('r1'))
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toMatchObject({ error: 'AI Gauntlet status unavailable', code: 'orchestrator_unreachable' })
    expect(body).not.toHaveProperty('status')
  })

  test('a status the orchestrator refused keeps its upstream status', async () => {
    fetchMock.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await statusRoute.GET({} as never, p('r1'))
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'AI Gauntlet status unavailable', code: 'orchestrator_error', upstreamStatus: 500 })
  })

  test('a healthy answer passes through', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ run_id: 'r1', status: 'running' }), { status: 200 }))
    const res = await statusRoute.GET({} as never, p('r1'))
    expect(res.status).toBe(200)
    expect((await res.json()).status).toBe('running')
  })
})

describe('stop', () => {
  test('an unreachable orchestrator is a 503 with the errno, not "fetch failed"', async () => {
    fetchMock.mockRejectedValue(refused())
    const res = await stopRoute.POST({} as never, p('r1'))
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to stop AI Gauntlet scan', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
  })

  test('an orchestrator refusal keeps its text and status', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'Service not initialized' }), { status: 503 }))
    const res = await stopRoute.POST({} as never, p('r1'))
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'Service not initialized', code: 'orchestrator_error', upstreamStatus: 503 })
  })
})

describe('log stream', () => {
  const logsReq = () => ({ signal: new AbortController().signal }) as never

  test('an unreachable orchestrator answers a 503 with a body instead of throwing', async () => {
    fetchMock.mockRejectedValue(refused())
    const res = await logsRoute.GET(logsReq(), p('r1'))
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('orchestrator_unreachable')
  })

  test('a run the orchestrator does not know keeps its 404', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ detail: 'No AI attack surface job found' }), { status: 404 }))
    const res = await logsRoute.GET(logsReq(), p('r1'))
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'No AI attack surface job found', code: 'orchestrator_error', upstreamStatus: 404 })
  })
})

describe('graph reads', () => {
  const neoError = () => Object.assign(
    new Error('Invalid input near MATCH (e:Endpoint {baseurl: "https://victim.example"})'),
    { name: 'Neo4jError', code: 'Neo.ClientError.Statement.SyntaxError' },
  )

  test('targets: the Neo4j code, never its message, and the empty list kept', async () => {
    graph.fail = neoError()
    const res = await targetsRoute.GET({} as never, p())
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to load the LLM endpoints', code: 'Neo.ClientError.Statement.SyntaxError', targets: [] })
    expect(JSON.stringify(body)).not.toContain('victim.example')
  })

  test('findings: the Neo4j code, never its message', async () => {
    graph.fail = neoError()
    const res = await findingsRoute.GET({} as never, p())
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to load AI Gauntlet findings', code: 'Neo.ClientError.Statement.SyntaxError', findings: [] })
    expect(JSON.stringify(body)).not.toContain('victim.example')
  })
})
