/**
 * Insights routes on a failure: a fixed sentence plus the Neo4j/Prisma code, never
 * the driver's own message (it can quote the Cypher and the target values in it).
 * The pipeline-status route says which pipeline is unreachable instead of
 * reporting it as null, which the dashboard drew as "idle".
 *
 * Run: npx vitest run src/app/api/analytics/insightsRouteErrors.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const state = vi.hoisted(() => ({
  graphError: null as Error | null,
  prismaError: null as Error | null,
  orchestrator: vi.fn(),
}))

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async () => {
      if (state.graphError) throw state.graphError
      return { records: [] }
    },
    close: async () => {},
  }),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => { if (state.prismaError) throw state.prismaError; return null } },
  },
}))

vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => state.orchestrator(...a) }))

const graphOverview = await import('./graph-overview/route')
const vulnerabilities = await import('./vulnerabilities/route')
const attackSurface = await import('./attack-surface/route')
const attackChains = await import('./attack-chains/route')
const activity = await import('./activity/route')
const pipeline = await import('./pipeline-status/route')

const request = (path: string): any => ({
  nextUrl: new URL(`http://localhost/api/analytics/${path}?projectId=p1`),
})

const NEO4J_CODE = 'Neo.TransientError.General.DatabaseUnavailable'

beforeEach(() => {
  state.graphError = null
  state.prismaError = null
  state.orchestrator.mockReset()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('Neo4j-backed Insights routes', () => {
  test.each([
    ['graph-overview', graphOverview.GET],
    ['vulnerabilities', vulnerabilities.GET],
    ['attack-surface', attackSurface.GET],
    ['attack-chains', attackChains.GET],
  ])('%s answers 500 {error, code} without the raw Neo4j text', async (path, handler) => {
    state.graphError = Object.assign(new Error('MATCH (s:Subdomain {name: "secret.target.example"})'), { code: NEO4J_CODE })
    const res = await handler(request(path))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Query failed', code: NEO4J_CODE })
    expect(JSON.stringify(body)).not.toContain('target.example')
  })
})

describe('activity (Prisma)', () => {
  test('answers 500 with the Prisma code', async () => {
    state.prismaError = Object.assign(new Error('Timed out fetching a new connection from the pool'), { code: 'P2024' })
    const res = await activity.GET(request('activity'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Query failed', code: 'P2024' })
  })
})

describe('pipeline-status', () => {
  test('an orchestrator that never answers is reported per pipeline, not as null', async () => {
    state.orchestrator.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    }))
    const res = await pipeline.GET(request('pipeline-status'))
    expect(res.status).toBe(200)
    const body = await res.json()
    for (const key of ['recon', 'gvm', 'githubHunt']) {
      expect(body[key]).toEqual({ reachable: false, code: 'orchestrator_unreachable' })
    }
  })

  test('a timeout reads as orchestrator_timeout', async () => {
    state.orchestrator.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const body = await (await pipeline.GET(request('pipeline-status'))).json()
    expect(body.gvm).toEqual({ reachable: false, code: 'orchestrator_timeout' })
  })

  test('an orchestrator error keeps its status, and a healthy pipeline is passed through as is', async () => {
    state.orchestrator.mockImplementation(async (url: string) => url.includes('/gvm/')
      ? new Response('Internal Server Error', { status: 500 })
      : new Response(JSON.stringify({ status: 'running', currentPhase: 'Port scan' }), { status: 200 }))
    const body = await (await pipeline.GET(request('pipeline-status'))).json()
    expect(body.gvm).toEqual({ reachable: false, code: 'orchestrator_error', upstreamStatus: 500 })
    expect(body.recon).toEqual({ status: 'running', currentPhase: 'Port scan' })
    expect(body.githubHunt).toEqual({ status: 'running', currentPhase: 'Port scan' })
  })
})
