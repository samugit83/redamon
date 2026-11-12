/**
 * Route handler tests for the Route Exposure red-zone lens: scoped to the
 * source, pending leads listed with their status, lists flattened to one cell.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/routeExposureRoute.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      return { records: runReturn.map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => { /* no-op */ },
  }),
}))

const route = await import('./routeExposure/route')

function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/routeExposure?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/routeExposure'
  return { nextUrl: new URL(url) }
}

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
  shouldThrow = null
})

describe('routeExposure lens route', () => {
  test('400 when projectId missing', async () => {
    expect((await route.GET(makeRequest(null))).status).toBe(400)
  })

  test('queries only route_exposure vulnerabilities, unmuted, and keeps pending leads', async () => {
    await route.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(1)
    const cypher = runCalls[0].cypher
    expect(cypher).toContain("source: 'route_exposure'")
    expect(cypher).toContain('stale_since IS NULL')
    // A working view: the deliverable-only exclusion must NOT be applied here.
    expect(cypher).not.toContain("v.source IN ['serialized_scan', 'route_exposure']")
    expect(cypher).toContain("ELSE 'pending' END")
    expect(cypher).toMatch(/LIMIT \d+/)
    expect(runCalls[0].params).toEqual({ pid: 'p1' })
  })

  test('maps rows, coerces Neo4j ints and flattens lists', async () => {
    runReturn = [
      { nodeId: '1', host: '10.0.0.5', path: '/internal/users/export', url: 'http://10.0.0.5/internal/users/export',
        kind: 'anonymous_access', routeClass: 'data_export', severity: 'info', confidence: 0.9,
        status: 'pending', anonStatus: { low: 200 }, authedStatus: 200,
        authExpectedBy: ['path_word', 'siblings_locked'], leakSignals: ['pii_others'], piiTypes: ['email'],
        signature: '', generatedBy: 'found', evidenceSnippet: 'keys: [].email', updatedAt: null },
      { nodeId: '2', host: '10.0.0.5', path: '/.env', url: null, kind: 'env_file', routeClass: 'unknown',
        severity: 'high', confidence: 0.95, status: 'finding', anonStatus: 200, authedStatus: null,
        authExpectedBy: null, leakSignals: [], piiTypes: [], signature: 'env_lines', generatedBy: 'vcs',
        evidenceSnippet: '3 KEY=value line(s)', updatedAt: null },
    ]
    const body = await (await route.GET(makeRequest('p1'))).json()
    expect(body.meta).toEqual({ totalRows: 2, pending: 1 })
    expect(body.rows[0]).toMatchObject({ anonStatus: 200, authExpectedBy: 'path_word, siblings_locked',
                                         leakSignals: 'pii_others', status: 'pending' })
    expect(body.rows[1]).toMatchObject({ status: 'finding', authExpectedBy: '', authedStatus: null })
  })

  test('500 on query failure', async () => {
    shouldThrow = new Error('neo4j down')
    expect((await route.GET(makeRequest('p1'))).status).toBe(500)
  })
})
