/**
 * Route handler tests for the Web Cache Poisoning red-zone lens.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/webCachePoisonRoute.test.ts
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

const route = await import('./webCachePoison/route')

function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/webCachePoison?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/webCachePoison'
  return { nextUrl: new URL(url) }
}

beforeEach(() => {
  runCalls.length = 0
  runReturn = []
  shouldThrow = null
})

describe('webCachePoison lens route', () => {
  test('400 when projectId missing', async () => {
    expect((await route.GET(makeRequest(null))).status).toBe(400)
  })

  test('queries only cache_poisoning vulnerabilities for the project', async () => {
    await route.GET(makeRequest('p1'))
    expect(runCalls).toHaveLength(1)
    expect(runCalls[0].cypher).toContain("source: 'cache_poisoning'")
    expect(runCalls[0].params).toEqual({ pid: 'p1' })
  })

  test('maps rows + tier histogram, coercing Neo4j ints', async () => {
    runReturn = [
      {
        endpointUrl: 'http://t/poison/xfh-redirect', baseUrl: 'http://t',
        cacheHeader: 'X-Forwarded-Host', cacheParam: '', vectorType: 'header',
        impact: 'stored_xss', severity: 'critical', cvss: 9.3, confidence: 0.97,
        tier: 'Confirmed', detectionMode: 'both', technique: 'unkeyed_header',
        engine: 'hypothesis', cacheBuster: 'rdmncb=cb1', crossVantage: false,
        pocLink: 'http://t/poison/xfh-redirect?rdmncb=cb1', curlVerify: 'curl ...',
      },
      {
        endpointUrl: 'http://t/diff/status-dos', baseUrl: 'http://t',
        cacheHeader: 'X-Host', cacheParam: '', vectorType: 'header',
        impact: 'dos', severity: 'high', cvss: { low: 7 }, confidence: 0.9,
        tier: 'Strong', detectionMode: 'differential', technique: 'unkeyed_header',
        engine: 'hypothesis', cacheBuster: 'rdmncb=cb2', crossVantage: false,
        pocLink: 'http://t/diff/status-dos?rdmncb=cb2', curlVerify: 'curl ...',
      },
    ]
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.rows).toHaveLength(2)
    expect(body.meta.totalRows).toBe(2)
    expect(body.meta.tiers).toEqual({ Confirmed: 1, Strong: 1 })
    expect(body.rows[0].impact).toBe('stored_xss')
    expect(body.rows[1].cvss).toBe(7)  // Neo4j Integer {low} coerced
  })

  test('500 on query failure', async () => {
    shouldThrow = new Error('boom')
    expect((await route.GET(makeRequest('p1'))).status).toBe(500)
  })

  test('nodeId is the finding node, mapped through and null when absent', async () => {
    runReturn = [{ nodeId: '77', endpointUrl: 'http://t/a' }, { endpointUrl: 'http://t/b' }]
    const body = await (await route.GET(makeRequest('p1'))).json()
    expect(runCalls[0].cypher).toContain('toString(id(v))')
    expect(runCalls[0].cypher).toMatch(/AS nodeId\b/)
    expect(body.rows[0].nodeId).toBe('77')
    expect(body.rows[1].nodeId).toBeNull()
  })
})
