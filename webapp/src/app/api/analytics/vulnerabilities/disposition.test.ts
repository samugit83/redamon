/**
 * @vitest-environment node
 *
 * Insights leads with disposition, like the report (plan 10.2): the route
 * returns the disposition summary beside the chart data, and its severity
 * chart counts reportable and candidate findings only.
 *
 * Run: npx vitest run src/app/api/analytics/vulnerabilities/disposition.test.ts
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { inSeverityBreakdown } from '@/lib/triage/disposition'
import { reportCountable } from '@/lib/triage/reportable'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const queries: string[] = []
let rows: (cypher: string) => Record<string, unknown>[] = () => []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      queries.push(cypher)
      return { records: rows(cypher).map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const route = await import('./route')

const request = () =>
  ({ nextUrl: new URL('http://localhost:3000/api/analytics/vulnerabilities?projectId=p1') }) as never

const isSummary = (q: string) => q.includes('AS disposition, ')

beforeEach(() => {
  queries.length = 0
  rows = () => []
})

describe('the Insights vulnerability route leads with disposition', () => {
  test('the severity chart counts reportable and candidate findings only', async () => {
    await route.GET(request())
    const sev = queries.find(q => q.includes('RETURN v.severity AS severity, count(v) AS count'))!
    expect(sev).toContain(inSeverityBreakdown('v'))
    expect(sev).toContain(reportCountable('v'))
  })

  test('it returns the disposition summary beside the chart data', async () => {
    rows = (q) => isSummary(q)
      ? [
          { disposition: 'reportable', blocker: null, total: 1 },
          { disposition: 'candidate', blocker: 'not triaged yet', total: { low: 4, high: 0 } },
          { disposition: 'info', blocker: null, total: 2 },
        ]
      : []
    const body = await (await route.GET(request())).json()
    expect(body.disposition).toEqual({
      reportable: 1, candidate: 4, info: 2, excluded: 0,
      blockers: [{ blocker: 'not triaged yet', count: 4 }],
    })
    expect(body.severityDistribution).toEqual([])
  })

  test('a disposition read that fails is null, and the charts still answer', async () => {
    rows = (q) => {
      if (isSummary(q)) throw new Error('neo4j hiccup')
      return []
    }
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await route.GET(request())
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.disposition).toBeNull()
    expect(body.severityDistribution).toEqual([])
    warn.mockRestore()
  })
})
