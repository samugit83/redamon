/**
 * @vitest-environment node
 *
 * Insights counts what the client report counts: a person's False positive
 * and a rule-resolved finding leave the severity chart, an AI-only false
 * positive stays in it, and the route says how many of each it set aside. The
 * Cypher semantics are proven on a real graph in reportData.integration.test.ts.
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
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

beforeEach(() => {
  queries.length = 0
  rows = () => []
})

describe('the Insights vulnerability route honours the board', () => {
  test('the severity distribution applies the report predicate', async () => {
    await route.GET(request())
    const sev = queries.find(q => q.includes('RETURN v.severity AS severity, count(v) AS count'))!
    expect(sev).toContain(reportCountable('v'))
  })

  test('it returns the judged counts beside the chart data', async () => {
    rows = (q) => q.includes("bucket <> 'counted'")
      ? [
          { bucket: 'person_false_positive', total: { low: 2, high: 0 } },
          { bucket: 'resolved', total: 1 },
          { bucket: 'ai_flagged', total: 4 },
        ]
      : []
    const body = await (await route.GET(request())).json()
    expect(body.judged).toEqual({ personFalsePositive: 2, resolved: 1, aiFlagged: 4 })
  })

  test('judged counts that cannot be read are null, and the rest still answers', async () => {
    const real = rows
    rows = (q) => {
      if (q.includes("bucket <> 'counted'")) throw new Error('boom')
      return real(q)
    }
    const res = await route.GET(request())
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.judged).toBeNull()
    expect(body.severityDistribution).toEqual([])
  })
})
