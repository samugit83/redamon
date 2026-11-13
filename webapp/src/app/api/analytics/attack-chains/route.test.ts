/**
 * The Insights "Chain Findings" rows carry the ChainFinding's graph Node ID.
 *
 * Run: npx vitest run src/app/api/analytics/attack-chains/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import neo4j from 'neo4j-driver'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: string[] = []
let topRows: Array<Record<string, unknown>> = []
let gvmRows: Array<Record<string, unknown>> = []

/** Only the top-findings query (the one following FOUND_ON) and the ExploitGvm list return rows. */
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      runCalls.push(cypher)
      const rows = cypher.includes('[:FOUND_ON]') ? topRows
        : cypher.includes('ex.cvss_score AS cvssScore') ? gvmRows : []
      return { records: rows.map(row => ({ get: (k: string) => row[k] })) }
    },
    close: async () => {},
  }),
}))

const route = await import('./route')

const request = (projectId: string): any => ({
  nextUrl: new URL(`http://localhost/api/analytics/attack-chains?projectId=${projectId}`),
})

beforeEach(() => {
  runCalls.length = 0
  topRows = []
  gvmRows = []
})

describe('GVM exploit CVSS', () => {
  test('a score stored as INTEGER comes back as a number, not hidden as null', async () => {
    gvmRows = [
      { name: 'int score', cvssScore: neo4j.int(9), cveIds: [] },
      { name: 'float score', cvssScore: 7.5, cveIds: [] },
      { name: 'no score', cvssScore: null, cveIds: [] },
    ]
    const body = await (await route.GET(request('p1'))).json()
    expect(body.gvmExploits.map((e: { cvssScore: unknown }) => e.cvssScore)).toEqual([9, 7.5, null])
  })
})

describe('Chain Findings Node ID', () => {
  test('the query projects the row node\'s internal id as a string', async () => {
    await route.GET(request('p1'))
    const top = runCalls.find(c => c.includes('[:FOUND_ON]'))!
    expect(top).toContain('toString(id(f)) AS nodeId')
    // Still one row per finding-and-target, capped and severity-ordered.
    expect(top).toContain('LIMIT 20')
  })

  test('each row maps it, and a missing one is null rather than absent', async () => {
    topRows = [
      { nodeId: '4711', title: 'SQLi', severity: 'high', findingType: 'sqli' },
      { title: 'Old row', severity: 'low', findingType: 'info' },
    ]
    const body = await (await route.GET(request('p1'))).json()
    expect(body.topFindings.map((f: { nodeId: unknown }) => f.nodeId)).toEqual(['4711', null])
  })
})

describe('Chain summary steps', () => {
  test('a chain step joins on the chain id, the tenant and the project, never the id alone', async () => {
    await route.GET(request('p1'))
    const summary = runCalls.find(c => c.includes('MATCH (ac:AttackChain {project_id: $pid})') && c.includes('ChainStep'))!
    expect(summary).toContain('OPTIONAL MATCH (step:ChainStep {chain_id: ac.chain_id, user_id: ac.user_id, project_id: $pid})')
    expect(summary).not.toMatch(/ChainStep \{chain_id: ac\.chain_id\}/)
  })
})
