/**
 * Insights vulnerabilities: a CVSS stored as INTEGER (10, not 10.0) reaches the
 * route as a driver Integer and must leave it as a plain number, or it serializes
 * as {low, high} and the Insights cards' .toFixed() throws.
 *
 * Run: npx vitest run src/app/api/analytics/vulnerabilities/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import neo4j from 'neo4j-driver'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

let findingRows: Array<Record<string, unknown>> = []
let chainRows: Array<Record<string, unknown>> = []
let exploitRows: Array<Record<string, unknown>> = []
let githubRows: Array<Record<string, unknown>> = []
const queries: string[] = []

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string) => {
      queries.push(cypher)
      const rows = cypher.includes('v.cvss_score AS cvssScore') ? findingRows
        : cypher.includes('c.cvss AS cvss,') ? chainRows
        : cypher.includes('ex.cvss_score AS cvssScore') ? exploitRows
        : cypher.includes('AS sensitiveFiles') ? githubRows : []
      return { records: rows.map(row => ({ get: (k: string) => row[k] ?? null })) }
    },
    close: async () => {},
  }),
}))

const route = await import('./route')

const request = (projectId: string): any => ({
  nextUrl: new URL(`http://localhost/api/analytics/vulnerabilities?projectId=${projectId}`),
})

beforeEach(() => {
  findingRows = []
  chainRows = []
  exploitRows = []
  githubRows = []
  queries.length = 0
})

describe('CVSS stored as INTEGER', () => {
  test('findings, CVE chains and exploits return it as a number', async () => {
    findingRows = [{ name: 'f', cvssScore: neo4j.int(10) }, { name: 'g', cvssScore: 9.8 }, { name: 'h' }]
    chainRows = [{ tech: 't', cveId: 'CVE-0000-0001', cvss: neo4j.int(9) }]
    exploitRows = [{ name: 'e', cvssScore: neo4j.int(8), cveIds: [] }]

    const body = await (await route.GET(request('p1'))).json()

    expect(body.findings.map((f: { cvssScore: unknown }) => f.cvssScore)).toEqual([10, 9.8, null])
    expect(body.cveChains[0].cvss).toBe(9)
    expect(body.exploits[0].cvssScore).toBe(8)
  })
})

describe('GitHub-hunt secrets (plan 05.2)', () => {
  test('a public client key in a repository is counted apart, as the report counts it', async () => {
    const { githubSecretCountsCypher } = await import('@/lib/secrets/githubSecretCounts')
    githubRows = [{ repos: neo4j.int(2), secrets: neo4j.int(5), publicClientKeys: neo4j.int(3),
                    sensitiveFiles: neo4j.int(1) }]

    const body = await (await route.GET(request('p1'))).json()

    expect(queries).toContain(githubSecretCountsCypher())
    expect(body.githubSecrets).toEqual({ repos: 2, secrets: 5, publicClientKeys: 3, sensitiveFiles: 1 })
  })
})
