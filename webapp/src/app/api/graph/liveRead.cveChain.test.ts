/**
 * The graph screen reads a finding's CVE chain the way it reads a Technology's.
 *
 * The nuclei writer links (v:Vulnerability)-[:INCLUDES_CVE]->(c:CVE) and that
 * CVE's CWE / CAPEC chain (R-35), as the passive CVE sources do. CVE, MitreData
 * and Capec are global nodes with no project_id, so the union's catch-all
 * "every edge out of a project node" branch stops at the CVE: only a branch
 * anchored on the project's Vulnerability reaches CVE -> MitreData -> Capec.
 *
 * The live counterpart (liveRead.cveChain.integration.test.ts) runs the query
 * against Neo4j.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import type { Node } from 'neo4j-driver'
import { driverNode, driverRel } from './__testing__/driverValues'

const h = vi.hoisted(() => ({ run: vi.fn(), close: vi.fn() }))

vi.mock('./neo4j', () => ({
  getGraphSession: () => ({ run: h.run, close: h.close }),
  neo4j: { int: (n: number) => n },
}))
vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: async () => [] } },
}))

import { readLiveGraph, LIVE_GRAPH_QUERY } from './liveRead'

/** The UNION branches of the CALL subquery, comments stripped. */
function branches(): string[] {
  const body = LIVE_GRAPH_QUERY.slice(LIVE_GRAPH_QUERY.indexOf('CALL {') + 'CALL {'.length,
    LIVE_GRAPH_QUERY.lastIndexOf('}'))
  return body
    .split(/^\s*UNION\s*$/m)
    .map(b => b.replace(/\/\/.*$/gm, '').replace(/\s+/g, ' ').trim())
}

/** The branches that return `rel` and walk from a Vulnerability through `via`. */
function vulnBranches(rel: string, via: string): string[] {
  return branches().filter(b =>
    b.startsWith('MATCH (v:Vulnerability {project_id: $projectId})') &&
    new RegExp(`-\\[(?:r\\w*)?:[\\w|]*\\b${via}\\b[\\w|]*\\]->\\(c:CVE\\)`).test(b) &&
    new RegExp(`\\[r\\w*:${rel}\\]`).test(b))
}

let id = 0
const node = (label: string, props: Record<string, unknown>) => driverNode(++id, [label], props)
const rel = (type: string, start: Node, end: Node) => driverRel(++id, start.identity.toNumber(), end.identity.toNumber(), type)
const record = (n: unknown, r: unknown, m: unknown) => {
  const row: Record<string, unknown> = { n, r, m }
  return { keys: ['n', 'r', 'm'], get: (k: string) => row[k] }
}

beforeEach(() => {
  vi.clearAllMocks()
  h.run.mockResolvedValue({ records: [] })
})

describe('LIVE_GRAPH_QUERY reads Vulnerability -> CVE -> CWE -> CAPEC', () => {
  test('the CVE -> MitreData edge of a CVE a finding cites by INCLUDES_CVE', () => {
    const [branch, ...more] = vulnBranches('HAS_CWE', 'INCLUDES_CVE')
    expect(more).toEqual([])
    expect(branch).toMatch(/\(c:CVE\)-\[r\w*:HAS_CWE\]->\(cwe:MitreData\)/)
    expect(branch).toMatch(/RETURN c as n, r\w* as r, cwe as m$/)
  })

  test('the MitreData -> Capec edge of that CVE', () => {
    const [branch, ...more] = vulnBranches('HAS_CAPEC', 'INCLUDES_CVE')
    expect(more).toEqual([])
    expect(branch).toMatch(/\(c:CVE\)-\[:HAS_CWE\]->\(cwe:MitreData\)-\[r\w*:HAS_CAPEC\]->\(cap:Capec\)/)
    expect(branch).toMatch(/RETURN cwe as n, r\w* as r, cap as m$/)
  })

  test('the Vulnerability -> CVE edge itself', () => {
    expect(vulnBranches('[\\w|]*INCLUDES_CVE[\\w|]*', 'INCLUDES_CVE')).toHaveLength(1)
  })

  test('the nmap NSE HAS_CVE chain is still read', () => {
    expect(vulnBranches('HAS_CWE', 'HAS_CVE')).toHaveLength(1)
    expect(vulnBranches('HAS_CAPEC', 'HAS_CVE')).toHaveLength(1)
  })

  test('the chain is anchored on the project, as the Technology chain is', () => {
    for (const via of ['INCLUDES_CVE', 'HAS_CVE']) {
      for (const r of ['HAS_CWE', 'HAS_CAPEC']) {
        for (const b of vulnBranches(r, via)) {
          expect(b.match(/\$projectId/g)).toHaveLength(1)
          expect(b).toContain('(v:Vulnerability {project_id: $projectId})')
        }
      }
    }
    const tech = branches().filter(b => b.includes('(t:Technology {project_id: $projectId})-[:HAS_KNOWN_CVE]->(c:CVE)-'))
    expect(tech).toHaveLength(2)
  })

  test('a muted finding brings no CVE chain', () => {
    // The chain rows return the CVE and its CWE, never `v`, so the union's
    // mute filter (on n and m) cannot see the finding they hang from.
    for (const via of ['INCLUDES_CVE', 'HAS_CVE']) {
      for (const r of ['HAS_CWE', 'HAS_CAPEC']) {
        const [b] = vulnBranches(r, via)
        expect(b).toContain('WHERE NOT v:Muted')
      }
    }
  })
})

describe('readLiveGraph renders the chain it reads', () => {
  test('a nuclei finding, its CVE, CWE and CAPEC become nodes and links', async () => {
    const v = node('Vulnerability', { id: 'nuclei-1', name: 'Apache Path Traversal', project_id: 'p1' })
    const c = node('CVE', { id: 'CVE-2021-41773', severity: 'HIGH', cvss: 7.5 })
    const m = node('MitreData', { id: 'CVE-2021-41773-CWE-22', cwe_id: 'CWE-22' })
    const cap = node('Capec', { capec_id: 'CAPEC-126', name: 'Path Traversal' })
    h.run.mockResolvedValueOnce({ records: [] }).mockResolvedValueOnce({
      records: [
        record(v, rel('INCLUDES_CVE', v, c), c),
        record(c, rel('HAS_CWE', c, m), m),
        record(m, rel('HAS_CAPEC', m, cap), cap),
      ],
    })

    const out = await readLiveGraph('p1')

    expect(h.run.mock.calls[1][0]).toBe(LIVE_GRAPH_QUERY)
    expect(h.run.mock.calls[1][1].projectId).toBe('p1')
    expect(out.nodes.map(n => n.type).sort()).toEqual(['CVE', 'Capec', 'MitreData', 'Vulnerability'])
    const byId = new Map(out.nodes.map(n => [n.id, n.type]))
    expect(out.links.map(l => [byId.get(l.source), l.type, byId.get(l.target)])).toEqual([
      ['Vulnerability', 'INCLUDES_CVE', 'CVE'],
      ['CVE', 'HAS_CWE', 'MitreData'],
      ['MitreData', 'HAS_CAPEC', 'Capec'],
    ])
  })
})
