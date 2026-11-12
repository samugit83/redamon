/**
 * Route handler tests for the Supply-Chain SCA endpoint (Package /
 * MalPackageFinding / OSV Vulnerability model).
 *
 * Run: npx vitest run src/app/api/analytics/redzone/supplyChainScaRoute.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturnByCall: Array<Array<Record<string, unknown>>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => {
    let callIdx = 0
    return {
      run: async (cypher: string, params: Record<string, unknown>) => {
        runCalls.push({ cypher, params })
        if (shouldThrow) throw shouldThrow
        const dataset = runReturnByCall[callIdx++] || []
        return { records: dataset.map(row => ({ get: (k: string) => row[k] })) }
      },
      close: async () => { /* no-op */ },
    }
  },
}))

const route = await import('./supplyChainSca/route')

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeRequest(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/supplyChainSca?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/supplyChainSca'
  return { nextUrl: new URL(url) }
}

/** Queries run in order: verdicts, packages, advisories, ecoTotals, verdictTotals. */
function setDatasets(opts: {
  verdicts?: Record<string, unknown>[]
  packages?: Record<string, unknown>[]
  advisories?: Record<string, unknown>[]
  ecoTotals?: Record<string, unknown>[]
  verdictTotals?: Record<string, unknown>[]
}) {
  runReturnByCall = [
    opts.verdicts ?? [],
    opts.packages ?? [],
    opts.advisories ?? [],
    opts.ecoTotals ?? [],
    opts.verdictTotals ?? [],
  ]
}

beforeEach(() => {
  runCalls.length = 0
  runReturnByCall = []
  shouldThrow = null
  delete process.env.REDAMON_REDZONE_ROW_CAP
})

describe('supplyChainSca: contract', () => {
  test('returns 400 when projectId is missing', async () => {
    const res = await route.GET(makeRequest(null))
    expect(res.status).toBe(400)
  })

  test('returns 500 on Neo4j failure', async () => {
    shouldThrow = new Error('neo4j down')
    const res = await route.GET(makeRequest('p1'))
    expect(res.status).toBe(500)
  })

  test('every query is tenant-scoped on $pid', async () => {
    setDatasets({})
    await route.GET(makeRequest('my-proj'))
    expect(runCalls.length).toBe(5)
    for (const c of runCalls) expect(c.params.pid).toBe('my-proj')
    for (const c of runCalls) expect(c.cypher).toContain('project_id: $pid')
  })

  test('returns all three sheets even when empty', async () => {
    setDatasets({})
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(Object.keys(body.sheets).sort()).toEqual(['advisories', 'packages', 'verdicts'])
  })
})

describe('supplyChainSca: anchor fan-out', () => {
  // L2 writes the artifact once per BaseURL, so a package can carry dozens of
  // DEPENDS_ON edges. Joining them row-wise would duplicate every finding.
  test('anchors are collected via pattern comprehension, never row-joined', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    for (const c of runCalls.slice(0, 3)) {
      expect(c.cypher).not.toContain('OPTIONAL MATCH (b:BaseURL')
      expect(c.cypher).not.toContain('OPTIONAL MATCH (gr:GithubRepository')
      expect(c.cypher).not.toContain('OPTIONAL MATCH (d:SbomDocument')
    }
    expect(runCalls[0].cypher).toContain('[(b:BaseURL)-[:DEPENDS_ON]->(p)')
    expect(runCalls[0].cypher).toContain('[(gr:GithubRepository)-[:DEPENDS_ON]->(p)')
    expect(runCalls[0].cypher).toContain('[(d:SbomDocument)-[:DEPENDS_ON]->(p)')
  })

  // All three sheets must collect the upload anchor, not just the first: an
  // uploaded package shows up in packages and advisories too, and a sheet that
  // skipped it would report the package as floating.
  test('every sheet collects all three anchor kinds', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    for (const c of runCalls.slice(0, 3)) {
      expect(c.cypher).toContain('[(d:SbomDocument)-[:DEPENDS_ON]->(p)')
      expect(c.cypher).toContain('AS sboms')
    }
  })
})

describe('supplyChainSca: verdicts sheet', () => {
  test('maps package + finding fields and both anchor kinds', async () => {
    setDatasets({
      verdicts: [{
        findingId: 'abc123', verdict: 'malicious', severity: 'high',
        sourceTool: 'osv', advisoryId: 'MAL-2022-1122', title: 'malware',
        detail: 'evidence', confidence: 'malicious', softError: false,
        aliases: ['GHSA-xxxx'], firstSeen: '2026-08-01T00:00:00Z',
        lastSeen: '2026-08-07T00:00:00Z', purl: 'pkg:npm/evil@1.0.0',
        name: 'evil', version: '1.0.0', ecosystem: 'npm',
        harvestSource: 'retirejs', sourcePath: 'app/package-lock.json',
        baseUrls: ['https://target.tld'], repos: [], sboms: [],
      }],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    const row = body.sheets.verdicts[0]
    expect(row.verdict).toBe('malicious')
    expect(row.advisoryId).toBe('MAL-2022-1122')
    expect(row.aliases).toEqual(['GHSA-xxxx'])
    expect(row.sourcePath).toBe('app/package-lock.json')
    expect(row.baseUrls).toEqual(['https://target.tld'])
    expect(row.repos).toEqual([])
    expect(row.sboms).toEqual([])
    expect(row.softError).toBe(false)
  })

  test('the uploaded-SBOM anchor reaches the row as the filename', async () => {
    setDatasets({
      verdicts: [{
        findingId: 'd1', verdict: 'malicious', purl: 'pkg:pypi/evil@1',
        name: 'evil', ecosystem: 'PyPI', harvestSource: 'osv',
        baseUrls: [], repos: [], sboms: ['requirements.txt'],
      }],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.sheets.verdicts[0].sboms).toEqual(['requirements.txt'])
  })

  test('softError survives as a boolean, not a truthy string', async () => {
    setDatasets({
      verdicts: [{
        findingId: 'f1', verdict: 'suspicious', severity: 'low',
        advisoryId: 'guarddog-not-run', softError: true, aliases: null,
        purl: 'pkg:npm/x@1', name: 'x', baseUrls: null, repos: null,
      }],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.sheets.verdicts[0].softError).toBe(true)
    // Null list properties must normalize to [], never null, so the UI can map them.
    expect(body.sheets.verdicts[0].aliases).toEqual([])
    expect(body.sheets.verdicts[0].baseUrls).toEqual([])
  })

  test('not-analysed rows sort after real suspicious hits', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    const cypher = runCalls[0].cypher
    expect(cypher).toContain("WHEN f.verdict = 'malicious' THEN 0")
    expect(cypher).toContain('THEN 2 ELSE 1 END')
  })
})

describe('supplyChainSca: packages sheet', () => {
  test('rolls up counts and separates not-analysed from suspicious', async () => {
    setDatasets({
      packages: [{
        purl: 'pkg:npm/lodash@4.17.4', name: 'lodash', version: '4.17.4',
        ecosystem: 'npm', harvestSource: 'retirejs', sourcePath: null,
        baseUrls: ['https://a.tld'], repos: [],
        maliciousCount: { low: 0 }, suspiciousCount: { low: 2 },
        notAnalysedCount: { low: 1 }, advisoryCount: { low: 9 },
        advisorySeverities: ['high', 'critical'],
      }],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    const row = body.sheets.packages[0]
    expect(row.suspiciousCount).toBe(2)
    expect(row.notAnalysedCount).toBe(1)
    expect(row.advisoryCount).toBe(9)
    expect(row.advisorySeverities).toEqual(['high', 'critical'])
  })

  test('the suspicious count excludes soft errors in Cypher', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    const cypher = runCalls[1].cypher
    expect(cypher).toContain("f.verdict = 'suspicious'")
    expect(cypher).toContain('coalesce(f.soft_error, false)')
    expect(cypher).toContain("coalesce(f.advisory_id, '') = 'guarddog-not-run'")
  })
})

describe('supplyChainSca: advisories sheet', () => {
  // Vulnerability is a shared label (GVM, nuclei, GraphQL all write it).
  test('filters to v.source = osv', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    expect(runCalls[2].cypher).toContain("v.source = 'osv'")
  })

  test('maps the CVSS vector through', async () => {
    setDatasets({
      advisories: [{
        advisoryId: 'GHSA-1234', severity: 'high', cvss: 'CVSS:3.1/AV:N/AC:L',
        title: 'prototype pollution', description: 'desc',
        purl: 'pkg:npm/lodash@4.17.4', name: 'lodash', version: '4.17.4',
        ecosystem: 'npm', harvestSource: 'retirejs', baseUrls: [], repos: [],
      }],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.sheets.advisories[0].cvss).toBe('CVSS:3.1/AV:N/AC:L')
  })
})

describe('supplyChainSca: row caps', () => {
  // LIMIT takes an Integer. The JS driver sends plain numbers as floats, so
  // `LIMIT $limit` fails at runtime with "expected Integer" - a break only a
  // live query would catch. The caps are compile-time constants, so they are
  // inlined as literals instead.
  test('limits are inlined as integer literals, never parameterized', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    for (const c of runCalls) {
      expect(c.cypher).not.toContain('LIMIT $')
      expect(c.params).not.toHaveProperty('limit')
    }
    expect(runCalls[0].cypher).toMatch(/LIMIT \d+$/m)
  })

  test('meta.truncated is false for every sheet under the cap', async () => {
    setDatasets({ verdicts: [{ findingId: 'f1', purl: 'p' }] })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.meta.truncated).toEqual({ verdicts: false, packages: false, advisories: false })
  })

  // A capped sheet next to uncapped totals is exactly the "absence reads as a
  // clean result" trap this feature keeps closing elsewhere.
  //
  // The cap is lowered for this test rather than materializing REDZONE_ROW_CAP
  // rows: the assertion is about the >= comparison, and building 200k mock rows
  // to prove it would cost a lot of heap to test nothing extra.
  test('meta.truncated flags a sheet that hit the cap', async () => {
    process.env.REDAMON_REDZONE_ROW_CAP = '3'
    setDatasets({
      verdicts: Array.from({ length: 3 }, (_, i) => ({ findingId: `f${i}`, purl: 'p' })),
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.meta.truncated.verdicts).toBe(true)
    expect(body.meta.truncated.packages).toBe(false)
  })
})

describe('supplyChainSca: meta totals', () => {
  test('totals come from the aggregate queries, not the truncated sheets', async () => {
    setDatasets({
      verdicts: [{ findingId: 'f1', verdict: 'malicious', purl: 'p' }],
      ecoTotals: [
        { ecosystem: 'npm', total: { low: 412 }, unversioned: { low: 300 } },
        { ecosystem: 'PyPI', total: { low: 30 }, unversioned: { low: 0 } },
      ],
      verdictTotals: [
        { verdict: 'malicious', notAnalysed: false, c: { low: 3 } },
        { verdict: 'suspicious', notAnalysed: false, c: { low: 5 } },
        { verdict: 'suspicious', notAnalysed: true, c: { low: 7 } },
      ],
    })
    const res = await route.GET(makeRequest('p1'))
    const body = await res.json()
    expect(body.meta.totalPackages).toBe(442)
    expect(body.meta.unversioned).toBe(300)
    expect(body.meta.malicious).toBe(3)
    expect(body.meta.suspicious).toBe(5)
    // A soft error is NOT a suspicious verdict; counting it as one would report
    // an unchecked package as a behavioural finding.
    expect(body.meta.notAnalysed).toBe(7)
    expect(body.meta.byEcosystem).toHaveLength(2)
  })
})

describe('supplyChainSca: Node ID', () => {
  // Each sheet points at the node its row is about: the finding, the package,
  // the advisory - never the untenanted CVE reference an MCP lookup can't reach.
  test('each sheet query projects its own row node id', async () => {
    setDatasets({})
    await route.GET(makeRequest('p1'))
    expect(runCalls[0].cypher).toContain('toString(id(f))')
    expect(runCalls[1].cypher).toContain('toString(id(p))')
    expect(runCalls[2].cypher).toContain('toString(id(v))')
    for (const c of runCalls.slice(0, 3)) expect(c.cypher).toMatch(/AS nodeId\b/)
  })

  test('maps nodeId on all three sheets, null when absent', async () => {
    setDatasets({
      verdicts: [{ nodeId: '101', findingId: 'f1', purl: 'p' }],
      packages: [{ nodeId: '102', purl: 'p' }],
      advisories: [{ advisoryId: 'GHSA-1', purl: 'p' }],
    })
    const body = await (await route.GET(makeRequest('p1'))).json()
    expect(body.sheets.verdicts[0].nodeId).toBe('101')
    expect(body.sheets.packages[0].nodeId).toBe('102')
    expect(body.sheets.advisories[0].nodeId).toBeNull()
  })
})
