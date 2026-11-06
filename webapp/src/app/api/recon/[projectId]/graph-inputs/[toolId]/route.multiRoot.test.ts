/** @vitest-environment node */
/**
 * The graph-inputs route on a project with several roots (Domain batch).
 *
 * Every branch used to group on the Domain node and read `records[0]`, so the
 * modal showed, and the run scanned, whichever root Neo4j returned first. The
 * route now takes the roots from the project row, returns them as `domains`
 * (with `stale_domains` for Domain nodes the project dropped and
 * `empty_domains` for roots with no recon data), and counts only over those
 * roots. Every supported tool is offered every current root.
 *
 * Fixture roots are alpha.test / beta.test / gamma.test only.
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockGuard = vi.fn()
const mockFindUnique = vi.fn()
const mockRun = vi.fn()

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuard(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } } }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => mockRun(...a), close: vi.fn() }),
}))

import { GET } from './route'
import { PARTIAL_RECON_SUPPORTED_TOOLS } from '@/lib/recon-types'

function record(fields: Record<string, unknown>) {
  return { get: (k: string) => fields[k] }
}

const BATCH = {
  userId: 'u1', targetDomain: '', ipMode: false, domainBatchMode: true,
  domainBatchGroups: [
    { rootDomain: 'gamma.test', prefixes: ['*'] },
    { rootDomain: 'alpha.test', prefixes: ['www.', '.'] },
    { rootDomain: 'beta.test', prefixes: ['*'] },
  ],
}

/** Domain nodes in the graph: the three roots, plus one the project dropped. */
let graphDomains: Array<{ name: string; hasData: boolean }> = []

function call(toolId: string) {
  return GET({} as never, { params: Promise.resolve({ projectId: 'p1', toolId }) })
}

function toolCall() {
  return mockRun.mock.calls.find(([cypher]) => !String(cypher).includes('AS hasData')) as
    [string, Record<string, unknown>] | undefined
}

beforeEach(() => {
  vi.clearAllMocks()
  mockGuard.mockResolvedValue(null)
  mockFindUnique.mockResolvedValue(BATCH)
  graphDomains = [
    { name: 'alpha.test', hasData: true },
    { name: 'beta.test', hasData: true },
    { name: 'gamma.test', hasData: false },
    { name: 'old.test', hasData: true },
  ]
  mockRun.mockImplementation(async (cypher: string) => (
    cypher.includes('AS hasData')
      ? { records: graphDomains.map(record) }
      : { records: [record({ subdomains: ['www.alpha.test'], subCount: 1, ipCount: 2, portCount: 3 })] }
  ))
})

describe('roots come from the project, not from the graph', () => {
  test('a multi-root tool is offered every current root, sorted', async () => {
    const body = await (await call('Tlsx')).json()
    expect(body.domains).toEqual(['alpha.test', 'beta.test', 'gamma.test'])
    expect(body.domain).toBe('alpha.test')
  })

  test('a Domain node the project dropped is stale and is not counted', async () => {
    const body = await (await call('Tlsx')).json()
    expect(body.stale_domains).toEqual(['old.test'])
    expect(toolCall()?.[1].domains).toEqual(['alpha.test', 'beta.test', 'gamma.test'])
  })

  test('a root without recon data is reported empty', async () => {
    const body = await (await call('Tlsx')).json()
    expect(body.empty_domains).toEqual(['gamma.test'])
  })

  test('a root with no Domain node yet is still offered, as empty', async () => {
    graphDomains = [{ name: 'alpha.test', hasData: true }]
    const body = await (await call('Tlsx')).json()
    expect(body.domains).toEqual(['alpha.test', 'beta.test', 'gamma.test'])
    expect(body.empty_domains).toEqual(['beta.test', 'gamma.test'])
  })

})

describe('single-domain and IP mode', () => {
  test('a single project keeps its target as stored', async () => {
    mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: 'Alpha.test', ipMode: false })
    graphDomains = [{ name: 'Alpha.test', hasData: true }]
    const body = await (await call('Naabu')).json()
    expect(body.domains).toEqual(['Alpha.test'])
    expect(body.stale_domains).toEqual([])
  })

  test('IP mode returns the synthetic root once a recon has minted it', async () => {
    mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: '', ipMode: true })
    graphDomains = [{ name: 'ip-targets.p1', hasData: true }]
    const body = await (await call('Httpx')).json()
    expect(body.domains).toEqual(['ip-targets.p1'])
    expect(body.domain).toBe('ip-targets.p1')
  })

  test('IP mode with no recon yet offers nothing, as before', async () => {
    mockFindUnique.mockResolvedValue({ userId: 'u1', targetDomain: '', ipMode: true })
    graphDomains = []
    const body = await (await call('Httpx')).json()
    expect(body.domains).toEqual([])
    expect(body.domain).toBeNull()
  })
})

describe('failure and SubdomainDiscovery', () => {
  test('a Neo4j failure still returns the roots, with zero counts', async () => {
    mockRun.mockRejectedValue(new Error('neo4j down'))
    const res = await call('Naabu')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.source).toBe('settings')
    expect(body.domains).toEqual(['alpha.test', 'beta.test', 'gamma.test'])
    expect(body.existing_ips_count).toBe(0)
  })

  test('SubdomainDiscovery says which roots may enumerate (wildcard groups only)', async () => {
    const body = await (await call('SubdomainDiscovery')).json()
    expect(body.discovery_domains).toEqual(['beta.test', 'gamma.test'])
  })
})

describe('vuln tools count only the run roots', () => {
  test.each(['Nuclei', 'SecurityChecks'])('%s skips BaseURLs under a Domain the run does not cover', async (toolId) => {
    await call(toolId)
    const cypher = toolCall()?.[0] ?? ''
    expect(cypher).toMatch(/MATCH \(b:BaseURL \{user_id: \$uid, project_id: \$pid\}\)\s+WHERE NOT EXISTS/)
    expect(cypher).toContain('NOT od.name IN $domains')
  })

  test('Nuclei skips Endpoints under a Domain the run does not cover', async () => {
    await call('Nuclei')
    expect(toolCall()?.[0]).toMatch(/MATCH \(e:Endpoint \{user_id: \$uid, project_id: \$pid\}\)\s+WHERE NOT EXISTS/)
  })

  test('OriginDiscovery counts fronted hosts under the run roots only', async () => {
    await call('OriginDiscovery')
    const cypher = toolCall()?.[0] ?? ''
    // The fronted hosts are the run's own subdomains, `s`, never every
    // Subdomain of the project.
    expect(cypher).toContain('d.name IN $domains')
    expect(cypher).toContain('(d)-[:HAS_SUBDOMAIN]->(s:Subdomain)')
    expect(cypher).toMatch(/count\(DISTINCT CASE WHEN EXISTS \{ \(s\)-\[cr:RESOLVES_TO\]->\(ci:IP\) WHERE ci\.is_cdn = true AND cr\.source IS NULL/)
    expect(cypher).not.toMatch(/MATCH \(s:Subdomain \{/)
  })
})

describe.each([...PARTIAL_RECON_SUPPORTED_TOOLS])('every supported tool: %s', (toolId) => {
  test('has a graph branch that returns and counts every current root', async () => {
    const body = await (await call(toolId)).json()
    expect(body.source).toBe('graph')
    expect(body.domains).toEqual(['alpha.test', 'beta.test', 'gamma.test'])
    expect(body.stale_domains).toEqual(['old.test'])
    expect(toolCall()?.[1]).toMatchObject({
      uid: 'u1', pid: 'p1', domains: ['alpha.test', 'beta.test', 'gamma.test'],
    })
  })

  test('never groups on the Domain node', async () => {
    await call(toolId)
    const cypher = toolCall()?.[0] ?? ''
    expect(cypher).not.toMatch(/WITH\s+d\s*,/)
    expect(cypher).not.toContain('d.name AS domain')
    if (cypher.includes(':Domain')) expect(cypher).toMatch(/\bIN \$domains\b/)
  })
})

describe('old-model Domain nodes (§4.11.6)', () => {
  test('are returned as legacy_graph, from the derived scope groups', async () => {
    mockFindUnique.mockResolvedValue({
      userId: 'u1', targetDomain: '', ipMode: false, domainBatchMode: true,
      domainBatchHosts: ['*.alpha.test', 'www.beta.test'], domainBatchGroups: null,
    })
    mockRun.mockImplementation(async (cypher: string) => {
      if (cypher.includes('AS hasData')) return { records: graphDomains.map(record) }
      if (cypher.includes('AS legacy')) return { records: [record({ legacy: ['www.beta.test'] })] }
      return { records: [record({ subdomains: [], subCount: 0, ipCount: 0, portCount: 0 })] }
    })
    const body = await (await call('Tlsx')).json()
    expect(body.legacy_graph).toEqual(['www.beta.test'])
    const legacyCall = mockRun.mock.calls.find(([c]) => String(c).includes('AS legacy'))!
    expect(legacyCall[1]).toMatchObject({ uid: 'u1', pid: 'p1', expected: ['alpha.test', 'beta.test'] })
  })

  test('a project whose scope is not derivable asks nothing and reports none', async () => {
    const body = await (await call('Tlsx')).json()
    expect(body.legacy_graph).toEqual([])
    expect(mockRun.mock.calls.some(([c]) => String(c).includes('AS legacy'))).toBe(false)
  })
})

describe('with scope groups, the graph is counted by the positive scope test (§4.6, §4.11.7)', () => {
  const SCOPED = {
    userId: 'u1', targetDomain: '', ipMode: false, domainBatchMode: true, domainBatchGroups: null,
    domainBatchHosts: ['*.alpha.test', 'alpha.test', 'www.beta.test', 'api.beta.test'],
  }

  test('hosts are matched tenant-scoped, by the listed hosts and the enumerated roots', async () => {
    mockFindUnique.mockResolvedValue(SCOPED)
    const body = await (await call('Naabu')).json()
    expect(body.domains).toEqual(['alpha.test', 'beta.test'])
    const [cypher, params] = toolCall()!
    expect(cypher).toContain('OPTIONAL MATCH (s:Subdomain {user_id: $uid, project_id: $pid})')
    expect(cypher).toContain('toLower(s.name) IN $listed')
    expect(cypher).not.toContain('IN $domains')
    expect(params).toMatchObject({
      uid: 'u1', pid: 'p1',
      listed: ['alpha.test', 'www.beta.test', 'api.beta.test'],
      enumRoots: ['alpha.test'],
      allRoots: ['alpha.test', 'beta.test'],
    })
  })

  test('a Domain node no current org hangs off is stale; an org without data is empty', async () => {
    mockFindUnique.mockResolvedValue(SCOPED)
    const body = await (await call('Naabu')).json()
    expect(body.stale_domains).toEqual(['gamma.test', 'old.test'])
    expect(body.empty_domains).toEqual([])
  })

  test('BaseURLs are in scope by the same test, not by "under no other Domain"', async () => {
    mockFindUnique.mockResolvedValue(SCOPED)
    await call('Katana')
    const cypher = toolCall()?.[0] ?? ''
    expect(cypher).toContain('IN $listed')
    expect(cypher).not.toContain('NOT EXISTS')
  })
})
