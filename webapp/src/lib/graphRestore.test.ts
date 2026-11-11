/**
 * Shared Neo4j restore — used by BOTH the project import and version activation.
 *
 * This is the most destructive code in the feature (it clears and rebuilds a
 * project's subgraph), and its tenancy rule is a security property: `project_id`
 * is always stamped from the CALLER, never taken from the payload, so a restore
 * can only ever write into the project it was asked for.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import type { Session } from 'neo4j-driver'
import { restoreGraph, clearProjectGraph } from './graphRestore'

interface Call { cypher: string; params: Record<string, unknown> }

function fakeSession(constraints: Array<{ label: string; properties: string[] }> = []): {
  session: Session
  calls: Call[]
} {
  const calls: Call[] = []
  const run = vi.fn(async (cypher: string, params: Record<string, unknown> = {}) => {
    calls.push({ cypher, params })
    if (cypher.includes('SHOW CONSTRAINTS')) {
      return {
        records: constraints.map(c => ({
          get: (k: string) => (k === 'label' ? c.label : c.properties),
        })),
      }
    }
    return { records: [] }
  })
  return { session: { run } as unknown as Session, calls }
}

const node = (label: string, properties: Record<string, unknown>, id: string) =>
  ({ labels: [label], properties, _exportId: id })

beforeEach(() => vi.clearAllMocks())

describe('clearProjectGraph', () => {
  // The wipe used to be a bare `MATCH (n {project_id}) DETACH DELETE n`. That
  // also took the CVE/MitreData/Capec catalogue, which is ONE node per CVE for
  // the whole database, shared by every project that found it — so deleting a
  // project removed other projects' links to it. Observed live: 4 CVEs stamped
  // with one project, linked from a second.
  test('the global reference catalogue is always excluded', async () => {
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1')
    expect(calls[0].cypher).toContain('NONE(l IN labels(n) WHERE l IN $excluded)')
    expect(calls[0].params.excluded).toEqual(
      expect.arrayContaining(['CVE', 'MitreData', 'Capec']))
  })

  test('with exclusions it preserves those labels TOO (F1: agent chains survive)', async () => {
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1', ['AttackChain', 'ChainStep'])
    expect(calls[0].cypher).toContain('NONE(l IN labels(n) WHERE l IN $excluded)')
    expect(calls[0].params.excluded).toEqual(
      expect.arrayContaining(['AttackChain', 'ChainStep', 'CVE', 'MitreData', 'Capec']))
  })

  test('the caller cannot accidentally drop the reference exclusion', async () => {
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1', [])
    expect(calls[0].params.excluded).toEqual(
      expect.arrayContaining(['CVE', 'MitreData', 'Capec']))
  })

  test('the project wipe itself is scoped by project_id, never a bare MATCH (n)', async () => {
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1')
    await clearProjectGraph(session, 'p1', ['AttackChain'])
    const wipes = calls.filter(c => c.cypher.includes('DETACH DELETE n')
                                 && c.cypher.includes('NONE('))
    expect(wipes.length).toBeGreaterThan(0)
    for (const c of wipes) expect(c.cypher).toContain('project_id: $pid')
  })

  test('the orphan sweep is global on purpose, and touches ONLY reference labels', async () => {
    // Reference nodes carry no project_id, so this one query cannot be
    // project-scoped. Its safety comes from the label predicate instead: a bare
    // `MATCH (n)` here without it would delete the database.
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1')
    const sweep = calls.find(c => c.cypher.includes('NOT EXISTS'))
    expect(sweep).toBeDefined()
    expect(sweep!.cypher).toContain('n:`CVE`')
    expect(sweep!.cypher).toContain('n:`MitreData`')
    expect(sweep!.cypher).toContain('n:`Capec`')
    // Reachability, not degree: the catalogue is internally linked
    // (CVE -> MitreData -> Capec), so a degree-zero test never fires.
    expect(sweep!.cypher).toContain('-[*1..3]-')
  })
})

describe('restoreGraph — retired properties', () => {
  test('a snapshot or export from before their retirement does not bring them back', async () => {
    const { session, calls } = fakeSession([{ label: 'Endpoint', properties: ['path', 'method', 'baseurl', 'user_id', 'project_id'] }])
    await restoreGraph(
      session,
      [
        node('Endpoint', {
          path: '/users/{id}', method: 'GET', baseurl: 'https://api.example.com',
          openapi_declared: true, openapi_declarations: '[{"operation":{}}]', _openapi_write_lock: 'tx',
        }, 'n1'),
        node('Domain', { name: 'example.com', openapi_summary: '{}', openapi_last_import_at: 'then' }, 'n2'),
      ],
      [],
      { projectId: 'p1' }
    )
    const written = calls
      .filter(c => c.cypher.includes('apoc.merge.node') || c.cypher.includes('apoc.create.node'))
      .flatMap(c => c.params.nodes as Array<{ properties: Record<string, unknown> }>)
      .map(n => n.properties)
    expect(written).toHaveLength(2)
    for (const props of written) {
      for (const retired of ['openapi_declarations', 'openapi_summary', 'openapi_last_import_at', '_openapi_write_lock']) {
        expect(props).not.toHaveProperty(retired)
      }
    }
    // What is still a live property is kept.
    expect(written[0]).toMatchObject({ openapi_declared: true, path: '/users/{id}' })
  })
})

describe('restoreGraph — retired props are per label (GDB-13)', () => {
  async function restored(nodes: ReturnType<typeof node>[]) {
    const { session, calls } = fakeSession()
    await restoreGraph(session, nodes, [], { projectId: 'p1' })
    return calls
      .filter(c => c.cypher.includes('apoc.merge.node') || c.cypher.includes('apoc.create.node'))
      .flatMap(c => c.params.nodes as Array<{ properties: Record<string, unknown> }>)
      .map(n => n.properties)
  }

  test("a Domain's flat per-run props are dropped; the latest scan_timestamp stays", async () => {
    const [d] = await restored([node('Domain', {
      name: 'example.com', target: 'api.example.com', filtered_mode: true, wildcard_mode: false,
      subdomain_filter: ['www.api.example.com'], modules_executed: ['domain_discovery'], anonymous_mode: false,
      bruteforce_mode: false, scan_type: 'full', scan_timestamp: 't1', registrar: 'R',
    }, 'n1')])
    for (const k of ['target', 'filtered_mode', 'wildcard_mode', 'subdomain_filter', 'modules_executed',
      'anonymous_mode', 'bruteforce_mode', 'scan_type']) expect(d).not.toHaveProperty(k)
    expect(d).toMatchObject({ scan_timestamp: 't1', registrar: 'R' })
  })

  test('a GithubHunt keeps its target', async () => {
    const [g] = await restored([node('GithubHunt', { id: 'h1', target: 'acme-org', scan_type: 'org' }, 'n1')])
    expect(g).toMatchObject({ target: 'acme-org', scan_type: 'org' })
  })

  test("an IP-mode Domain keeps its own scan_type and modules_executed", async () => {
    const [d] = await restored([node('Domain', {
      name: 'ip-targets.p1', ip_mode: true, scan_type: 'ip', modules_executed: ['ip_recon'],
    }, 'n1')])
    expect(d).toMatchObject({ scan_type: 'ip', modules_executed: ['ip_recon'] })
  })
})

describe('restoreGraph — tenancy', () => {
  test('stamps the CALLER project id onto every node, overriding the payload', async () => {
    const { session, calls } = fakeSession()
    await restoreGraph(
      session,
      [
        node('IP', { address: '10.0.0.1', project_id: 'SOME_OTHER_PROJECT', user_id: 'someoneElse' }, 'n1'),
        node('IP', { address: '10.0.0.2' }, 'n2'),
      ],
      [],
      { projectId: 'p1' }
    )
    const create = calls.find(c => c.cypher.includes('apoc.create.node'))!
    const batch = create.params.nodes as Array<{ properties: Record<string, unknown> }>
    for (const n of batch) expect(n.properties.project_id).toBe('p1')
    // No userId given (activation): each node keeps its own owner.
    expect(batch[0].properties.user_id).toBe('someoneElse')
  })

  test('re-owns every node when a userId is given (import)', async () => {
    const { session, calls } = fakeSession()
    await restoreGraph(
      session,
      [node('IP', { address: '10.0.0.1', user_id: 'oldOwner' }, 'n1')],
      [],
      { projectId: 'p1', userId: 'importer' }
    )
    const batch = calls.find(c => c.cypher.includes('apoc.create.node'))!.params.nodes as Array<{
      properties: Record<string, unknown>
    }>
    expect(batch[0].properties).toMatchObject({ user_id: 'importer', project_id: 'p1' })
  })

  test('relationships are matched inside the target project only', async () => {
    const { session, calls } = fakeSession()
    await restoreGraph(
      session,
      [node('IP', { address: '1.1.1.1' }, 'n1'), node('Port', { number: 443 }, 'n2')],
      [{ startExportId: 'n1', endExportId: 'n2', type: 'HAS_PORT', properties: {} }],
      { projectId: 'p1' }
    )
    const rel = calls.find(c => c.cypher.includes('apoc.create.relationship'))!
    expect(rel.cypher).toContain('project_id: $pid')
    expect(rel.params.pid).toBe('p1')
  })
})

describe('restoreGraph — strategy', () => {
  test('CREATEs when the label has no uniqueness constraint', async () => {
    const { session, calls } = fakeSession([])
    await restoreGraph(session, [node('IP', { address: '1.1.1.1' }, 'n1')], [], { projectId: 'p1' })
    expect(calls.some(c => c.cypher.includes('apoc.create.node'))).toBe(true)
    expect(calls.some(c => c.cypher.includes('apoc.merge.node'))).toBe(false)
  })

  test('MERGEs on the constraint keys when the label has one', async () => {
    const { session, calls } = fakeSession([{ label: 'Subdomain', properties: ['name'] }])
    await restoreGraph(session, [node('Subdomain', { name: 'a.x.tld' }, 'n1')], [], { projectId: 'p1' })
    const merge = calls.find(c => c.cypher.includes('apoc.merge.node'))
    expect(merge).toBeTruthy()
    expect(merge!.cypher).toContain('`name`: node.properties.`name`')
  })

  test('picks the strategy per label, not per graph', async () => {
    const { session, calls } = fakeSession([{ label: 'Subdomain', properties: ['name'] }])
    await restoreGraph(
      session,
      [node('Subdomain', { name: 'a.x.tld' }, 'n1'), node('IP', { address: '1.1.1.1' }, 'n2')],
      [],
      { projectId: 'p1' }
    )
    expect(calls.some(c => c.cypher.includes('apoc.merge.node'))).toBe(true)
    expect(calls.some(c => c.cypher.includes('apoc.create.node'))).toBe(true)
  })

  test('batches nodes and relationships', async () => {
    const { session, calls } = fakeSession()
    const nodes = Array.from({ length: 5 }, (_, i) => node('IP', { address: `10.0.0.${i}` }, `n${i}`))
    const rels = Array.from({ length: 5 }, (_, i) => ({
      startExportId: 'n0', endExportId: `n${i}`, type: 'R', properties: {},
    }))
    await restoreGraph(session, nodes, rels, { projectId: 'p1', nodeBatchSize: 2, relBatchSize: 2 })
    expect(calls.filter(c => c.cypher.includes('apoc.create.node'))).toHaveLength(3)
    expect(calls.filter(c => c.cypher.includes('apoc.create.relationship'))).toHaveLength(3)
  })

  test('strips the temporary _exportId so it never leaks into the graph', async () => {
    const { session, calls } = fakeSession()
    await restoreGraph(session, [node('IP', { address: '1.1.1.1' }, 'n1')], [], { projectId: 'p1' })
    const cleanup = calls.at(-1)!
    expect(cleanup.cypher).toContain('REMOVE n._exportId')
    expect(cleanup.params).toEqual({ pid: 'p1' })
  })

  test('an unlabeled node still restores under a placeholder group', async () => {
    const { session, calls } = fakeSession()
    const res = await restoreGraph(
      session,
      [{ labels: [], properties: { a: 1 }, _exportId: 'n1' }],
      [],
      { projectId: 'p1' }
    )
    expect(res.nodes).toBe(1)
    expect(calls.some(c => c.cypher.includes('apoc.create.node'))).toBe(true)
  })

  test('an empty payload does no work at all (not even SHOW CONSTRAINTS)', async () => {
    const { session, calls } = fakeSession()
    const res = await restoreGraph(session, [], [], { projectId: 'p1' })
    expect(res).toEqual({ nodes: 0, relationships: 0 })
    expect(calls).toHaveLength(0)
  })

  test('nodes with no relationships skip the relationship pass', async () => {
    const { session, calls } = fakeSession()
    await restoreGraph(session, [node('IP', { address: '1.1.1.1' }, 'n1')], [], { projectId: 'p1' })
    expect(calls.some(c => c.cypher.includes('apoc.create.relationship'))).toBe(false)
  })

  test('reports what it restored', async () => {
    const { session } = fakeSession()
    const res = await restoreGraph(
      session,
      [node('IP', { address: '1.1.1.1' }, 'n1'), node('IP', { address: '1.1.1.2' }, 'n2')],
      [{ startExportId: 'n1', endExportId: 'n2', type: 'R', properties: {} }],
      { projectId: 'p1' }
    )
    expect(res).toEqual({ nodes: 2, relationships: 1 })
  })
})

describe('restoreGraph — the global reference catalogue (plan 09.5)', () => {
  const cveLink = {
    startExportId: 'n1', endExportId: null, type: 'INCLUDES_CVE',
    refLabel: 'CVE', refKey: 'CVE-2021-44228', properties: {},
  }

  test('a bundle that carries a reference node never creates or overwrites one', async () => {
    // One CVE node is shared by every tenant and keyed on its id alone, so a
    // MERGE of a bundle's CVE would rewrite the shared node's properties.
    const { session, calls } = fakeSession([{ label: 'CVE', properties: ['id'] }])
    const res = await restoreGraph(session, [
      node('Vulnerability', { id: 'v1' }, 'n1'),
      node('CVE', { id: 'CVE-2021-44228', cvss: 0, description: 'forged' }, 'n2'),
      { labels: ['MitreData'], properties: { id: 'CVE-2021-44228-CWE-502' }, _exportId: 'n3' },
    ], [], { projectId: 'p1' })
    const written = calls.filter(c => c.cypher.includes('apoc.merge.node') || c.cypher.includes('apoc.create.node'))
    for (const c of written) {
      for (const n of c.params.nodes as { labels: string[] }[]) {
        expect(n.labels).not.toContain('CVE')
        expect(n.labels).not.toContain('MitreData')
      }
    }
    expect(res.nodes).toBe(1)
  })

  test("a carried reference node's edges become links to the existing node, not lost", async () => {
    // A snapshot stored before the reference catalogue lost its tenant stamp
    // holds the CVE as a node and its edge as an ordinary relationship.
    const { session, calls } = fakeSession()
    await restoreGraph(session, [
      node('Vulnerability', { id: 'v1' }, 'n1'),
      node('CVE', { id: 'CVE-2021-44228', project_id: 'old' }, 'n2'),
      node('Capec', { capec_id: 'not-a-capec' }, 'n3'),
    ], [
      { startExportId: 'n1', endExportId: 'n2', type: 'INCLUDES_CVE', properties: { w: 1 } },
      { startExportId: 'n1', endExportId: 'n3', type: 'HAS_CAPEC', properties: {} },
    ], { projectId: 'p1' })
    const rels = calls.filter(c => c.cypher.includes('MATCH (a {_exportId: rel.startExportId'))
    expect(rels.flatMap(c => c.params.rels as unknown[])).toEqual([])
    const link = calls.find(c => c.cypher.includes('MATCH (ref:CVE {id: link.refKey})'))!
    expect(link.params.links).toEqual([
      { localExportId: 'n1', refKey: 'CVE-2021-44228', type: 'INCLUDES_CVE', properties: { w: 1 } }])
  })

  test('links to the catalogue are restored before the export ids are stripped', async () => {
    const { session, calls } = fakeSession()
    const res = await restoreGraph(session, [node('Vulnerability', { id: 'v1' }, 'n1')], [],
      { projectId: 'p1', referenceLinks: [cveLink, { ...cveLink, refKey: 'bad' }] })
    const linkAt = calls.findIndex(c => c.cypher.includes('MATCH (ref:CVE {id: link.refKey})'))
    const stripAt = calls.findIndex(c => c.cypher.includes('REMOVE n._exportId'))
    expect(linkAt).toBeGreaterThan(-1)
    expect(linkAt).toBeLessThan(stripAt)
    // The fake session reports no edge made: the CVE node "does not exist".
    expect(res.referenceLinks).toEqual({ restored: 0, skipped: 2 })
  })

  test('a payload with no link records restores exactly as before', async () => {
    const { session, calls } = fakeSession()
    const res = await restoreGraph(session, [node('IP', { address: '1.1.1.1' }, 'n1')], [], { projectId: 'p1' })
    expect(res).toEqual({ nodes: 1, relationships: 0 })
    expect(calls.some(c => c.cypher.includes('(ref:'))).toBe(false)
  })
})

describe('clearProjectGraph — sweeping after a restore (plan 09.5)', () => {
  test('a caller that restores next can defer the orphan sweep', async () => {
    // Activation clears, then restores the version's links to the catalogue:
    // sweeping in between would delete a CVE only this project linked, and the
    // restore would find nothing to link back to.
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1', [], { sweep: false })
    expect(calls.some(c => c.cypher.includes('NOT EXISTS'))).toBe(false)
    expect(calls).toHaveLength(1)
  })
})

describe('restoreGraph — a suppressed finding is dual-labelled', () => {
  // This was a real bug. Nodes are bucketed by label to look up the uniqueness
  // key for apoc.merge.node. A muted finding carries TWO labels and Neo4j does
  // not order them, so bucketing on labels[0] could yield "Muted", miss the
  // uniqueKeyMap, and fall through to apoc.create.node -- recreating the finding
  // with NO uniqueness key and duplicating it on the next import.
  const constraints = [{ label: 'Vulnerability', properties: ['id'] }]

  const mutedNode = (order: string[]) =>
    ({ labels: order, properties: { id: 'v1' }, _exportId: 'n1' })

  test('merges on the uniqueness key whichever way the labels are ordered', async () => {
    for (const order of [['Vulnerability', 'Muted'], ['Muted', 'Vulnerability']]) {
      const { session, calls } = fakeSession(constraints)
      await restoreGraph(session, [mutedNode(order)], [], { projectId: 'p1' })

      const merge = calls.find(c => c.cypher.includes('apoc.merge.node'))
      expect(merge, `labels ${order.join(',')} fell through to create`).toBeDefined()
      expect(merge!.cypher).toContain('`id`: node.properties.`id`')
      expect(calls.find(c => c.cypher.includes('apoc.create.node'))).toBeUndefined()
    }
  })

  test('recreates the node with BOTH labels, so the mute survives activation', async () => {
    const { session, calls } = fakeSession(constraints)
    await restoreGraph(session, [mutedNode(['Muted', 'Vulnerability'])], [], { projectId: 'p1' })

    const batch = calls.find(c => c.cypher.includes('apoc.merge.node'))!.params.nodes as Array<{
      labels: string[]
    }>
    expect(batch[0].labels).toEqual(expect.arrayContaining(['Vulnerability', 'Muted']))
  })

  test('an ordinary single-label node is unaffected', async () => {
    const { session, calls } = fakeSession(constraints)
    await restoreGraph(
      session,
      [{ labels: ['Vulnerability'], properties: { id: 'v2' }, _exportId: 'n2' }],
      [],
      { projectId: 'p1' }
    )
    expect(calls.find(c => c.cypher.includes('apoc.merge.node'))).toBeDefined()
  })
})

// P4 (design §6.1, §6.3): an IP-mode graph with hostnames recorded and scanned
// on its target IPs survives a Scan Timeline activation and an import, and a
// project delete takes all of it.
describe('restoreGraph — hostnames on target IPs', () => {
  const ipGraph = () => [
    node('Domain', { name: 'ip-targets.p1', ip_mode: true, is_mock: true, ip_hostname_mode: 'record_filter',
      scan_type: 'ip' }, 'root'),
    node('Domain', { name: 'example.com', ip_hostname_org: true, scan_type: 'full' }, 'org'),
    node('Subdomain', { name: 'app.example.com', source: 'ip_hostname_selection', ip_mode: true,
      ip_hostname_reason: 'scanned', ip_hostname_sources: ['ptr', 'tlsx_san'],
      ip_hostname_evaluated_at: '2026-11-11T10:00:00Z' }, 'sub'),
    node('ExternalDomain', { domain: 'old.example.com', ip_hostname_reason: 'filter_no_match',
      ip_hostname_org: 'example.com', ips_seen: ['203.0.113.10'], sources: ['ptr'],
      ip_hostname_evaluated_at: '2026-11-11T10:00:00Z', first_seen_at: '2026-11-11T10:00:00Z' }, 'ed'),
    node('IP', { address: '203.0.113.10' }, 'ip'),
  ]
  const rels = [
    { startExportId: 'ed', endExportId: 'ip', type: 'SEEN_ON',
      properties: { sources: ['ptr'], first_seen: '2025-02-01', last_seen: '2026-10-30', resolves_here: true,
        cert_covers: false, reason: 'filter_no_match' } },
    { startExportId: 'sub', endExportId: 'ip', type: 'RESOLVES_TO', properties: { record_type: 'A' } },
    { startExportId: 'org', endExportId: 'sub', type: 'HAS_SUBDOMAIN', properties: {} },
  ]

  async function restoredIp() {
    const { session, calls } = fakeSession()
    await restoreGraph(session, ipGraph(), rels, { projectId: 'p1' })
    const nodes = calls
      .filter(c => c.cypher.includes('apoc.merge.node') || c.cypher.includes('apoc.create.node'))
      .flatMap(c => c.params.nodes as Array<{ labels: string[]; properties: Record<string, unknown> }>)
    const relationships = calls
      .filter(c => c.cypher.includes('apoc.create.relationship'))
      .flatMap(c => c.params.rels as Array<{ type: string; properties: Record<string, unknown> }>)
    return { nodes, relationships }
  }

  test('the selection properties round-trip; the evaluation time is a DateTime again', async () => {
    const { nodes } = await restoredIp()
    const byName = (n: string) => nodes.find(x => x.properties.name === n || x.properties.domain === n)!.properties
    expect(byName('example.com')).toMatchObject({ ip_hostname_org: true })
    expect(byName('ip-targets.p1')).toMatchObject({ ip_mode: true, ip_hostname_mode: 'record_filter', scan_type: 'ip' })
    expect(byName('app.example.com')).toMatchObject({ source: 'ip_hostname_selection', ip_mode: true,
      ip_hostname_reason: 'scanned', ip_hostname_sources: ['ptr', 'tlsx_san'] })
    expect(byName('old.example.com')).toMatchObject({ ip_hostname_reason: 'filter_no_match',
      ip_hostname_org: 'example.com', ips_seen: ['203.0.113.10'], sources: ['ptr'] })
    for (const n of ['app.example.com', 'old.example.com']) {
      expect(typeof byName(n).ip_hostname_evaluated_at).not.toBe('string')
    }
  })

  test('an org Domain is an org Domain: its retired per-run props go, the root keeps its own', async () => {
    const { nodes } = await restoredIp()
    const org = nodes.find(x => x.properties.name === 'example.com')!.properties
    expect(org).not.toHaveProperty('scan_type')
    expect(org).not.toHaveProperty('ip_mode')
  })

  test('SEEN_ON keeps its evidence', async () => {
    const { relationships } = await restoredIp()
    const seen = relationships.find(r => r.type === 'SEEN_ON')!
    expect(seen.properties).toEqual({ sources: ['ptr'], first_seen: '2025-02-01', last_seen: '2026-10-30',
      resolves_here: true, cert_covers: false, reason: 'filter_no_match' })
  })

  test('a project delete takes the recorded names, their SEEN_ON edges and the org Domains', async () => {
    const { session, calls } = fakeSession()
    await clearProjectGraph(session, 'p1')
    const wipe = calls[0]
    // One statement, scoped to the project, sparing only the global catalogue;
    // DETACH takes every SEEN_ON edge with its ExternalDomain.
    expect(wipe.cypher).toContain('MATCH (n {project_id: $pid})')
    expect(wipe.cypher).toContain('DETACH DELETE n')
    expect(wipe.params.pid).toBe('p1')
    for (const label of ['ExternalDomain', 'Domain', 'Subdomain', 'IP']) {
      expect(wipe.params.excluded as string[]).not.toContain(label)
    }
  })
})
