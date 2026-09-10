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
