/**
 * The live-graph read, extracted from GET /api/graph so the version endpoint can
 * render "current" through exactly the same path.
 *
 * It carries a DETACH DELETE (the orphan-chain self-heal), so the extraction is
 * precisely the kind of change that could alter destructive behavior silently.
 * These tests pin what it deletes, what it must NOT delete, and that a failure in
 * the housekeeping can never block the read itself.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ run: vi.fn(), close: vi.fn(), conversations: vi.fn() }))

vi.mock('./neo4j', () => ({
  getGraphSession: () => ({ run: h.run, close: h.close }),
  // readLiveGraph now bounds the query at the DATABASE, so it needs the
  // driver's Integer helper: a plain JS number is sent as a float and Neo4j
  // rejects it for LIMIT.
  neo4j: { int: (n: number) => n },
}))
vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: (...a: unknown[]) => h.conversations(...a) } },
}))
vi.mock('./format', () => ({
  formatGraphRecords: (records: unknown[]) => ({
    nodes: records.map((_, i) => ({ id: String(i), name: 'n', type: 'IP', properties: {} })),
    links: [],
  }),
}))

import { readLiveGraph, reconcileOrphanChains, LIVE_GRAPH_QUERY } from './liveRead'
import { getGraphSession } from './neo4j'

const calls = () => h.run.mock.calls.map(c => ({ cypher: String(c[0]), params: c[1] ?? {} }))

beforeEach(() => {
  vi.clearAllMocks()
  h.conversations.mockResolvedValue([{ sessionId: 's1' }, { sessionId: 's2' }])
  h.run.mockResolvedValue({ records: [] })
})

describe('reconcileOrphanChains', () => {
  test('deletes only AttackChain-family nodes whose session no longer exists', async () => {
    await reconcileOrphanChains(getGraphSession(), 'p1')
    const { cypher, params } = calls()[0]
    expect(cypher).toContain('DETACH DELETE n')
    expect(cypher).toContain('n.project_id = $projectId')
    // Scoped to the chain family and to dead sessions only.
    for (const label of ['AttackChain', 'ChainStep', 'ChainFinding', 'ChainDecision', 'ChainFailure']) {
      expect(cypher).toContain(`n:${label}`)
    }
    expect(cypher).toContain('NOT n.chain_id IN $liveSessionIds')
    expect(params).toEqual({ projectId: 'p1', liveSessionIds: ['s1', 's2'] })
  })

  test('is scoped to ONE project (never a cross-tenant delete)', async () => {
    await reconcileOrphanChains(getGraphSession(), 'p1')
    expect(calls()[0].cypher).toMatch(/WHERE\s+n\.project_id = \$projectId/)
  })

  test('a project with no live conversations purges all of its chains (documented)', async () => {
    h.conversations.mockResolvedValue([])
    await reconcileOrphanChains(getGraphSession(), 'p1')
    // `NOT chain_id IN []` is true for every chain node — correct, since no live
    // conversation means every chain is an orphan.
    expect(calls()[0].params.liveSessionIds).toEqual([])
  })

  test('conversations with a blank sessionId are filtered out', async () => {
    h.conversations.mockResolvedValue([{ sessionId: 's1' }, { sessionId: '' }, { sessionId: null }])
    await reconcileOrphanChains(getGraphSession(), 'p1')
    expect(calls()[0].params.liveSessionIds).toEqual(['s1'])
  })

  test('a reconcile failure is swallowed (housekeeping must not block the graph)', async () => {
    h.run.mockRejectedValue(new Error('neo4j hiccup'))
    await expect(reconcileOrphanChains(getGraphSession(), 'p1')).resolves.toBeUndefined()
  })

  test('a conversation-lookup failure is also swallowed', async () => {
    h.conversations.mockRejectedValue(new Error('db down'))
    await expect(reconcileOrphanChains(getGraphSession(), 'p1')).resolves.toBeUndefined()
  })
})

describe('readLiveGraph', () => {
  test('reconciles BEFORE reading, so orphans are never returned', async () => {
    await readLiveGraph('p1')
    const order = calls().map(c => (c.cypher.includes('DETACH DELETE') ? 'reconcile' : 'read'))
    expect(order).toEqual(['reconcile', 'read'])
  })

  test('runs the project subgraph query scoped by project id', async () => {
    await readLiveGraph('p1')
    const read = calls()[1]
    expect(read.cypher).toBe(LIVE_GRAPH_QUERY)
    // The read now also carries the record ceiling. Assert the tenant key
    // EXACTLY and that nothing else leaked in beyond the known bound, so this
    // still fails if a future param could widen the scope.
    expect(read.params.projectId).toBe('p1')
    expect(Object.keys(read.params).sort()).toEqual(['maxRecords', 'projectId'])
    // Every MATCH in the query is tenant-scoped.
    const matches = LIVE_GRAPH_QUERY.split('MATCH').slice(1)
    expect(matches.length).toBeGreaterThan(10)
    expect(LIVE_GRAPH_QUERY.split('$projectId').length - 1).toBeGreaterThanOrEqual(matches.length - 6)
  })

  test('excludes muted findings from both ends of every relationship', async () => {
    // A muted finding must be invisible in the graph view. The filter is
    // applied once to the whole union, so assert it is there and covers BOTH
    // endpoint variables -- filtering only `n` would still render a muted node
    // whenever it happened to be the target of a relationship.
    expect(LIVE_GRAPH_QUERY).toContain('WHERE NOT n:Muted AND NOT m:Muted')
  })

  test('applies the mute filter to the union, not to one branch', async () => {
    // Guards the shape rather than the text: the filter has to sit after the
    // CALL subquery closes, or branches added later silently bypass it.
    const afterUnion = LIVE_GRAPH_QUERY.slice(LIVE_GRAPH_QUERY.lastIndexOf('}'))
    expect(afterUnion).toContain('NOT n:Muted')
    expect(afterUnion).toContain('NOT m:Muted')
  })

  test('filters muted nodes before the record ceiling is applied', async () => {
    // If LIMIT ran first, suppressed findings would consume the row budget and
    // silently push real findings out of the view.
    expect(LIVE_GRAPH_QUERY.indexOf('NOT n:Muted')).toBeLessThan(
      LIVE_GRAPH_QUERY.indexOf('LIMIT $maxRecords')
    )
  })

  test('returns the formatted { nodes, links } payload', async () => {
    h.run.mockResolvedValueOnce({ records: [] }).mockResolvedValueOnce({ records: [{}, {}] })
    const out = await readLiveGraph('p1')
    expect(out.nodes).toHaveLength(2)
    expect(out.links).toEqual([])
  })

  test('closes the session even when the read throws', async () => {
    h.run.mockResolvedValueOnce({ records: [] }).mockRejectedValueOnce(new Error('query failed'))
    await expect(readLiveGraph('p1')).rejects.toThrow('query failed')
    expect(h.close).toHaveBeenCalled()
  })

  test('still reads when the reconcile fails', async () => {
    h.run.mockRejectedValueOnce(new Error('reconcile blew up')).mockResolvedValueOnce({ records: [{}] })
    const out = await readLiveGraph('p1')
    expect(out.nodes).toHaveLength(1)
  })
})
